/*
 * Copyright (c) 2007-2012 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/openvswitch.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in6.h>
#include <linux/if_arp.h>
#include <linux/if_vlan.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/checksum.h>
#include <net/dsfield.h>

#include "checksum.h"
#include "datapath.h"
#include "vlan.h"
#include "vport.h"
/* by Liu Sicheng */
#include "liu_buffer.h"
/* End by Liu Sicheng */

static int do_execute_actions(struct datapath *dp, struct sk_buff *skb,
			      const struct nlattr *attr, int len,
			      struct ovs_key_ipv4_tunnel *tun_key, bool keep_skb);

static int make_writable(struct sk_buff *skb, int write_len)
{
	if (!skb_cloned(skb) || skb_clone_writable(skb, write_len))
		return 0;

	return pskb_expand_head(skb, 0, 0, GFP_ATOMIC);
}

/* remove VLAN header from packet and update csum accordingly. */
static int __pop_vlan_tci(struct sk_buff *skb, __be16 *current_tci)
{
	struct vlan_hdr *vhdr;
	int err;

	err = make_writable(skb, VLAN_ETH_HLEN);
	if (unlikely(err))
		return err;

	if (get_ip_summed(skb) == OVS_CSUM_COMPLETE)
		skb->csum = csum_sub(skb->csum, csum_partial(skb->data
					+ (2 * ETH_ALEN), VLAN_HLEN, 0));

	vhdr = (struct vlan_hdr *)(skb->data + ETH_HLEN);
	*current_tci = vhdr->h_vlan_TCI;

	memmove(skb->data + VLAN_HLEN, skb->data, 2 * ETH_ALEN);
	__skb_pull(skb, VLAN_HLEN);

	vlan_set_encap_proto(skb, vhdr);
	skb->mac_header += VLAN_HLEN;
	skb_reset_mac_len(skb);

	return 0;
}

static int pop_vlan(struct sk_buff *skb)
{
	__be16 tci;
	int err;

	if (likely(vlan_tx_tag_present(skb))) {
		vlan_set_tci(skb, 0);
	} else {
		if (unlikely(skb->protocol != htons(ETH_P_8021Q) ||
			     skb->len < VLAN_ETH_HLEN))
			return 0;

		err = __pop_vlan_tci(skb, &tci);
		if (err)
			return err;
	}
	/* move next vlan tag to hw accel tag */
	if (likely(skb->protocol != htons(ETH_P_8021Q) ||
		   skb->len < VLAN_ETH_HLEN))
		return 0;

	err = __pop_vlan_tci(skb, &tci);
	if (unlikely(err))
		return err;

	__vlan_hwaccel_put_tag(skb, ntohs(tci));
	return 0;
}

static int push_vlan(struct sk_buff *skb, const struct ovs_action_push_vlan *vlan)
{
	if (unlikely(vlan_tx_tag_present(skb))) {
		u16 current_tag;

		/* push down current VLAN tag */
		current_tag = vlan_tx_tag_get(skb);

		if (!__vlan_put_tag(skb, current_tag))
			return -ENOMEM;

		if (get_ip_summed(skb) == OVS_CSUM_COMPLETE)
			skb->csum = csum_add(skb->csum, csum_partial(skb->data
					+ (2 * ETH_ALEN), VLAN_HLEN, 0));

	}
	__vlan_hwaccel_put_tag(skb, ntohs(vlan->vlan_tci) & ~VLAN_TAG_PRESENT);
	return 0;
}

static int set_eth_addr(struct sk_buff *skb,
			const struct ovs_key_ethernet *eth_key)
{
	int err;
	err = make_writable(skb, ETH_HLEN);
	if (unlikely(err))
		return err;

	memcpy(eth_hdr(skb)->h_source, eth_key->eth_src, ETH_ALEN);
	memcpy(eth_hdr(skb)->h_dest, eth_key->eth_dst, ETH_ALEN);

	return 0;
}

static void set_ip_addr(struct sk_buff *skb, struct iphdr *nh,
				__be32 *addr, __be32 new_addr)
{
	int transport_len = skb->len - skb_transport_offset(skb);

	if (nh->protocol == IPPROTO_TCP) {
		if (likely(transport_len >= sizeof(struct tcphdr)))
			inet_proto_csum_replace4(&tcp_hdr(skb)->check, skb,
						 *addr, new_addr, 1);
	} else if (nh->protocol == IPPROTO_UDP) {
		if (likely(transport_len >= sizeof(struct udphdr))) {
			struct udphdr *uh = udp_hdr(skb);

			if (uh->check ||
			    get_ip_summed(skb) == OVS_CSUM_PARTIAL) {
				inet_proto_csum_replace4(&uh->check, skb,
							 *addr, new_addr, 1);
				if (!uh->check)
					uh->check = CSUM_MANGLED_0;
			}
		}
	}

	csum_replace4(&nh->check, *addr, new_addr);
	skb_clear_rxhash(skb);
	*addr = new_addr;
}

static void update_ipv6_checksum(struct sk_buff *skb, u8 l4_proto,
				 __be32 addr[4], const __be32 new_addr[4])
{
	int transport_len = skb->len - skb_transport_offset(skb);

	if (l4_proto == IPPROTO_TCP) {
		if (likely(transport_len >= sizeof(struct tcphdr)))
			inet_proto_csum_replace16(&tcp_hdr(skb)->check, skb,
						  addr, new_addr, 1);
	} else if (l4_proto == IPPROTO_UDP) {
		if (likely(transport_len >= sizeof(struct udphdr))) {
			struct udphdr *uh = udp_hdr(skb);

			if (uh->check ||
			    get_ip_summed(skb) == OVS_CSUM_PARTIAL) {
				inet_proto_csum_replace16(&uh->check, skb,
							  addr, new_addr, 1);
				if (!uh->check)
					uh->check = CSUM_MANGLED_0;
			}
		}
	}
}

static void set_ipv6_addr(struct sk_buff *skb, u8 l4_proto,
			  __be32 addr[4], const __be32 new_addr[4],
			  bool recalculate_csum)
{
	if (recalculate_csum)
		update_ipv6_checksum(skb, l4_proto, addr, new_addr);

	skb_clear_rxhash(skb);
	memcpy(addr, new_addr, sizeof(__be32[4]));
}

static void set_ipv6_tc(struct ipv6hdr *nh, u8 tc)
{
	nh->priority = tc >> 4;
	nh->flow_lbl[0] = (nh->flow_lbl[0] & 0x0F) | ((tc & 0x0F) << 4);
}

static void set_ipv6_fl(struct ipv6hdr *nh, u32 fl)
{
	nh->flow_lbl[0] = (nh->flow_lbl[0] & 0xF0) | (fl & 0x000F0000) >> 16;
	nh->flow_lbl[1] = (fl & 0x0000FF00) >> 8;
	nh->flow_lbl[2] = fl & 0x000000FF;
}

static void set_ip_ttl(struct sk_buff *skb, struct iphdr *nh, u8 new_ttl)
{
	csum_replace2(&nh->check, htons(nh->ttl << 8), htons(new_ttl << 8));
	nh->ttl = new_ttl;
}

static int set_ipv4(struct sk_buff *skb, const struct ovs_key_ipv4 *ipv4_key)
{
	struct iphdr *nh;
	int err;

	err = make_writable(skb, skb_network_offset(skb) +
				 sizeof(struct iphdr));
	if (unlikely(err))
		return err;

	nh = ip_hdr(skb);

	if (ipv4_key->ipv4_src != nh->saddr)
		set_ip_addr(skb, nh, &nh->saddr, ipv4_key->ipv4_src);

	if (ipv4_key->ipv4_dst != nh->daddr)
		set_ip_addr(skb, nh, &nh->daddr, ipv4_key->ipv4_dst);

	if (ipv4_key->ipv4_tos != nh->tos)
		ipv4_change_dsfield(nh, 0, ipv4_key->ipv4_tos);

	if (ipv4_key->ipv4_ttl != nh->ttl)
		set_ip_ttl(skb, nh, ipv4_key->ipv4_ttl);

	return 0;
}

static int set_ipv6(struct sk_buff *skb, const struct ovs_key_ipv6 *ipv6_key)
{
	struct ipv6hdr *nh;
	int err;
	__be32 *saddr;
	__be32 *daddr;

	err = make_writable(skb, skb_network_offset(skb) +
			    sizeof(struct ipv6hdr));
	if (unlikely(err))
		return err;

	nh = ipv6_hdr(skb);
	saddr = (__be32 *)&nh->saddr;
	daddr = (__be32 *)&nh->daddr;

	if (memcmp(ipv6_key->ipv6_src, saddr, sizeof(ipv6_key->ipv6_src)))
		set_ipv6_addr(skb, ipv6_key->ipv6_proto, saddr,
			      ipv6_key->ipv6_src, true);

	if (memcmp(ipv6_key->ipv6_dst, daddr, sizeof(ipv6_key->ipv6_dst))) {
		unsigned int offset = 0;
		int flags = OVS_IP6T_FH_F_SKIP_RH;
		bool recalc_csum = true;

		if (ipv6_ext_hdr(nh->nexthdr))
			recalc_csum = ipv6_find_hdr(skb, &offset,
						    NEXTHDR_ROUTING, NULL,
						    &flags) != NEXTHDR_ROUTING;

		set_ipv6_addr(skb, ipv6_key->ipv6_proto, daddr,
			      ipv6_key->ipv6_dst, recalc_csum);
	}

	set_ipv6_tc(nh, ipv6_key->ipv6_tclass);
	set_ipv6_fl(nh, ntohl(ipv6_key->ipv6_label));
	nh->hop_limit = ipv6_key->ipv6_hlimit;

	return 0;
}

/* Must follow make_writable() since that can move the skb data. */
static void set_tp_port(struct sk_buff *skb, __be16 *port,
			 __be16 new_port, __sum16 *check)
{
	inet_proto_csum_replace2(check, skb, *port, new_port, 0);
	*port = new_port;
	skb_clear_rxhash(skb);
}

static void set_udp_port(struct sk_buff *skb, __be16 *port, __be16 new_port)
{
	struct udphdr *uh = udp_hdr(skb);

	if (uh->check && get_ip_summed(skb) != OVS_CSUM_PARTIAL) {
		set_tp_port(skb, port, new_port, &uh->check);

		if (!uh->check)
			uh->check = CSUM_MANGLED_0;
	} else {
		*port = new_port;
		skb_clear_rxhash(skb);
	}
}

static int set_udp(struct sk_buff *skb, const struct ovs_key_udp *udp_port_key)
{
	struct udphdr *uh;
	int err;

	err = make_writable(skb, skb_transport_offset(skb) +
				 sizeof(struct udphdr));
	if (unlikely(err))
		return err;

	uh = udp_hdr(skb);
	if (udp_port_key->udp_src != uh->source)
		set_udp_port(skb, &uh->source, udp_port_key->udp_src);

	if (udp_port_key->udp_dst != uh->dest)
		set_udp_port(skb, &uh->dest, udp_port_key->udp_dst);

	return 0;
}

static int set_tcp(struct sk_buff *skb, const struct ovs_key_tcp *tcp_port_key)
{
	struct tcphdr *th;
	int err;

	err = make_writable(skb, skb_transport_offset(skb) +
				 sizeof(struct tcphdr));
	if (unlikely(err))
		return err;

	th = tcp_hdr(skb);
	if (tcp_port_key->tcp_src != th->source)
		set_tp_port(skb, &th->source, tcp_port_key->tcp_src, &th->check);

	if (tcp_port_key->tcp_dst != th->dest)
		set_tp_port(skb, &th->dest, tcp_port_key->tcp_dst, &th->check);

	return 0;
}

static int do_output(struct datapath *dp, struct sk_buff *skb, int out_port)
{
	struct vport *vport;

	if (unlikely(!skb))
		return -ENOMEM;

	vport = ovs_vport_rcu(dp, out_port);
	if (unlikely(!vport)) {
		kfree_skb(skb);
		return -ENODEV;
	}

	ovs_vport_send(vport, skb);
	return 0;
}

static int output_userspace(struct datapath *dp, struct sk_buff *skb,
			    const struct nlattr *attr)
{
	struct dp_upcall_info upcall;
	const struct nlattr *a;
	int rem;

	upcall.cmd = OVS_PACKET_CMD_ACTION;
	upcall.key = &OVS_CB(skb)->flow->key;
	upcall.userdata = NULL;
	upcall.portid = 0;

	for (a = nla_data(attr), rem = nla_len(attr); rem > 0;
		 a = nla_next(a, &rem)) {
		switch (nla_type(a)) {
		case OVS_USERSPACE_ATTR_USERDATA:
			upcall.userdata = a;
			break;

		case OVS_USERSPACE_ATTR_PID:
			upcall.portid = nla_get_u32(a);
			break;
		}
	}

	return ovs_dp_upcall(dp, skb, &upcall);
}

static int sample(struct datapath *dp, struct sk_buff *skb,
		  const struct nlattr *attr,
		  struct ovs_key_ipv4_tunnel *tun_key)
{
	const struct nlattr *acts_list = NULL;
	const struct nlattr *a;
	int rem;

	for (a = nla_data(attr), rem = nla_len(attr); rem > 0;
		 a = nla_next(a, &rem)) {
		switch (nla_type(a)) {
		case OVS_SAMPLE_ATTR_PROBABILITY:
			if (net_random() >= nla_get_u32(a))
				return 0;
			break;

		case OVS_SAMPLE_ATTR_ACTIONS:
			acts_list = a;
			break;
		}
	}

	return do_execute_actions(dp, skb, nla_data(acts_list),
				  nla_len(acts_list), tun_key, true);
}

static int execute_set_action(struct sk_buff *skb,
				 const struct nlattr *nested_attr,
				 struct ovs_key_ipv4_tunnel *tun_key)
{
	int err = 0;

	switch (nla_type(nested_attr)) {
	case OVS_KEY_ATTR_PRIORITY:
		skb->priority = nla_get_u32(nested_attr);
		break;

	case OVS_KEY_ATTR_SKB_MARK:
		skb_set_mark(skb, nla_get_u32(nested_attr));
		break;

	case OVS_KEY_ATTR_TUN_ID:
		/* If we're only using the TUN_ID action, store the value in a
		 * temporary instance of struct ovs_key_ipv4_tunnel on the stack.
		 * If both IPV4_TUNNEL and TUN_ID are being used together we
		 * can't write into the IPV4_TUNNEL action, so make a copy and
		 * write into that version.
		 */
		if (!OVS_CB(skb)->tun_key)
			memset(tun_key, 0, sizeof(*tun_key));
		else if (OVS_CB(skb)->tun_key != tun_key)
			memcpy(tun_key, OVS_CB(skb)->tun_key, sizeof(*tun_key));
		OVS_CB(skb)->tun_key = tun_key;

		OVS_CB(skb)->tun_key->tun_id = nla_get_be64(nested_attr);
		break;

	case OVS_KEY_ATTR_IPV4_TUNNEL:
		OVS_CB(skb)->tun_key = nla_data(nested_attr);
		break;

	case OVS_KEY_ATTR_ETHERNET:
		err = set_eth_addr(skb, nla_data(nested_attr));
		break;

	case OVS_KEY_ATTR_IPV4:
		err = set_ipv4(skb, nla_data(nested_attr));
		break;

	case OVS_KEY_ATTR_IPV6:
		err = set_ipv6(skb, nla_data(nested_attr));
		break;

	case OVS_KEY_ATTR_TCP:
		err = set_tcp(skb, nla_data(nested_attr));
		break;

	case OVS_KEY_ATTR_UDP:
		err = set_udp(skb, nla_data(nested_attr));
		break;
	}

	return err;
}
/* by Liu Sicheng */
static void nc_print_vector(char *ss, void *data, int len, int size)
{
    char *t1 = data;
    char s[64];
    int i;
    for(i = 0; i < len; i++){
        if(size == 1) {
            sprintf(s, "%8u", *(uint8_t *)t1);
            strcat(ss, s);
        } else if(size == 2) {
            sprintf(s, "%8u", ntohs(*(uint16_t *)t1));
            strcat(ss, s);
        } 
        t1 += size;
    }
    if((size != 1) && (size != 2)) {
        sprintf(s, "wrong vector size");
        strcat(ss, s);
    }
    strcat(ss, "\n");
}
#define NC_ALIGN(SIZE) (((SIZE) + 15)/16*16)
static uint32_t skb_get_generation_id(struct sk_buff *pk)
{
    struct nchdr *nc = (struct nchdr *)(((char *)ip_hdr(pk)) + ip_hdrlen(pk));
#ifdef NC_DEBUG_GATHER
    printk(KERN_INFO "nc %p, udp %p, nc_vector %p, ip_hdlen %d\n", nc, (char *)nc + nc->len, nc->code_vector, ip_hdrlen(pk));
#endif
    return ntohl(nc->generation_id);
}

static void * skb_get_udp(struct sk_buff *pk)
{
    struct nchdr *nc = (struct nchdr *)(((char *)ip_hdr(pk)) + ip_hdrlen(pk));
    return ((char *)nc) + nc->len;
}

static void * skb_get_vector(struct sk_buff *pk)
{
    struct nchdr *nc = (struct nchdr *)(((char *)ip_hdr(pk)) + ip_hdrlen(pk));
    return nc->code_vector;
}

static inline int add_round(unsigned int a, unsigned int l)
{
    if(a < l - 1)
        return a + 1;
    else 
        return 0;
}

static inline int buff_len(unsigned int h, unsigned int t, unsigned int l)
{
    if(h >= t)
        return h - t;
    else 
        return l + h - t;
}
/* return negative value means some thing's wrong
 * 1 means not collect full
 * 10 means collect this generation of packet is send out already and need send out immediately
 * 11 means collect to much packet we need to free the last one
 * 12 means collect full and we can send it out
 */
static int nc_gather(struct __liu_buffer *buff, struct sk_buff *pk, uint16_t port_id, uint16_t buffer_size, uint8_t packet_num)
{
    unsigned char flag;
    unsigned int g_id = skb_get_generation_id(pk);
    unsigned int head = buff->head[port_id];
    if(port_id >= buff->in_port_num)
    {
        printk(KERN_DEBUG "false id!\n");
        return -1;
    }
    //before insert, we check generation is right
    flag = ((uint32_t)(g_id + (1<<16)) < (uint32_t)(buff->generation_id[head] + (1<<16))); // check generation id is round robin
    if(buff->generation_id[head] == 0)
    { // this is the first packet of the generation 
        buff->generation_id[head] = g_id;
    } else if ((g_id < buff->generation_id[head]) \
            && flag)
    { // this packet of the generation is already send out, so just send it
            return 10;
    } else if (g_id == buff->generation_id[head])
    { // this is the normal situation
        ;
    } else if (( g_id > buff->generation_id[head]) \
            || flag)
    { // this means some packet get lost
        while((g_id != buff->generation_id[head]) && (buff->generation_id[head] == 0))
        {
            head = add_round(head, buffer_size);
        }
        if (buff->generation_id[head] == 0){
            buff->generation_id[head] = g_id;
        }
        buff->head[port_id] = head;
    } else { // this means some thing we don't expect happened
        printk(KERN_ALERT "some thing bad happened in nc_gather!\n");
        return -3;
    }
    buff->buffer[port_id][head] = pk;
    buff->flag[head]++ ;
    buff->head[port_id] = add_round(buff->head[port_id], buffer_size);
    buff->data[port_id][head] = skb_get_udp(pk);
    buff->mMatrix[head][port_id] = skb_get_vector(pk);

    if(buff->head[port_id] == buff->tail)
    { // buff too much packet
        if(buff->flag[head] == packet_num)
            return 12;
        else return 11;
    }
    if(buff->flag[head]  == packet_num)
        return 12;
    else return 1;
}
#define DEBUG_INIT_CODING
//here add len is 16 normally, so if packet change is no more than 8 we can tolerate it with out 
//any extra change
//buffer_id's first bit indicate the ip protocol it use(network coding use two different ip protocol for change state save)
static int nc_init_coding(struct datapath *dp, struct sk_buff *pk, 
		struct ovs_action_init_coding *nc, bool *keep_skb)
{
/* by Liu Sicheng need to add code */
    struct liu_buffer * buffer = &dp->buffer;
    uint8_t buffer_id = (nc->buffer_id) & 0x7f;
    struct __liu_buffer * buff = &buffer->buff[buffer_id];
    uint8_t id = nc->vector_off;
    unsigned int head = buff->head[id];
    uint16_t head_add_len;
    struct iphdr * ip;
    uint8_t nc_start;
    struct nchdr * nch;
    int i;
    uint16_t * outport_id;
    FIELD * vector;
    *keep_skb = true;
    // generation id != 0
    if(buff->generation_id[id] == 0)
        buff->generation_id[id] = 1;
#ifdef DEBUG_INIT_CODING
    printk(KERN_INFO "init_coding:%p\n", pk);
    printk(KERN_INFO "  init_coding:%d,%d,%d,%d,%d\n", nc->vector_off, nc->buffer_id, nc->packet_num, nc->port_num, nc->packet_len);
    printk(KERN_INFO "  head %d, generation_id %d\n", buff->head[id], buff->generation_id[id]);
#endif
    // change skb
    head_add_len = NC_ALIGN(8 + sizeof(FIELD)*nc->packet_num);
    ip = ip_hdr(pk);
#ifdef DEBUG_INIT_CODING
    //printk(KERN_INFO "ip_len %d\n", ip->tot_len);
#endif
    //change IP header, length & protocol
    ip->tot_len = htons(ntohs(ip->tot_len) + head_add_len);
	if (skb_cow_head(pk, head_add_len) < 0) {
	    printk(KERN_WARNING "reserve packet false!\n");
        return -1;
	}
    // in change, to resolve packet
    // for now, we can only resolve packet without VLAN use IP
    nc_start = sizeof(struct ethhdr) + ip->ihl * 4;
    skb_push(pk, head_add_len);
    memmove(pk->data, pk->data + head_add_len, nc_start);
    pk->mac_header -= head_add_len;
    pk->network_header -= head_add_len;
#ifdef DEBUG_INIT_CODING
    //ip = ip_hdr(pk);
    //printk(KERN_INFO "after moving:ip %p, data %p, mac %x, ip src %x\n", ip, pk->data, *(unsigned int *)pk->data, ip->saddr);
#endif
    nch = (struct nchdr *)((char *)pk->data + nc_start);
    nch->len = head_add_len;

    //skb change is finish and need to insert
    buff->buffer[id][head] = pk;
#ifdef DEBUG_INIT_CODING
    //printk(KERN_INFO "  packet put in %p\n", pk);
#endif
    //buff->head[id] ++;
    buff->head[id] = add_round(buff->head[id], buff->max_buffer);
    //if(buff->head[id] == nc->packet_num) 
    if(buff_len(buff->head[id], buff->tail, buff->max_buffer) >= nc->packet_num)
    { // packet collect is over , need to code and send
      // remember to free the skb, and add generation id
        // just for test, assume there is no need to encode
        // port_num must == packet_num 
#ifdef DEBUG_INIT_CODING
        //printk(KERN_INFO "  start to send in init_coding\n");
#endif
        outport_id = (uint16_t *)nc->dataasdf;
        for(i = 0; i < nc->port_num; i++)
        {
            ip = ip_hdr(buff->buffer[id][buff->tail]); 
            ip->protocol =  PROTOCOL_SHIFT + (nc->buffer_id >> 7);
            ip->check = 0;
            ip->check = ip_fast_csum(ip, ip->ihl);
            nch = (struct nchdr *)(((char *)((struct sk_buff *)buff->buffer[id][buff->tail])->data) + nc_start);
            nch->code_len = sizeof(FIELD);
            nch->packet_num = htons(nc->packet_num);
            // create vector
            // now packet_num and port_num must the same
            vector = (FIELD *)nch->code_vector;
            memset(vector, 0, sizeof(FIELD)*nc->packet_num);
            vector[i] = 1;
            nch->generation_id = htonl(buff->generation_id[id]);
            do_output(dp, (struct sk_buff*)buff->buffer[id][buff->tail], ntohs(outport_id[i]));
#ifdef DEBUG_INIT_CODING
            printk(KERN_INFO "  init send to %d ,pos %p\n", ntohs(outport_id[i]), buff->buffer[id][buff->tail]);
#endif
            buff->buffer[id][buff->tail] = NULL;
            buff->tail = add_round(buff->tail, buff->max_buffer);
        }
        buff->generation_id[id]++;
    } 
	return 0;
}
#define DEBUG_ERROR_RECOVER
#define DEBUG_ENCODE
static int nc_encode(struct datapath *dp, struct sk_buff *pk, 
		struct ovs_action_encode *nc, bool *keep_skb)
{
/* by Liu Sicheng need to add code */
    int i, j;
    struct __liu_buffer *buffer = &dp->buffer.buff[nc->buffer_id];
    unsigned int tail ;
    
    *keep_skb = true;

    j = nc_gather(buffer, pk, nc->port_id, nc->buffer_size, nc->packet_num);
    
#ifdef DEBUG_ENCODE
    printk(KERN_INFO "encode  len %d, packet num %d, port_num %d, nc->dataasdf %d,%d\n", nc->packet_len, nc->packet_num, nc->port_num, nc->dataasdf[0], nc->dataasdf[1]);
    printk(KERN_INFO "  encode flag %d, point %p\n",j, pk);
#endif
    if(j == 12)
    { // buffer is full can encode!
        tail = buffer->head[nc->port_id];
        while(buff_len(tail, buffer->tail, nc->buffer_size) > 1) {
            // this means some packet in the buffer is older than current generation 
            // but still not get enough, some may be lost in the way
            // we send this packet   
#ifdef DEBUG_ERROR_RECOVER
            printk(KERN_INFO "  some packet get lost at encode!\n");
#endif
            for( i = 0; i < buffer->in_port_num; i++)
            {
                if(buffer->buffer[i][buffer->tail] != NULL)
                    //kfree_skb(buffer->buffer[i][buffer->tail]);
                    do_output(dp, buffer->buffer[i][buffer->tail], nc->output_port);
                buffer->buffer[i][buffer->tail] = NULL;
            }
            buffer->generation_id[buffer->tail] = 0;
            buffer->tail = add_round(buffer->tail, nc->buffer_size);
        }
        tail = buffer->tail;
        encode(buffer->data[0][tail], buffer->data[1][tail], nc->packet_len, 
                buffer->mMatrix[tail][0], buffer->mMatrix[tail][1], nc->packet_num, 
                nc->dataasdf[0], nc->dataasdf[1]);
        for(i = 2; i < nc->port_num; i++)
        {
            cMulvAdd(buffer->data[0][tail], buffer->data[i][tail], nc->packet_len, nc->dataasdf[i]);
            cMulvAdd(buffer->mMatrix[tail][0], buffer->mMatrix[tail][i], nc->packet_num, nc->dataasdf[i]);
        }

#ifdef DEBUG_ENCODE
        printk(KERN_INFO "  send packet out to %d!tail %d\n", nc->output_port, tail);
#endif
        //send packet and end
        //kfree_skb(buffer->buffer[i][buffer->tail]);
        do_output(dp, buffer->buffer[0][tail], nc->output_port);
        buffer->buffer[0][tail] = NULL;
        for(i = 1; i < nc->port_num; i++) {
            kfree_skb(buffer->buffer[i][tail]);
            buffer->buffer[i][tail] = NULL;
        }
        buffer->generation_id[tail] = 0;
        tail_add(buffer, nc->buffer_size); 
        return 0;
    } else if(j == 10) {
        do_output(dp, pk, nc->output_port);
        //*keep_skb = false;
#ifdef DEBUG_ERROR_RECOVER
        printk(KERN_INFO "this generation has already be send!\n");
#endif
    } else if(j == 11) {
        //buffer too much
        for( i = 0; i < buffer->in_port_num; i++)
        {
            if(buffer->buffer[i][buffer->tail])
                //kfree_skb(buffer->buffer[i][buffer->tail]);
                do_output(dp, buffer->buffer[i][buffer->tail], nc->output_port);
            buffer->buffer[i][buffer->tail] = NULL;
        }
        buffer->generation_id[buffer->tail] = 0;
        buffer->tail = add_round(buffer->tail, nc->buffer_size);
#ifdef DEBUG_ERROR_RECOVER
        printk(KERN_INFO "buffer too much packet %d!\n", buffer->tail);
#endif
    }
	return 0;
}
#define DEBUG_DECODE
static int nc_decode(struct datapath *dp, struct sk_buff *pk, 
		struct ovs_action_decode *nc, bool *keep_skb)
{
/* by Liu Sicheng need to add code */
    int i,j;
    uint16_t * port;
    struct __liu_buffer *buff = &dp->buffer.buff[nc->buffer_id];
    unsigned int tail;
    int flag ;
    unsigned int head = buff->head[nc->port_id];
    uint8_t head_add_len;
    unsigned int g_id = skb_get_generation_id(pk);
    struct iphdr * ip;
    struct sk_buff * skb;
#ifdef DEBUG_DECODE
    printk(KERN_INFO "decode: buffer_id %d, port_id %d, packet_num %d, \
            output_port %d, packet_len %d, flag %d\n", nc->buffer_id, \
            nc->port_id, nc->packet_num, nc->output_num, nc->packet_len, \
            buff->flag[head]);
    //printk(KERN_INFO "head %d, outport %d\n", head, ntohs(*((uint16_t *)nc->dataasdf)));
#endif
    head_add_len = NC_ALIGN(8 + sizeof(FIELD)*nc->packet_num);
    //before insert, we check generation is right
    flag = ((uint32_t)(g_id + (1<<16)) < (uint32_t)(buff->generation_id[head] + (1<<16))); // check generation id is round robin
    if(buff->generation_id[head] == 0)
    { // this is the first packet of the generation 
        buff->generation_id[head] = g_id;
    } else if ((g_id < buff->generation_id[head]) \
            && flag)
    { // this packet of the generation is already send out, so just drop it
#ifdef DEBUG_ERROR_RECOVER
            printk(KERN_INFO "this generation has already sent out!\n");
#endif
            return -1;
    } else if (g_id == buff->generation_id[head])
    { // this is the normal situation
        ;
    } else if (( g_id > buff->generation_id[head]) \
            || flag)
    { // this means some packet get lost
#ifdef DEBUG_ERROR_RECOVER
        printk(KERN_INFO "  some packet has lost on the way!g_id %d, head %d, head g_id %d\n",
                g_id, head, buff->generation_id[head]);
#endif
        while((g_id != buff->generation_id[head]) && (buff->generation_id[head] == 0))
        {
            head = add_round(head, nc->buffer_size);
        }
        if (buff->generation_id[head] == 0){
            buff->generation_id[head] = g_id;
        }
        buff->head[nc->port_id] = head;
    } else { // this means some thing we don't expect happened
        printk(KERN_ALERT "some thing bad happened in nc_gather!\n");
        return -3;
    }

    flag = appendM(buff, skb_get_vector(pk), nc->packet_num, head);
#ifdef  DEBUG_DECODE
    printk(KERN_INFO "      flag %d, head %d, buff->flag[head] %d, g_id %d\n",flag, head, buff->flag[head], g_id);
#endif    
    // here packet in the buffer is not the order of its port_id,
    // but the order of its vector's first not zero field
    if(flag >= 0){ //insert success
        *keep_skb = true;
        buff->buffer[flag][head] = pk;
        buff->head[nc->port_id] = add_round(buff->head[nc->port_id], nc->buffer_size);
        buff->data[flag][head] = skb_get_udp(pk);
        if(buff->flag[head] == nc->packet_num){
            // now we can decode the packet
            tail = head;
#ifdef DEBUG_ERROR_RECOVER
            if(buff_len(tail, buff->tail, nc->buffer_size) > 1){
                printk(KERN_INFO "packets in the buffer is older than current g_id!\n");
            }
#endif
            while(buff_len(tail, buff->tail, nc->buffer_size) > 1) {
                // this means have packets in buffer older than the current g_id
                // we must free that buffer
                for(i = 0; i < buff->in_port_num; i++)
                {
                    if(buff->buffer[i][buff->tail])
                        kfree_skb(buff->buffer[i][buff->tail]);
                    buff->buffer[i][buff->tail] = NULL;
                    buff->mMatrix[buff->tail][i] = NULL;
                    buff->flag[buff->tail] = 0;
                }
                buff->generation_id[buff->tail] = 0;
                buff->tail = add_round(buff->tail, nc->buffer_size);
            }
            tail = buff->tail;
            // init cb
            decode(buff, nc->packet_num, nc->packet_len, tail);
            //change packet back to what it looks
            for(i = 0; i < nc->packet_num; i++)
            {
                skb = (struct sk_buff *)(buff->buffer[i][tail]);
                ip = ip_hdr(skb);
                ip->tot_len = htons(ntohs(ip->tot_len) - head_add_len);
                ip->protocol = 17; // udp is 17
#ifdef  DEBUG_DECODE
                //printk(KERN_INFO "tail %d, dp %p, buffer %p, packet %p, data %p, vector %p, len %d\n",tail, dp, skb, skb->data, buff->data[i][tail], buff->mMatrix[tail][i], ntohs(ip->tot_len));
#endif    
                ip->check = 0;
                ip->check = ip_fast_csum((unsigned char *)ip, ip->ihl);
                memcpy(((unsigned char *)ip)+ip->ihl * 4, buff->out[i], nc->packet_len);
                // reduce useless buffer size
                skb->len -= head_add_len;
                skb->tail -= head_add_len;
            }
            //send packet
            for(i = 0; i < nc->packet_num; i++) {
                port = nc->dataasdf;
                for(j=0; j < nc->output_num - 1; j++){
                    skb = skb_copy((struct sk_buff *)buff->buffer[i][tail], GFP_ATOMIC);
                    do_output(dp, skb, ntohs(port[j]));
                }
                do_output(dp, (struct sk_buff *)buff->buffer[i][tail], ntohs(port[nc->output_num - 1]));
#ifdef  DEBUG_DECODE
                printk(KERN_INFO "  decode and output!\n");
#endif    
                buff->buffer[i][tail] = NULL;
                buff->mMatrix[tail][i] = NULL;
                buff->flag[tail] = 0;
            }
            tail_add(buff, nc->buffer_size);
        }
        if(buff->head[nc->port_id] == buff->tail) {
            // this means buffer is full, 
            // we must free buff->tail to make it work
            for(i = 0; i < buff->in_port_num; i++)
            {
                if(buff->buffer[i][buff->tail])
                    kfree_skb(buff->buffer[i][buff->tail]);
                buff->buffer[i][buff->tail] = NULL;
                buff->mMatrix[buff->tail][i] = NULL;
            }
            buff->flag[buff->tail] = 0;
            buff->generation_id[buff->tail] = 0;
            buff->tail = add_round(buff->tail, nc->buffer_size); 
        }
        return 0;
    } else if(flag == -2) 
    { // means packet insert failed
#ifdef DEBUG_ERROR_RECOVER
        printk(KERN_INFO "decode insert failed, this packet do not have any information!\n");
#endif
        return -1;
    }
	return 0;
}
#define OUTPUT_COPY
/* End by Liu Sicheng */

/* Execute a list of actions against 'skb'. */
static int do_execute_actions(struct datapath *dp, struct sk_buff *skb,
			const struct nlattr *attr, int len,
			struct ovs_key_ipv4_tunnel *tun_key, bool keep_skb)
{
	/* Every output action needs a separate clone of 'skb', but the common
	 * case is just a single output action, so that doing a clone and
	 * then freeing the original skbuff is wasteful.  So the following code
	 * is slightly obscure just to avoid that. */
	int prev_port = -1;
	const struct nlattr *a;
	int rem;

	for (a = attr, rem = len; rem > 0;
	     a = nla_next(a, &rem)) {
		int err = 0;

		if (prev_port != -1) {
/* by Liu Sicheng */
#ifdef OUTPUT_COPY
			do_output(dp, skb_copy(skb, GFP_ATOMIC), prev_port);
#else
			do_output(dp, skb_clone(skb, GFP_ATOMIC), prev_port);
#endif
/* End by Liu Sicheng */
#if 0 /* Recover need by Liu Sicheng */
			do_output(dp, skb_clone(skb, GFP_ATOMIC), prev_port);
#endif /* End by Liu Sicheng*/
			prev_port = -1;
		}

		switch (nla_type(a)) {
		case OVS_ACTION_ATTR_OUTPUT:
			prev_port = nla_get_u32(a);
			break;

		case OVS_ACTION_ATTR_USERSPACE:
			output_userspace(dp, skb, a);
			break;

		case OVS_ACTION_ATTR_PUSH_VLAN:
			err = push_vlan(skb, nla_data(a));
			if (unlikely(err)) /* skb already freed. */
				return err;
			break;

		case OVS_ACTION_ATTR_POP_VLAN:
			err = pop_vlan(skb);
			break;

		case OVS_ACTION_ATTR_SET:
			err = execute_set_action(skb, nla_data(a), tun_key);
			break;

		case OVS_ACTION_ATTR_SAMPLE:
			err = sample(dp, skb, a, tun_key);
			break;
/* by Liu Sicheng */
		case OVS_ACTION_ATTR_INIT_CODING:
			err = nc_init_coding(dp, skb, nla_data(a), &keep_skb);
			break;
		case OVS_ACTION_ATTR_ENCODE:
			err = nc_encode(dp, skb, nla_data(a), &keep_skb);
			break;
		case OVS_ACTION_ATTR_DECODE:
			err = nc_decode(dp, skb, nla_data(a), &keep_skb);
			break;
/* End by Liu Sicheng */
		}

		if (unlikely(err)) {
			kfree_skb(skb);
			return err;
		}
	}

	if (prev_port != -1) {
		if (keep_skb)
/* by Liu Sicheng */
#ifdef OUTPUT_COPY
			skb = skb_copy(skb, GFP_ATOMIC);
#else
			skb = skb_clone(skb, GFP_ATOMIC);
#endif
/* End by Liu Sicheng */
#if 0 /* Recover need by Liu Sicheng */
			skb = skb_clone(skb, GFP_ATOMIC);
#endif /* End by Liu Sicheng*/

		do_output(dp, skb, prev_port);
	} else if (!keep_skb)
		consume_skb(skb);

	return 0;
}

/* We limit the number of times that we pass into execute_actions()
 * to avoid blowing out the stack in the event that we have a loop. */
#define MAX_LOOPS 5

struct loop_counter {
	u8 count;		/* Count. */
	bool looping;		/* Loop detected? */
};

static DEFINE_PER_CPU(struct loop_counter, loop_counters);

static int loop_suppress(struct datapath *dp, struct sw_flow_actions *actions)
{
	if (net_ratelimit())
		pr_warn("%s: flow looped %d times, dropping\n",
				ovs_dp_name(dp), MAX_LOOPS);
	actions->actions_len = 0;
	return -ELOOP;
}

/* Execute a list of actions against 'skb'. */
int ovs_execute_actions(struct datapath *dp, struct sk_buff *skb)
{
	struct sw_flow_actions *acts = rcu_dereference(OVS_CB(skb)->flow->sf_acts);
	struct loop_counter *loop;
	int error;
	struct ovs_key_ipv4_tunnel tun_key;

	/* Check whether we've looped too much. */
	loop = &__get_cpu_var(loop_counters);
	if (unlikely(++loop->count > MAX_LOOPS))
		loop->looping = true;
	if (unlikely(loop->looping)) {
		error = loop_suppress(dp, acts);
		kfree_skb(skb);
		goto out_loop;
	}

	OVS_CB(skb)->tun_key = NULL;
	error = do_execute_actions(dp, skb, acts->actions,
					 acts->actions_len, &tun_key, false);

	/* Check whether sub-actions looped too much. */
	if (unlikely(loop->looping))
		error = loop_suppress(dp, acts);

out_loop:
	/* Decrement loop counter. */
	if (!--loop->count)
		loop->looping = false;

	return error;
}
