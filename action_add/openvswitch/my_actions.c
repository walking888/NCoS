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
        buff->head[port_id] = head;
    } else { // this means some thing we don't expect happened
        printk(KERN_ALERT "some thing bad happened in nc_gather!\n");
        return -3;
    }
    buff->buffer[port_id][head] = pk;
    buff->flag[head]++ ;
    buff->head[port_id] = add_round(buff->head[port_id], buffer_size);
    buff->data[port_id][head] = skb_get_udp(pk);
    buff->mMatrix[port_id][head] = skb_get_vector(pk);

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
//#define DEBUG_INIT_CODING
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
    printk(KERN_INFO "init_coding:%d,%d,%d,%d,%d\n", nc->vector_off, nc->buffer_id, nc->packet_num, nc->port_num, nc->packet_len);
    printk(KERN_INFO "head %d, generation_id %d\n", buff->head[id], buff->generation_id[id]);
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
    printk(KERN_INFO "packet put in %p\n", pk);
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
        printk(KERN_INFO "start to send in init_coding\n");
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
            printk(KERN_INFO "send to %d ,pos %p\n", ntohs(outport_id[i]), buff->buffer[id][buff->tail]);
#endif
            buff->buffer[id][buff->tail] = NULL;
            buff->tail = add_round(buff->tail, buff->max_buffer);
        }
        buff->generation_id[id]++;
    } 
    return 0;
}
static int nc_encode(struct datapath *dp, struct sk_buff *pk, 
		struct ovs_action_encode *nc, bool *keep_skb)
{
/* by Liu Sicheng need to add code */
    int i, j;
    struct __liu_buffer *buffer = &dp->buffer.buff[nc->buffer_id];
    unsigned int tail ;
    
    *keep_skb = true;

    j = nc_gather(buffer, pk, nc->port_id, nc->buffer_size, nc->packet_num);
    
    if(j == 12)
    { // buffer is full can encode!
        tail = buffer->head[nc->port_id];
        while(buff_len(tail, buffer->tail, nc->buffer_size) > 1) {
            // this means some packet in the buffer is older than current generation 
            // but still not get enough, some may be lost in the way
            // we send this packet   
#define DEBUG_ERROR_RECOVER
#ifdef DEBUG_ERROR_RECOVER
            printk(KERN_INFO "some packet get lost at encode!\n");
#endif
            for( i = 0; i < buffer->in_port_num; i++)
            {
                if(buffer->buffer[i][buffer->tail])
                    do_output(dp, buffer->buffer[i][buffer->tail], nc->output_port);
                buffer->buffer[i][buffer->tail] = NULL;
            }
            buffer->generation_id[buffer->tail] = 0;
            buffer->tail = add_round(buffer->tail, nc->buffer_size);
        }
        tail = buffer->tail;
#ifdef DEBUG_ENCODE
        printk(KERN_INFO "len %d, packet num %d, port_num %d, nc->dataasdf %d,%d\n", nc->packet_len, nc->packet_num, nc->port_num, nc->dataasdf[0], nc->dataasdf[1]);
#endif
        encode(buffer->data[0][tail], buffer->data[1][tail], nc->packet_len, 
                buffer->mMatrix[0][tail], buffer->mMatrix[1][tail], nc->packet_num, 
                nc->dataasdf[0], nc->dataasdf[1]);
        for(i = 2; i < nc->port_num; i++)
        {
            cMulvAdd(buffer->data[0][tail], buffer->data[i][tail], nc->packet_len, nc->dataasdf[i]);
            cMulvAdd(buffer->mMatrix[0][tail], buffer->mMatrix[i][tail], nc->packet_num, nc->dataasdf[i]);
        }

        //send packet and end
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
#ifdef DEBUG_ERROR_RECOVER
        printk(KERN_INFO "this generation has already be send!\n");
#endif
    } else if(j == 11) {
        //buffer too much
        for( i = 0; i < buffer->in_port_num; i++)
        {
            if(buffer->buffer[i][buffer->tail])
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
    printk(KERN_INFO "decode: buffer_id %d, port_id %d, packet_num %d, output_port %d, packet_len %d, flag %d\n", nc->buffer_id, nc->port_id, nc->packet_num, nc->output_port, nc->packet_len, buff->flag[head]);
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
        printk(KERN_INFO "some packet has lost on the way!\n");
#endif
        while((g_id != buff->generation_id[head]) && (buff->generation_id[head] == 0))
        {
            head = add_round(head, nc->buffer_size);
        }
        buff->head[nc->port_id] = head;
    } else { // this means some thing we don't expect happened
        printk(KERN_ALERT "some thing bad happened in nc_gather!\n");
        return -3;
    }

    flag = appendM(buff, skb_get_vector(pk), nc->packet_num, head);
#ifdef  DEBUG_DECODE
    printk(KERN_INFO "flag %d, head %d, packet %p, vector %p\n",flag, tail, pk, buff->mMatrix[head][flag]);
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
                    buff->mMatrix[i][buff->tail] = NULL;
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
                printk(KERN_INFO "tail %d, dp %p, buffer %p, packet %p, data %p, vector %p, len %d\n",tail, dp, skb, skb->data, buff->data[i][tail], buff->mMatrix[tail][i], ip->tot_len);
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
                    skb = skb_clone((struct sk_buff *)buff->buffer[i][tail], GFP_ATOMIC);
                    do_output(dp, skb, ntohs(port[j]));
                }
                do_output(dp, (struct sk_buff *)buff->buffer[i][tail], ntohs(port[nc->output_num - 1]));
                //printk(KERN_INFO "decode and output!\n");
                buff->buffer[i][tail] = NULL;
                buff->mMatrix[tail][i] = NULL;
                buff->flag[tail] = 0;
            }
            tail_add(buff, nc->buffer_size);
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
