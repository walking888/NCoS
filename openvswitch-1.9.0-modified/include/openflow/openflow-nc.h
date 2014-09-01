/* by Liu Sicheng
 * for Network coding extension
 */

#ifndef OPENFLOW_LIU_NC
#define OPENFLOW_LIU_NC 1

#include "openflow/openflow-1.0.h"
#include "openvswitch/types.h"

#define NC_VENDOR_ID 0x00003333

struct nc_header {
    struct ofp_header header;
    ovs_be32   vendor;
    ovs_be32   subtype;
};
OFP_ASSERT(sizeof(struct nc_header) == 16);

enum nc_action_subtype {
    NC_NULL,        /* never used */
	NC_INIT_CODING,
	NC_ENCODE,
	NC_DECODE,
};
/* Header for NC actions. */
struct nc_action_header {
    ovs_be16 type;                  /* OFPAT_VENDOR. */
    ovs_be16 len;                   /* Length is 16. */
    ovs_be32 vendor;                /* NC_VENDOR_ID. */
    ovs_be16 subtype;               /* NC_*. */
    uint8_t pad[6];
};
OFP_ASSERT(sizeof(struct nc_action_header) == 16);

/* action structure for NC */

struct nc_action_init_coding {
    ovs_be16 type;                  /* OFPAT_VENDOR. */
    ovs_be16 len;                   /* Length is 24. */
    ovs_be32 vendor;                /* NC_VENDOR_ID. */
    ovs_be16 subtype;               /* NC_*. */
	uint8_t buffer_id;
	uint8_t packet_num;
	uint8_t port_num;
	uint8_t vector_off;
	ovs_be16 packet_len;
	uint8_t dataasdf[0];
};
struct nc_action_encode {
    ovs_be16 type;                  /* OFPAT_VENDOR. */
    ovs_be16 len;                   /* Length is 24. */
    ovs_be32 vendor;                /* NC_VENDOR_ID. */
    ovs_be16 subtype;               /* NC_*. */
	uint8_t buffer_id;
	uint8_t port_num;
	ovs_be16 buffer_size;
	ovs_be16 output_port;
	ovs_be16 packet_len;
	ovs_be16 packet_num;
	ovs_be16 port_id;
	uint8_t dataasdf[2];
};
struct nc_action_decode {
    ovs_be16 type;                  /* OFPAT_VENDOR. */
    ovs_be16 len;                   /* Length is 24. */
    ovs_be32 vendor;                /* NC_VENDOR_ID. */
    ovs_be16 subtype;               /* NC_*. */
	uint8_t buffer_id;
	uint8_t packet_num;
	ovs_be16 buffer_size;
	ovs_be16 output_num;
	ovs_be16 packet_len;
	ovs_be16 port_id;
	uint8_t dataasdf[4];
};
#endif  /* end of the file openflow-nc.h */
