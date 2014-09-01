#define OFPACTS                                                     \
    /* Output. */                                                   \
    DEFINE_OFPACT(OUTPUT,          ofpact_output,        ofpact)    \
    DEFINE_OFPACT(CONTROLLER,      ofpact_controller,    ofpact)    \
    DEFINE_OFPACT(ENQUEUE,         ofpact_enqueue,       ofpact)    \
    DEFINE_OFPACT(OUTPUT_REG,      ofpact_output_reg,    ofpact)    \
    DEFINE_OFPACT(BUNDLE,          ofpact_bundle,        slaves)    \
    /* Header changes. */                                           \
    DEFINE_OFPACT(SET_VLAN_VID,    ofpact_vlan_vid,      ofpact)    \
    DEFINE_OFPACT(SET_VLAN_PCP,    ofpact_vlan_pcp,      ofpact)    \
    DEFINE_OFPACT(STRIP_VLAN,      ofpact_null,          ofpact)    \
    DEFINE_OFPACT(SET_ETH_SRC,     ofpact_mac,           ofpact)    \
    DEFINE_OFPACT(SET_ETH_DST,     ofpact_mac,           ofpact)    \
    DEFINE_OFPACT(SET_IPV4_SRC,    ofpact_ipv4,          ofpact)    \
    DEFINE_OFPACT(SET_IPV4_DST,    ofpact_ipv4,          ofpact)    \
    DEFINE_OFPACT(SET_IPV4_DSCP,   ofpact_dscp,          ofpact)    \
    DEFINE_OFPACT(SET_L4_SRC_PORT, ofpact_l4_port,       ofpact)    \
    DEFINE_OFPACT(SET_L4_DST_PORT, ofpact_l4_port,       ofpact)    \
    DEFINE_OFPACT(REG_MOVE,        ofpact_reg_move,      ofpact)    \
    DEFINE_OFPACT(REG_LOAD,        ofpact_reg_load,      ofpact)    \
    DEFINE_OFPACT(DEC_TTL,         ofpact_cnt_ids,       cnt_ids)   \
                                                                    \
    /* Metadata. */                                                 \
    DEFINE_OFPACT(SET_TUNNEL,      ofpact_tunnel,        ofpact)    \
    DEFINE_OFPACT(SET_QUEUE,       ofpact_queue,         ofpact)    \
    DEFINE_OFPACT(POP_QUEUE,       ofpact_null,          ofpact)    \
    DEFINE_OFPACT(FIN_TIMEOUT,     ofpact_fin_timeout,   ofpact)    \
                                                                    \
    /* Flow table interaction. */                                   \
    DEFINE_OFPACT(RESUBMIT,        ofpact_resubmit,      ofpact)    \
    DEFINE_OFPACT(LEARN,           ofpact_learn,         specs)     \
                                                                    \
    /* Arithmetic. */                                               \
    DEFINE_OFPACT(MULTIPATH,       ofpact_multipath,     ofpact)    \
    DEFINE_OFPACT(AUTOPATH,        ofpact_autopath,      ofpact)    \
                                                                    \
    /* Other. */                                                    \
    DEFINE_OFPACT(NOTE,            ofpact_note,          data)      \
    DEFINE_OFPACT(EXIT,            ofpact_null,          ofpact)    \
                                                                    \
    /* Instructions */                                              \
    /* TODO:XXX Write-Actions */                                    \
    DEFINE_OFPACT(WRITE_METADATA,  ofpact_metadata,      ofpact)    \
    DEFINE_OFPACT(CLEAR_ACTIONS,   ofpact_null,          ofpact)    \
    DEFINE_OFPACT(GOTO_TABLE,      ofpact_goto_table,    ofpact)    

/* enum ofpact_type, with a member OFPACT_<ENUM> for each action. */
enum OVS_PACKED_ENUM ofpact_type {
#define DEFINE_OFPACT(ENUM, STRUCT, MEMBER) OFPACT_##ENUM,
    OFPACTS
#undef DEFINE_OFPACT
};
