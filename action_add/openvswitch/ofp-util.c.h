#define NC_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME) OFPUTIL_##ENUM,
#define NC_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME)     + 1
#define NC_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME)              \
    void ofputil_init_##ENUM(struct STRUCT *);          \
    struct STRUCT *ofputil_put_##ENUM(struct ofpbuf *);
#define NC_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME)          NAME,
#define NC_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME)        \
    case OFPUTIL_##ENUM: return ofputil_put_##ENUM(buf);
#define NC_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME)            \
    void                                                        \
    ofputil_init_##ENUM(struct STRUCT *s)                       \
    {                                                           \
        memset(s, 0, sizeof *s);                                \
        s->type = htons(OFPAT10_VENDOR);                        \
        s->len = htons(sizeof *s);                              \
        s->vendor = htonl(NC_VENDOR_ID);                        \
        s->subtype = htons(ENUM);                               \
    }                                                           \
                                                                \
    struct STRUCT *                                             \
    ofputil_put_##ENUM(struct ofpbuf *buf)                      \
    {                                                           \
        struct STRUCT *s = ofpbuf_put_uninit(buf, sizeof *s);   \
        ofputil_init_##ENUM(s);                                 \
        return s;                                               \
    }
/* The type of an action.
 *
 * For each implemented OFPAT10_* and NXAST_* action type, there is a
 * corresponding constant prefixed with OFPUTIL_, e.g.:
 *
 * OFPUTIL_OFPAT10_OUTPUT
 * OFPUTIL_OFPAT10_SET_VLAN_VID
 * OFPUTIL_OFPAT10_SET_VLAN_PCP
 * OFPUTIL_OFPAT10_STRIP_VLAN
 * OFPUTIL_OFPAT10_SET_DL_SRC
 * OFPUTIL_OFPAT10_SET_DL_DST
 * OFPUTIL_OFPAT10_SET_NW_SRC
 * OFPUTIL_OFPAT10_SET_NW_DST
 * OFPUTIL_OFPAT10_SET_NW_TOS
 * OFPUTIL_OFPAT10_SET_TP_SRC
 * OFPUTIL_OFPAT10_SET_TP_DST
 * OFPUTIL_OFPAT10_ENQUEUE
 * OFPUTIL_NXAST_RESUBMIT
 * OFPUTIL_NXAST_SET_TUNNEL
 * OFPUTIL_NXAST_SET_METADATA
 * OFPUTIL_NXAST_SET_QUEUE
 * OFPUTIL_NXAST_POP_QUEUE
 * OFPUTIL_NXAST_REG_MOVE
 * OFPUTIL_NXAST_REG_LOAD
 * OFPUTIL_NXAST_NOTE
 * OFPUTIL_NXAST_SET_TUNNEL64
 * OFPUTIL_NXAST_MULTIPATH
 * OFPUTIL_NXAST_AUTOPATH
 * OFPUTIL_NXAST_BUNDLE
 * OFPUTIL_NXAST_BUNDLE_LOAD
 * OFPUTIL_NXAST_RESUBMIT_TABLE
 * OFPUTIL_NXAST_OUTPUT_REG
 * OFPUTIL_NXAST_LEARN
 * OFPUTIL_NXAST_DEC_TTL
 * OFPUTIL_NXAST_FIN_TIMEOUT
 *
 * (The above list helps developers who want to "grep" for these definitions.)
 */
