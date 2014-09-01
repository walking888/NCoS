static enum ofperr
decode_nc_action(const union ofp_action *a, enum ofputil_action_code *code)
{
    const struct nc_action_header *nch = (const struct nc_action_header *)a;
    uint16_t len = ntohs(a->header.len);
    switch(nch->subtype) {
#define NC_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME)    \
        case CONSTANT_HTONS(ENUM):                      \
            if (EXTENSIBLE                              \
                ? len >= sizeof(struct STRUCT)          \
                : len == sizeof(struct STRUCT)) {       \
                *code = OFPUTIL_##ENUM;                 \
                return 0;                               \
            } else {                                    \
                return OFPERR_OFPBAC_BAD_LEN;           \
            }                                           \
            NOT_REACHED();
#include "ofp-util.def"
    }
    return OFPERR_OFPBAC_BAD_TYPE;
}

