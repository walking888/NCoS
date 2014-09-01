        } else if(hdrs->vendor == NC_VENDOR_ID) {
            const struct nc_header *nch;
            if(length < sizeof *nch) {
                return OFPERR_OFPBRC_BAD_LEN;
            }
            nch = (const struct nc_header *) oh;
            hdrs->subtype = ntohl(nch->subtype);
