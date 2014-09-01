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
