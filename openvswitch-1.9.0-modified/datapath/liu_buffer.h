/*
 * by Liu Sicheng
 * for buffer things
 */

#ifndef LIU_BUFFER
#define LIU_BUFFER

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include "gf256.h"
#include "matrix.h"

// nchdr nc header
struct nchdr{
    uint8_t len;
    uint8_t code_len;
    uint16_t packet_num;
    uint32_t generation_id;
    char  code_vector[0];
};
#define MAX_LIU_BUFFER 8
#define MAX_INPORT_NUM 8
#define MAX_PACKET_NUM 1024
#define MAX_CB_SIZE 2048

#define uint16_t unsigned short
typedef unsigned long ulong;

extern FIELD* mtab;
extern FIELD* dtab;

int initMulDivTab(char * fileName);

#ifndef gfadd
#define gfadd(x,y) ((FIELD)(x)^(y))
#define gfsub(x,y) ((FIELD)(x)^(y))
#define gfmul(x,y) ((FIELD)(mtab[(x)*256+(y)]))
#define gfdiv(x,y) ((FIELD)(dtab[(x)*256+(y)]))
#endif

// total size now is MAX_LIU_BUFFER * (24 + 
// (8 + 8) * MAX_PACKET_NUM + 8 * MAX_INPORT_NUM + 
// MAX_INPORT_NUM * MAX_PACKET_NUM * (8 + 8 + 8))
// according to the default setting we need 1664K + 704
struct __liu_buffer {
    unsigned char in_port_num; // no more than 8
    unsigned char used_num;
    unsigned int max_buffer;
    unsigned int tail;       //next buffer to use 
    unsigned int *generation_id;
    unsigned int *flag;      //indicate the port it indicate to have buffer or not
    unsigned int *head;       //next free buffer location    
    void *** buffer;
    char *** data;
    FIELD iMatrix[MAX_PACKET_NUM][MAX_INPORT_NUM][MAX_INPORT_NUM];    // about 64K
    FIELD *mMatrix[MAX_PACKET_NUM][MAX_INPORT_NUM];      // about 64K
    FIELD tmpv[MAX_INPORT_NUM];
    char out[MAX_INPORT_NUM][MAX_CB_SIZE];
};

struct liu_buffer{
    struct __liu_buffer buff[MAX_LIU_BUFFER];
};

static inline void tail_add(struct __liu_buffer *b, unsigned int buffer_num)
{
    if(b->tail == buffer_num - 1)
    {
        b->tail = 0;
    }
    else b->tail ++;
}

int ovs_liu_buffer_init(struct liu_buffer *);
int ovs__liu_buffer_init(struct __liu_buffer *, unsigned char in_port_num, unsigned int max_buffer);
int ovs__liu_buffer_free(struct __liu_buffer *buff);
int liu_buffer_insert(struct liu_buffer *buff, struct sk_buff *pk, uint8_t buffer_id, unsigned int id);

//encode two field( include buff and vector), the result stored in the first field
inline void encode(FIELD* buff1, FIELD* buff2, ulong size,
        FIELD* buff1_v, FIELD* buff2_v, ulong num, FIELD vector1, FIELD vector2);
//add new buff into CB for decode
//return 0 means insert failed
//return != 0 indicate success
//return 2 means cb is full and ready to decode.
int appendM(struct __liu_buffer *buff, FIELD *vector, unsigned int num, unsigned int k);
//decode cb when appendM return 2
int decode(struct __liu_buffer* buff, unsigned int num, unsigned int size, unsigned int k);

#endif
