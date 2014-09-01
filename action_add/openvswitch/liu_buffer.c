#include "liu_buffer.h"

int ovs_liu_buffer_init(struct liu_buffer* buff)
{
    int i;
    for(i = 0 ; i < MAX_LIU_BUFFER; i++ )
        buff->buff[i].in_port_num = 0;
    return 0;
}

int ovs__liu_buffer_init(struct __liu_buffer *buff, unsigned char in_port_num, unsigned int max_buffer)
{
    int i, j;
    if(buff->in_port_num)
        ovs__liu_buffer_free(buff);
    buff->in_port_num = in_port_num;
    buff->used_num = 0;
    buff->max_buffer = max_buffer;
    buff->generation_id = (unsigned int *)kmalloc(sizeof(int)* max_buffer, GFP_KERNEL);
    buff->flag = (unsigned int *)kmalloc(sizeof(int)* max_buffer, GFP_KERNEL);
    buff->tail = 0;
    buff->head = (unsigned int *)kmalloc(sizeof(int)* in_port_num, GFP_KERNEL);
    memset(buff->flag, 0, sizeof(int)*max_buffer );
    memset(buff->generation_id, 0, sizeof(int)*max_buffer );
    memset(buff->head, 0, sizeof(int)*in_port_num );

    buff->buffer = (void ***)kmalloc(sizeof(void **)*in_port_num, GFP_KERNEL);
    buff->data = (char ***)kmalloc(sizeof(char **)*in_port_num, GFP_KERNEL);
    for(i = 0; i < in_port_num ;i++)
    {
        buff->buffer[i] = (void **)kmalloc(sizeof(void *) * max_buffer, GFP_KERNEL);
        for(j = 0; j < max_buffer; j++)
            buff->buffer[i][j] = NULL;
        buff->data[i] = (char **)kmalloc(sizeof(char *) * max_buffer, GFP_KERNEL);
        for(j = 0; j < max_buffer; j++)
            buff->data[i][j] = NULL;
        for(j = 0; j < max_buffer; j++)
            buff->mMatrix[i][j] = NULL;
    }

    return 0;
}

int ovs__liu_buffer_free(struct __liu_buffer *buff)
{
    int i,j;
    for(i = 0; i < buff->in_port_num ;i++)
    {
        for(j = 0; j < buff->max_buffer; j++)
        {
            if(buff->buffer[i][j])
                kfree_skb(buff->buffer[i][j]);
        }
        kfree(buff->buffer[i]);
        kfree(buff->data[i]);
    }
    
    kfree(buff->flag);
    kfree(buff->head);
    kfree(buff->generation_id);
    kfree(buff->data);
    kfree(buff->buffer);
    buff->in_port_num = 0;
    buff->max_buffer = 0;
    return 0;
}

static uint32_t skb_get_generation_id(struct sk_buff *pk)
{
    struct iphdr *ip = (struct iphdr *)(((char *)pk->data) + pk->mac_len);
    struct nchdr *nc = (struct nchdr *)(((char *)pk->data) + pk->mac_len + ip->ihl);
    return nc->generation_id;
}

static void * skb_get_udp(struct sk_buff *pk)
{
    struct iphdr *ip = (struct iphdr *)(((char *)pk->data) + pk->mac_len);
    struct nchdr *nc = (struct nchdr *)(((char *)pk->data) + pk->mac_len + ip->ihl);
    return ((char *)nc) + nc->len;
}

static void * skb_get_vector(struct sk_buff *pk)
{
    struct iphdr *ip = (struct iphdr *)(((char *)pk->data) + pk->mac_len);
    struct nchdr *nc = (struct nchdr *)(((char *)pk->data) + pk->mac_len + ip->ihl);
    return nc->code_vector;
}

int liu_buffer_insert(struct liu_buffer *liubuff,\
        struct sk_buff *pk, uint8_t buffer_id, unsigned int id)
{
    int i;
    struct __liu_buffer * buff = &liubuff->buff[buffer_id];
    unsigned int head = buff->head[id];
    unsigned int g_id = skb_get_generation_id(pk);
    if(id >= buff->in_port_num)
    {
        printk(KERN_DEBUG "false id!\n");
        return -1;
    }
    //before insert, we check generation is right
    if(g_id > buff->generation_id[head])
    {// new generation 
        buff->generation_id[head] = g_id;
        // clean up the current buffer
        for( i = 0; i < buff->in_port_num; i++)
        {
            if(buff->buffer[id][i])
                kfree_skb(buff->buffer[id][i]);
            buff->buffer[id][i] = NULL;
        }
        buff->flag[head] = 0;
    } else if(g_id < buff->generation_id[head]) 
    { // disorder packet
        printk(KERN_DEBUG "generation id is small than record!\n");
        return -2;
    }

    buff->buffer[id][head] = pk;
    buff->data[id][head] = skb_get_udp(pk);
    buff->mMatrix[id][head] = skb_get_vector(pk);
    buff->flag[head] |= (1<< id);
    buff->head[id] ++;
    buff->head[id] = (buff->head[id] == buff->max_buffer)?buff->head[id]:0;
    if(buff->head[id] == buff->tail)
    { // buff too much packet
        buff->tail ++;
        buff->tail = (buff->tail == buff->max_buffer)?buff->tail:0;
    }
    if(buff->flag[head] + 1 == 1<<buff->in_port_num)
    { //buffer can decode, encode and init
        return 0;
    } else { //buffer is not full
        return 1;
    }
}

inline void encode(FIELD* buff1, FIELD* buff2, ulong size,
        FIELD* buff1_v, FIELD* buff2_v, ulong num, 
        FIELD vector1, FIELD vector2)
{
    cMulvAdd2(buff1, buff2, size, vector1, vector2);
    cMulvAdd2(buff1_v, buff2_v, num, vector1, vector2);
}

//flag = -2 indicate insert failed
//flag >= 0 indicate insert success, 
//#define DEBUG_NC_CODING
int appendM(struct __liu_buffer *buff, FIELD *vector, unsigned int num, unsigned int k)
{
    ulong i = 0;
    char flag = -2;
    FIELD tmp = 0;
    FIELD * tmpvector;
#ifdef DEBUG_NC_CODING
    printk(KERN_INFO "num %d, k %d\n", num, k);
#endif
    tmpvector = buff->tmpv;
    memset(tmpvector,0,sizeof(FIELD)*num);
    for(i = 0; i < num; i++)
    {
        tmp = vector[i];
        if(tmp == 0)
            continue;
        if(!buff->mMatrix[k][i])  
        {
            tmpvector[i] = gfadd(tmpvector[i], I_GF);
            cDiv(vector,num,tmp);
            cDiv(tmpvector,num,tmp);
            memcpy(buff->iMatrix[k][i], tmpvector, sizeof(FIELD) * num);
            buff->mMatrix[k][i] = vector;
            buff->flag[k]++;
#ifdef DEBUG_NC_CODING
            printk(KERN_INFO "i %d, flag %d, vector = %d,%d, iMatrix = %d, %d\n",i , buff->flag[k], vector[0], vector[1], buff->iMatrix[k][i][0], buff->iMatrix[k][i][1]);
#endif
            flag = i;
            break;
        } else {
            cMulvAdd(vector,buff->mMatrix[k][i],num,tmp);
            cMulvAdd(tmpvector,buff->iMatrix[k][i],num,tmp);
        }
    }
    
    if(flag == -2) {
        printk(KERN_INFO "There is a invalid insert!\n");
    }

    return flag;
}

int decode(struct __liu_buffer * buff, unsigned int num, unsigned int size, unsigned int k)
{
    ulong i,j;
    FIELD tmp;
    //after this for, iMatrix becomes inverse matrix of cMatrix
    for(i = num -1; i > 0; i--) 
    {
        j = i;
        do
        {
            j --;
            tmp = buff->mMatrix[k][j][i];
            cMulvAdd(buff->mMatrix[k][j], buff->mMatrix[k][i], num, tmp);
            cMulvAdd(buff->iMatrix[k][j], buff->iMatrix[k][i], num, tmp);
        } while(j != 0);
    }

    for(i = 0; i < num; i++)
    {
        memset(buff->out[i], 0 , sizeof(FIELD)*size); 
        for(j = 0; j < num; j++)
        {
            cMulvAdd(buff->out[i], buff->data[j][k], size, buff->iMatrix[k][i][j]);
        }
        // init for next insert
    }
    return 0;
}

