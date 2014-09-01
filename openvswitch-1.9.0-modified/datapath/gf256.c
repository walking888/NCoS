
#include "gf256.h"

FIELD* mtab=NULL;
FIELD* dtab=NULL;

int initMulDivTab(char* fileName)
{
    if(!mtab) {
        struct file * f;
        mm_segment_t fs;
        if((f=filp_open(fileName,O_RDONLY, 0))==NULL)
            return FALSE;
        mtab=(FIELD*)kmalloc(sizeof(FIELD)*65536, GFP_KERNEL);
        dtab=(FIELD*)kmalloc(sizeof(FIELD)*65536, GFP_KERNEL);
        fs = get_fs();
        set_fs(KERNEL_DS);
        f->f_op->read(f, mtab, 65536L,&(f->f_pos));
        f->f_op->read(f, dtab, 65536L,&(f->f_pos));
        set_fs(fs);
        filp_close(f, NULL);
    }
	return TRUE;
}

void freeDivTab()
{
    kfree(mtab);
    kfree(dtab);
}
