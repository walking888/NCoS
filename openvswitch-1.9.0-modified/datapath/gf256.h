/**

  ��ģ���ṩGF(256)�ϵļӼ��˳����㣬��matrixģ���о�������Ļ�
  ���ϵ�"+"��������Ϊ���(XOR)��"*"��������Ϊģ��Լ����ʽ�ĳ˷���
  ���õĶ���ʽΪ[1, 0, 0, 0, 1, 1, 1, 0, 1]����һ���˽���Է��ʣ�
  http://www.math.rwth-aachen.de/~Frank.Luebeck/ConwayPol/cp2.html
  Ϊ����������ٶȣ��˳�����ͨ������ɡ�

*/


#ifndef GF256_H
#define GF256_H

#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <asm/uaccess.h>

#define TRUE 1
#define FALSE 0

#define uint16_t unsigned short

#ifndef NULL
#define NULL 0
#endif

#define true 1
#define false 0
#define bool int

#define I_GF ((FIELD)1)

/*GF�����СΪ256����unsigned char����*/
typedef unsigned char FIELD;

typedef unsigned long ulong;

extern FIELD* mtab;
extern FIELD* dtab;

/*GF(256)�ϵĳ˳������ò����ɣ��˺�����ļ�fileName����˳��*/
int initMulDivTab(char* fileName);

void freeDivTab(void);
/*GF(256)�ϵļӼ��˳�����*/
#define gfadd(x,y) (FIELD)((x)^(y))
#define gfsub(x,y) (FIELD)((x)^(y))
#define gfmul(x,y) (FIELD)(mtab[(x)*256+(y)])
#define gfdiv(x,y) (FIELD)(dtab[(x)*256+(y)])

#endif
