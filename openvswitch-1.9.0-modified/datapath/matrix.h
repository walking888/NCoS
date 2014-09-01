/**

  ��ģ��ʵ��GF(256)����������;������㣬���о������㺯��ֻ��һ����identical()
  �������㺯������identical()�Լ�nc.c�е���������Լ�⡣

*/

#ifndef MATRIX_H
#define MATRIX_H

#include "gf256.h"

/*����vec��ÿ��������add/sub/mul/div����coeff*/
void cAdd(FIELD* vec,ulong size,FIELD coeff);
void cSub(FIELD* vec,ulong size,FIELD coeff);
void cMul(FIELD* vec,ulong size,FIELD coeff);
void cDiv(FIELD* vec,ulong size,FIELD coeff);

/*����vec1=����vec1 + ����vec2*/
void vAdd(FIELD* vec1,FIELD* vec2,ulong size);

/*����vec1=����vec1 + (����vec2��ÿ���������Ա���coeff)*/
void cMulvAdd(FIELD* vec1,FIELD* vec2,ulong size,FIELD coeff);
void cMulvAdd2(FIELD* vec1,FIELD* vec2,ulong size,FIELD vector1, FIELD vector2);

/*�����б任��n1*n2�ľ���rm��ǰn1�л��ɵ�λ�󣬸ú������ڽ������*/
int identical(FIELD** rm,ulong n1,ulong n2);

#endif
