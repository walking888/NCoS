/**

  本模块实现GF(256)上向量运算和矩阵运算，其中矩阵运算函数只有一个：identical()
  向量运算函数用于identical()以及nc.c中的线性相关性检测。

*/

#ifndef MATRIX_H
#define MATRIX_H

#include "gf256.h"

/*向量vec的每个分量都add/sub/mul/div标量coeff*/
void cAdd(FIELD* vec,ulong size,FIELD coeff);
void cSub(FIELD* vec,ulong size,FIELD coeff);
void cMul(FIELD* vec,ulong size,FIELD coeff);
void cDiv(FIELD* vec,ulong size,FIELD coeff);

/*向量vec1=向量vec1 + 向量vec2*/
void vAdd(FIELD* vec1,FIELD* vec2,ulong size);

/*向量vec1=向量vec1 + (向量vec2的每个分量乘以标量coeff)*/
void cMulvAdd(FIELD* vec1,FIELD* vec2,ulong size,FIELD coeff);
void cMulvAdd2(FIELD* vec1,FIELD* vec2,ulong size,FIELD vector1, FIELD vector2);

/*初等行变换把n1*n2的矩阵rm的前n1列化成单位阵，该函数用于解码操作*/
int identical(FIELD** rm,ulong n1,ulong n2);

#endif
