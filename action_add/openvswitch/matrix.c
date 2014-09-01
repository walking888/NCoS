#include "matrix.h"

void cMulvAdd2(FIELD* vec1,FIELD* vec2,ulong size,FIELD vector1, FIELD vector2)
{
	/*vec1=vector1*vec1+vector2*vec2*/
	ulong i;
	for(i=0;i<size;i++)
		vec1[i]=gfadd(gfmul(vector1,vec1[i]),gfmul(vector2,vec2[i]));
	return;
}

void cMulvAdd(FIELD* vec1,FIELD* vec2,ulong size,FIELD coeff)
{
	/*vec1=vec1+coeff*vec2*/
	ulong i;
	for(i=0;i<size;i++)
		vec1[i]=gfadd(vec1[i],gfmul(coeff,vec2[i]));
	return;
}

void cAdd(FIELD* vec,ulong size,FIELD coeff)
{
	ulong i;
	for(i=0;i<size;i++)
		vec[i]=gfadd(coeff,vec[i]);
	return;
}

void cSub(FIELD* vec,ulong size,FIELD coeff)
{
	ulong i;
	for(i=0;i<size;i++)
		vec[i]=gfsub(coeff,vec[i]);
	return;
}
void cMul(FIELD* vec,ulong size,FIELD coeff)
{
	ulong i;
	for(i=0;i<size;i++)
		vec[i]=gfmul(coeff,vec[i]);
	return;
}
void cDiv(FIELD* vec,ulong size,FIELD coeff)
{
	ulong i;
	for(i=0;i<size;i++)
		vec[i]=gfdiv(vec[i],coeff);
	return;
}


void vAdd(FIELD* vec1,FIELD* vec2,ulong size)
{
	ulong i;
	for(i=0;i<size;i++)
		vec1[i]=gfadd(vec1[i],vec2[i]);
	return;
}

int identical(FIELD** rm,ulong n1,ulong n2)
{
	ulong i,j;
	for(j=0;j<n1;j++)			//col
	{
		for(i=j;i<n1&&rm[i][j]==0;i++)
			;
		if(i==n1)
			return FALSE;			//singular matrix
		else if(i!=j)				//make rm[j][j] nonzero
		{
			FIELD* temp=rm[i];
			rm[i]=rm[j];
			rm[j]=temp;
		}
		cDiv(rm[j],n2,rm[j][j]);	//make rm[j][j]=1
		for(i=0;i<n1;i++)			//make rm[i][j]=0 (i!=j)
		{
			if(rm[i][j]==0||i==j)
				continue;
			cMulvAdd(rm[i],rm[j],n2,gfsub(0,rm[i][j]));
		}
	}
	return TRUE;
}

