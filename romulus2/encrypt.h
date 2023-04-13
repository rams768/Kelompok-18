#include <stdio.h>
#include <stdlib.h>
//#include "common.h"

unsigned char xtime(unsigned char x);
void SubBytes(unsigned char state[][4]);
void ShiftRows(unsigned char state[][4]);
void MixColumns(unsigned char state[][4]);
void AddRoundKey(unsigned char state[][4], unsigned char *roundKey);
void encrypt(unsigned char state[][4]);
