#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
//#include "common.h"

void key_schedule(unsigned char key[], unsigned char round_keys[][16]);

void add_round_key(unsigned char state[4][4], unsigned char round_key[16]);

void inv_mix_columns(unsigned char state[4][4]);

void inv_shift_rows(unsigned char state[4][4]);

void inv_sub_bytes(unsigned char state[4][4]);

void decrypt(unsigned char state[][4]);

unsigned char get_inv_s_box(unsigned char sBox[16][16], unsigned char value);

void xor_128(uint64_t* c, const uint64_t* a, const uint64_t* b);

void lfsr(unsigned char *tmp, const unsigned char *key);

unsigned char gf_mul(unsigned char a, unsigned char b);



