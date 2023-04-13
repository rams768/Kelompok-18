#include <stdio.h>
#include <string.h>

#define CRYPTO_BYTES 64

#include <stdlib.h>
#include <time.h>

#define MSG_BLK_LEN 16
#define AD_BLK_LEN_ODD 16
#define AD_BLK_LEN_EVN 16
#define CRYPTO_KEYBYTES 16
#define CRYPTO_NSECBYTES 0
#define CRYPTO_NPUBBYTES 16
#define CRYPTO_ABYTES 16
#define CRYPTO_NOOVERLAP 1

/*void display_vector (const unsigned char* x, int lenx) {
  int i;

  for (i = 0; i < lenx; i++) {
    //printf("%02x",x[i]);
  }
  //printf("\n");

  }*/

void pad (const unsigned char* m, unsigned char* mp, int l, int len8) {
  int i;

  for (i = 0; i < l; i++) {
    if (i < len8) {
      mp[i] = m[i];
    }
    else if (i == l - 1) {
      mp[i] = (len8 & 0x0f);
    }
    else {
      mp[i] = 0x00;
    }
  }

}

void g8A (unsigned char* s, unsigned char* c) {
  int i;

  for (i = 0; i < 16; i++) {
    c[i] = (s[i] >> 1) ^ (s[i] & 0x80) ^ ((s[i] & 0x01) << 7);
  }

}

void rho_ad (const unsigned char* m,
	     unsigned char* s,
	     int len8,
	     int ver) {
  int i;
  unsigned char mp [16];

  //printf("rho in m  = ");display_vector(m,len8);
  pad(m,mp,ver,len8);
  //printf("rho in mp = ");display_vector(mp,16);
  //printf("rho in s  = ");display_vector(s,16);
  for (i = 0; i < ver; i++) {
    s[i] = s[i] ^ mp[i];
  }
  //printf("rho out s = ");display_vector(s,16);

}

void rho (const unsigned char* m,
	  unsigned char* c,
	  unsigned char* s,
	  int len8,
	  int ver) {
  int i;
  unsigned char mp [16];

  //printf("rho in m  = ");display_vector(m,len8);
  pad(m,mp,ver,len8);
  //printf("rho in mp = ");display_vector(mp,16);
  //printf("rho in s  = ");display_vector(s,16);

  g8A(s,c);
  for (i = 0; i < ver; i++) {
    s[i] = s[i] ^ mp[i];
    if (i < len8) {
      c[i] = c[i] ^ mp[i];
    }
    else {
      c[i] = 0;
    }
  }
  //printf("rho out s = ");display_vector(s,16);
  //printf("rho out c = ");display_vector(c,16);

}

void irho (unsigned char* m,
	  const unsigned char* c,
	  unsigned char* s,
	  int len8,
	  int ver) {
  int i;
  unsigned char cp [16];

  //printf("irho in c  = ");display_vector(c,len8);
  pad(c,cp,ver,len8);
  //printf("irho in cp = ");display_vector(cp,16);
  //printf("irho in s  = ");display_vector(s,16);

  g8A(s,m);
  for (i = 0; i < ver; i++) {
    if (i < len8) {
      s[i] = s[i] ^ cp[i] ^ m[i];
    }
    else {
      s[i] = s[i] ^ cp[i];
    }
    if (i < len8) {
      m[i] = m[i] ^ cp[i];
    }
    else {
      m[i] = 0;
    }
  }
  //printf("irho out s = ");display_vector(s,16);
  //printf("irho out m = ");display_vector(c,16);

}

void reset_lfsr_gf56 (unsigned char* CNT) {
  CNT[0] = 0x01;
  CNT[1] = 0x00;
  CNT[2] = 0x00;
  CNT[3] = 0x00;
  CNT[4] = 0x00;
  CNT[5] = 0x00;
  CNT[6] = 0x00;
}

void lfsr_gf56 (unsigned char* CNT) {
  unsigned char fb0;

  fb0 = CNT[6] >> 7;

  CNT[6] = (CNT[6] << 1) | (CNT[5] >> 7);
  CNT[5] = (CNT[5] << 1) | (CNT[4] >> 7);
  CNT[4] = (CNT[4] << 1) | (CNT[3] >> 7);
  CNT[3] = (CNT[3] << 1) | (CNT[2] >> 7);
  CNT[2] = (CNT[2] << 1) | (CNT[1] >> 7);
  CNT[1] = (CNT[1] << 1) | (CNT[0] >> 7);
  if (fb0 == 1) {
    CNT[0] = (CNT[0] << 1) ^ 0x95;
  }
  else {
    CNT[0] = (CNT[0] << 1);
  }
}

void compose_tweakey (unsigned char* KT,
		      const unsigned char* K,
		      unsigned char* T,
		      unsigned char* CNT,
		      unsigned char D,
		      int t) {

  int i;

  for (i = 0; i < 7; i++) {
    KT[i] = CNT[i];
  }
  KT[i] = D;
  for (i = 8; i < 16; i++) {
    KT[i] = 0x00;
  }
  for (i = 0; i < t; i++) {
    KT[i+16] = T[i];
  }
  for (i = 0; i < 16; i++) {
    KT[i+16+t] = K[i];
  }

}

void block_cipher(unsigned char* s,
		  const unsigned char* k, unsigned char* T,
		  unsigned char* CNT, unsigned char D, int t, int n) {
  unsigned char KT [48];

  (void)n;
  compose_tweakey(KT,k,T,CNT,D,t);
  //printf("BC in kt = ");display_vector(KT,3*n);
  //printf("BC in s  = ");display_vector(s,n);
  skinny_128_384_enc (s,KT);
  //printf("BC out s = ");display_vector(s,n);

}

void nonce_encryption (const unsigned char* N,
		       unsigned char* CNT,
		       unsigned char*s, const unsigned char* k,
		       int t, int n, unsigned char D) {
  unsigned char T [16];
  int i;

  for (i = 0; i < t; i++) {
    T[i] = N[i];
  }
  //printf("nonce cnt = ");display_vector(CNT,7);
  block_cipher(s,k,T,CNT,D,t,n);

}

void generate_tag (unsigned char** c, unsigned char* s,
		   int n, unsigned long long* clen) {

  g8A(s, *c);
  *c = *c + n;
  *c = *c - *clen;

}

unsigned long long msg_encryption (const unsigned char** M, unsigned char** c,
				   const unsigned char* N,
				   unsigned char* CNT,
				   unsigned char*s, const unsigned char* k,
				   unsigned int n, unsigned int t, unsigned char D,
				   unsigned long long mlen) {
  int len8;


  if (mlen >= n) {
    len8 = n;
    mlen = mlen - n;
  }
  else {
    len8 = mlen;
    mlen = 0;
  }
  rho(*M, *c, s, len8, n);
  *c = *c + len8;
  *M = *M + len8;
  lfsr_gf56(CNT);
  if (mlen != 0) {
    nonce_encryption(N,CNT,s,k,t,n,D);
  }
  return mlen;
}



unsigned long long msg_decryption (unsigned char** M, const unsigned char** c,
				   const unsigned char* N,
				   unsigned char* CNT,
				   unsigned char*s, const unsigned char* k,
				   unsigned int n, unsigned int t, unsigned char D,
				   unsigned long long clen) {
  int len8;

  if (clen >= n) {
    len8 = n;
    clen = clen - n;
  }
  else {
    len8 = clen;
    clen = 0;
  }
  irho(*M, *c, s, len8, n);
  *c = *c + len8;
  *M = *M + len8;
  lfsr_gf56(CNT);
  nonce_encryption(N,CNT,s,k,t,n,D);
  return clen;
}

unsigned long long ad2msg_encryption (const unsigned char** M,
				      unsigned char* CNT,
				      unsigned char*s, const unsigned char* k,
				      unsigned int t, unsigned int n, unsigned char D,
				      unsigned long long mlen) {
  unsigned char T [16];
  int len8;

  if (mlen <= t) {
    len8 = mlen;
    mlen = 0;
  }
  else {
    len8 = t;
    mlen = mlen - t;
  }

  pad (*M,T,t,len8);
  //printf("ad2msg nonce cnt = ");display_vector(CNT,7);
  block_cipher(s,k,T,CNT,D,t,n);
  lfsr_gf56(CNT);
  *M = *M + len8;

  return mlen;

}


unsigned long long ad_encryption (const unsigned char** A, unsigned char* s,
				  const unsigned char* k, unsigned long long adlen,
				  unsigned char* CNT,
				  unsigned char D,
				  unsigned int n, unsigned int t) {

  unsigned char T [16];
  int len8;

  if (adlen >= n) {
    len8 = n;
    adlen = adlen - n;
  }
  else {
    len8 = adlen;
    adlen = 0;
  }
  //printf("AD in = ");display_vector(*A,len8);
  rho_ad(*A, s, len8, n);
  *A = *A + len8;
  lfsr_gf56(CNT);
  //printf("AD cnt = ");display_vector(CNT,7);
  if (adlen != 0) {
    if (adlen >= t) {
      len8 = t;
      adlen = adlen - t;
    }
    else {
      len8 = adlen;
      adlen = 0;
    }
    pad(*A, T, t, len8);
    *A = *A + len8;
    block_cipher(s,k,T,CNT,D,t,n);
    lfsr_gf56(CNT);
  }

  return adlen;
}

int crypto_aead_encrypt (
			 unsigned char* c, unsigned long long* clen,
			 const unsigned char* m, unsigned long long mlen,
			 const unsigned char* ad, unsigned long long adlen,
			 const unsigned char* nsec,
			 const unsigned char* npub,
			 const unsigned char* k
			 )
{
  unsigned char s[16];
  unsigned char CNT[7];
  unsigned char T[16];
  const unsigned char* N;
  unsigned int n, t, i;
  unsigned char w;
  unsigned long long xlen;

  (void)nsec;
  N = npub;

  n = AD_BLK_LEN_ODD;
  t = AD_BLK_LEN_EVN;

  xlen = mlen;

  for (i = 0; i < n; i++) {
    s[i] = 0;
  }
  reset_lfsr_gf56(CNT);
  //printf("s = ");display_vector(s,16);
  //printf("cnt = ");display_vector(CNT,7);

  w = 48;

  if (adlen == 0) {
    w = w ^ 2;
    if (xlen == 0) {
      w =w ^ 1;
    }
    else if (xlen%(n+t) == 0) {
      w = w ^ 4;
    }
    else if (xlen%(n+t) < t) {
      w = w ^ 1;
    }
    else if (xlen%(n+t) == t) {
      w = w ^ 0;
    }
    else {
      w = w ^ 5;
    }
  }
  else if (adlen%(n+t) == 0) {
    w = w ^ 8;
    if (xlen == 0) {
      w =w ^ 1;
    }
    else if (xlen%(n+t) == 0) {
      w = w ^ 4;
    }
    else if (xlen%(n+t) < n) {
      w = w ^ 1;
    }
    else if (xlen%(n+t) == n) {
      w = w ^ 0;
    }
    else {
      w = w ^ 5;
    }
  }
  else if (adlen%(n+t) < n) {
    w = w ^ 2;
    if (xlen == 0) {
      w =w ^ 1;
    }
    else if (xlen%(n+t) == 0) {
      w = w ^ 4;
    }
    else if (xlen%(n+t) < t) {
      w = w ^ 1;
    }
    else if (xlen%(n+t) == t) {
      w = w ^ 0;
    }
    else {
      w = w ^ 5;
    }
  }
  else if (adlen%(n+t) == n) {
    w = w ^ 0;
    if (xlen == 0) {
      w =w ^ 1;
    }
    else if (xlen%(n+t) == 0) {
      w = w ^ 4;
    }
    else if (xlen%(n+t) < t) {
      w = w ^ 1;
    }
    else if (xlen%(n+t) == t) {
      w = w ^ 0;
    }
    else {
      w = w ^ 5;
    }
  }
  else {
    w = w ^ 10;
    if (xlen == 0) {
      w =w ^ 1;
    }
    else if (xlen%(n+t) == 0) {
      w = w ^ 4;
    }
    else if (xlen%(n+t) < n) {
      w = w ^ 1;
    }
    else if (xlen%(n+t) == n) {
      w = w ^ 0;
    }
    else {
      w = w ^ 5;
    }
  }

  if (adlen == 0) { // AD is an empty string
    lfsr_gf56(CNT);
    //xlen = ad2msg_encryption (&m,CNT,s,k,t,n,44,xlen);
  }
  else while (adlen > 0) {
      adlen = ad_encryption(&ad,s,k,adlen,CNT,40,n,t);
    }

  if ((w & 8) == 0) {
    xlen = ad2msg_encryption (&m,CNT,s,k,t,n,44,xlen);
  }
  else if (mlen == 0) {
    lfsr_gf56(CNT);
  }
  while (xlen > 0) {
    xlen = ad_encryption(&m,s,k,xlen,CNT,44,n,t);
  }
  nonce_encryption(N,CNT,s,k,t,n,w);


  // Tag generation
  g8A(s, T);
  //printf("T = ");display_vector(T,n);

  m = m - mlen;

  reset_lfsr_gf56(CNT);

  for (i = 0; i < n; i = i + 1) {
    s[i] = T[i];
  }

  n = MSG_BLK_LEN;
  *clen = mlen + n;



  if (mlen > 0) {
    nonce_encryption(N,CNT,s,k,t,n,36);
    while (mlen > n) {
      mlen = msg_encryption(&m,&c,N,CNT,s,k,n,t,36,mlen);
    }
    rho(m, c, s, mlen, 16);
    c = c + mlen;
    m = m + mlen;
  }

  // Tag Concatenation
  for (i = 0; i < 16; i = i + 1) {
    *(c + i) = T[i];
  }

  c = c - *clen;



  return 0;
}

int crypto_aead_decrypt(
unsigned char *m,unsigned long long *mlen,
unsigned char *nsec,
const unsigned char *c,unsigned long long clen,
const unsigned char *ad,unsigned long long adlen,
const unsigned char *npub,
const unsigned char *k
)
{
  unsigned char s[16];
  unsigned char CNT[7];
  unsigned char T[16];
  const unsigned char* N;
  unsigned int n, t, i;
  unsigned char w;
  unsigned long long xlen;
  const unsigned char* mauth;

  (void)nsec;
  mauth = m;

  N = npub;

  n = AD_BLK_LEN_ODD;
  t = AD_BLK_LEN_EVN;

  xlen = clen-16;

  reset_lfsr_gf56(CNT);

  for (i = 0; i < 16; i++) {
    T[i] = *(c + clen - 16 + i);
  }

  for (i = 0; i < n; i = i + 1) {
    s[i] = T[i];
  }

  n = MSG_BLK_LEN;
  clen = clen - 16;
  *mlen = clen;


  if (clen > 0) {
    nonce_encryption(N,CNT,s,k,t,n,36);
    while (clen > n) {
      clen = msg_decryption(&m,&c,N,CNT,s,k,n,t,36,clen);
    }
    irho(m, c, s, clen, 16);
    c = c + clen;
    m = m + clen;
  }


  for (i = 0; i < n; i++) {
    s[i] = 0;
  }
  reset_lfsr_gf56(CNT);
  //printf("s = ");display_vector(s,16);
  //printf("cnt = ");display_vector(CNT,7);

  w = 48;

  if (adlen == 0) {
    w = w ^ 2;
    if (xlen == 0) {
      w =w ^ 1;
    }
    else if (xlen%(n+t) == 0) {
      w = w ^ 4;
    }
    else if (xlen%(n+t) < t) {
      w = w ^ 1;
    }
    else if (xlen%(n+t) == t) {
      w = w ^ 0;
    }
    else {
      w = w ^ 5;
    }
  }
  else if (adlen%(n+t) == 0) {
    w = w ^ 8;
    if (xlen == 0) {
      w =w ^ 1;
    }
    else if (xlen%(n+t) == 0) {
      w = w ^ 4;
    }
    else if (xlen%(n+t) < n) {
      w = w ^ 1;
    }
    else if (xlen%(n+t) == n) {
      w = w ^ 0;
    }
    else {
      w = w ^ 5;
    }
  }
  else if (adlen%(n+t) < n) {
    w = w ^ 2;
    if (xlen == 0) {
      w =w ^ 1;
    }
    else if (xlen%(n+t) == 0) {
      w = w ^ 4;
    }
    else if (xlen%(n+t) < t) {
      w = w ^ 1;
    }
    else if (xlen%(n+t) == t) {
      w = w ^ 0;
    }
    else {
      w = w ^ 5;
    }
  }
  else if (adlen%(n+t) == n) {
    w = w ^ 0;
    if (xlen == 0) {
      w =w ^ 1;
    }
    else if (xlen%(n+t) == 0) {
      w = w ^ 4;
    }
    else if (xlen%(n+t) < t) {
      w = w ^ 1;
    }
    else if (xlen%(n+t) == t) {
      w = w ^ 0;
    }
    else {
      w = w ^ 5;
    }
  }
  else {
    w = w ^ 10;
    if (xlen == 0) {
      w =w ^ 1;
    }
    else if (xlen%(n+t) == 0) {
      w = w ^ 4;
    }
    else if (xlen%(n+t) < n) {
      w = w ^ 1;
    }
    else if (xlen%(n+t) == n) {
      w = w ^ 0;
    }
    else {
      w = w ^ 5;
    }
  }

  if (adlen == 0) { // AD is an empty string
    lfsr_gf56(CNT);
    //xlen = ad2msg_encryption (&mauth,CNT,s,k,t,n,44,xlen);
  }
  else while (adlen > 0) {
      adlen = ad_encryption(&ad,s,k,adlen,CNT,40,n,t);
    }


  if ((w & 8) == 0) {
    xlen = ad2msg_encryption (&mauth,CNT,s,k,t,n,44,xlen);
  }
  else if (clen == 0) {
    lfsr_gf56(CNT);
  }
  while (xlen > 0) {
    xlen = ad_encryption(&mauth,s,k,xlen,CNT,44,n,t);
  }
  nonce_encryption(N,CNT,s,k,t,n,w);

    // Tag generation
  g8A(s, T);
  //printf("T = ");display_vector(T,16);
  //printf("t = ");display_vector(c,16);
  for (i = 0; i < 16; i++) {
    if (T[i] != (*(c+i))) {
      return -1;
    }
  }

  return 0;
}

#define DEBUG 0

// Table that encodes the parameters of the various Skinny versions:
// (block size, key size, number of rounds)
//Skinny-64-64: 32 rounds
//Skinny-64-128: 36 rounds
//Skinny-64-192: 40 rounds
//Skinny-128-128: 40 rounds
//Skinny-128-256: 48 rounds
//Skinny-128-384: 56 rounds
int versions[6][3]={{64,64,32},{64,128,36},{64,192,40},{128,128,40},{128,256,48},{128,384,56}};

// Packing of data is done as follows (state[i][j] stands for row i and column j):
// 0  1  2  3
// 4  5  6  7
// 8  9 10 11
//12 13 14 15

// 4-bit Sbox
const unsigned char sbox_4[16] = {12,6,9,0,1,10,2,11,3,8,5,13,4,14,7,15};
const unsigned char sbox_4_inv[16] = {3,4,6,8,12,10,1,14,9,2,5,7,0,11,13,15};

// 8-bit Sbox
const unsigned char sbox_8[256] = {0x65 , 0x4c , 0x6a , 0x42 , 0x4b , 0x63 , 0x43 , 0x6b , 0x55 , 0x75 , 0x5a , 0x7a , 0x53 , 0x73 , 0x5b , 0x7b ,0x35 , 0x8c , 0x3a , 0x81 , 0x89 , 0x33 , 0x80 , 0x3b , 0x95 , 0x25 , 0x98 , 0x2a , 0x90 , 0x23 , 0x99 , 0x2b ,0xe5 , 0xcc , 0xe8 , 0xc1 , 0xc9 , 0xe0 , 0xc0 , 0xe9 , 0xd5 , 0xf5 , 0xd8 , 0xf8 , 0xd0 , 0xf0 , 0xd9 , 0xf9 ,0xa5 , 0x1c , 0xa8 , 0x12 , 0x1b , 0xa0 , 0x13 , 0xa9 , 0x05 , 0xb5 , 0x0a , 0xb8 , 0x03 , 0xb0 , 0x0b , 0xb9 ,0x32 , 0x88 , 0x3c , 0x85 , 0x8d , 0x34 , 0x84 , 0x3d , 0x91 , 0x22 , 0x9c , 0x2c , 0x94 , 0x24 , 0x9d , 0x2d ,0x62 , 0x4a , 0x6c , 0x45 , 0x4d , 0x64 , 0x44 , 0x6d , 0x52 , 0x72 , 0x5c , 0x7c , 0x54 , 0x74 , 0x5d , 0x7d ,0xa1 , 0x1a , 0xac , 0x15 , 0x1d , 0xa4 , 0x14 , 0xad , 0x02 , 0xb1 , 0x0c , 0xbc , 0x04 , 0xb4 , 0x0d , 0xbd ,0xe1 , 0xc8 , 0xec , 0xc5 , 0xcd , 0xe4 , 0xc4 , 0xed , 0xd1 , 0xf1 , 0xdc , 0xfc , 0xd4 , 0xf4 , 0xdd , 0xfd ,0x36 , 0x8e , 0x38 , 0x82 , 0x8b , 0x30 , 0x83 , 0x39 , 0x96 , 0x26 , 0x9a , 0x28 , 0x93 , 0x20 , 0x9b , 0x29 ,0x66 , 0x4e , 0x68 , 0x41 , 0x49 , 0x60 , 0x40 , 0x69 , 0x56 , 0x76 , 0x58 , 0x78 , 0x50 , 0x70 , 0x59 , 0x79 ,0xa6 , 0x1e , 0xaa , 0x11 , 0x19 , 0xa3 , 0x10 , 0xab , 0x06 , 0xb6 , 0x08 , 0xba , 0x00 , 0xb3 , 0x09 , 0xbb ,0xe6 , 0xce , 0xea , 0xc2 , 0xcb , 0xe3 , 0xc3 , 0xeb , 0xd6 , 0xf6 , 0xda , 0xfa , 0xd3 , 0xf3 , 0xdb , 0xfb ,0x31 , 0x8a , 0x3e , 0x86 , 0x8f , 0x37 , 0x87 , 0x3f , 0x92 , 0x21 , 0x9e , 0x2e , 0x97 , 0x27 , 0x9f , 0x2f ,0x61 , 0x48 , 0x6e , 0x46 , 0x4f , 0x67 , 0x47 , 0x6f , 0x51 , 0x71 , 0x5e , 0x7e , 0x57 , 0x77 , 0x5f , 0x7f ,0xa2 , 0x18 , 0xae , 0x16 , 0x1f , 0xa7 , 0x17 , 0xaf , 0x01 , 0xb2 , 0x0e , 0xbe , 0x07 , 0xb7 , 0x0f , 0xbf ,0xe2 , 0xca , 0xee , 0xc6 , 0xcf ,0xe7 , 0xc7 , 0xef , 0xd2 , 0xf2 , 0xde , 0xfe , 0xd7 , 0xf7 , 0xdf , 0xff};
const unsigned char sbox_8_inv[256] = {0xac , 0xe8 , 0x68 , 0x3c , 0x6c , 0x38 , 0xa8 , 0xec , 0xaa , 0xae , 0x3a , 0x3e , 0x6a , 0x6e , 0xea , 0xee ,0xa6 , 0xa3 , 0x33 , 0x36 , 0x66 , 0x63 , 0xe3 , 0xe6 , 0xe1 , 0xa4 , 0x61 , 0x34 , 0x31 , 0x64 , 0xa1 , 0xe4 ,0x8d , 0xc9 , 0x49 , 0x1d , 0x4d , 0x19 , 0x89 , 0xcd , 0x8b , 0x8f , 0x1b , 0x1f , 0x4b , 0x4f , 0xcb , 0xcf ,0x85 , 0xc0 , 0x40 , 0x15 , 0x45 , 0x10 , 0x80 , 0xc5 , 0x82 , 0x87 , 0x12 , 0x17 , 0x42 , 0x47 , 0xc2 , 0xc7 ,0x96 , 0x93 , 0x03 , 0x06 , 0x56 , 0x53 , 0xd3 , 0xd6 , 0xd1 , 0x94 , 0x51 , 0x04 , 0x01 , 0x54 , 0x91 , 0xd4 ,0x9c , 0xd8 , 0x58 , 0x0c , 0x5c , 0x08 , 0x98 , 0xdc , 0x9a , 0x9e , 0x0a , 0x0e , 0x5a , 0x5e , 0xda , 0xde ,0x95 , 0xd0 , 0x50 , 0x05 , 0x55 , 0x00 , 0x90 , 0xd5 , 0x92 , 0x97 , 0x02 , 0x07 , 0x52 , 0x57 , 0xd2 , 0xd7 ,0x9d , 0xd9 , 0x59 , 0x0d , 0x5d , 0x09 , 0x99 , 0xdd , 0x9b , 0x9f , 0x0b , 0x0f , 0x5b , 0x5f , 0xdb , 0xdf ,0x16 , 0x13 , 0x83 , 0x86 , 0x46 , 0x43 , 0xc3 , 0xc6 , 0x41 , 0x14 , 0xc1 , 0x84 , 0x11 , 0x44 , 0x81 , 0xc4 ,0x1c , 0x48 , 0xc8 , 0x8c , 0x4c , 0x18 , 0x88 , 0xcc , 0x1a , 0x1e , 0x8a , 0x8e , 0x4a , 0x4e , 0xca , 0xce ,0x35 , 0x60 , 0xe0 , 0xa5 , 0x65 , 0x30 , 0xa0 , 0xe5 , 0x32 , 0x37 , 0xa2 , 0xa7 , 0x62 , 0x67 , 0xe2 , 0xe7 ,0x3d , 0x69 , 0xe9 , 0xad , 0x6d , 0x39 , 0xa9 , 0xed , 0x3b , 0x3f , 0xab , 0xaf , 0x6b , 0x6f , 0xeb , 0xef ,0x26 , 0x23 , 0xb3 , 0xb6 , 0x76 , 0x73 , 0xf3 , 0xf6 , 0x71 , 0x24 , 0xf1 , 0xb4 , 0x21 , 0x74 , 0xb1 , 0xf4 ,0x2c , 0x78 , 0xf8 , 0xbc , 0x7c , 0x28 , 0xb8 , 0xfc , 0x2a , 0x2e , 0xba , 0xbe , 0x7a , 0x7e , 0xfa , 0xfe ,0x25 , 0x70 , 0xf0 , 0xb5 , 0x75 , 0x20 , 0xb0 , 0xf5 , 0x22 , 0x27 , 0xb2 , 0xb7 , 0x72 , 0x77 , 0xf2 , 0xf7 ,0x2d , 0x79 , 0xf9 , 0xbd , 0x7d , 0x29 , 0xb9 , 0xfd , 0x2b , 0x2f , 0xbb , 0xbf , 0x7b , 0x7f , 0xfb , 0xff};

// ShiftAndSwitchRows permutation
const unsigned char P[16] = {0,1,2,3,7,4,5,6,10,11,8,9,13,14,15,12};
const unsigned char P_inv[16] = {0,1,2,3,5,6,7,4,10,11,8,9,15,12,13,14};

// Tweakey permutation
const unsigned char TWEAKEY_P[16] = {9,15,8,13,10,14,12,11,0,1,2,3,4,5,6,7};
const unsigned char TWEAKEY_P_inv[16] = {8,9,10,11,12,13,14,15,2,0,4,7,6,3,5,1};

// round constants
const unsigned char RC[62] = {
		0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F,
		0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B,
		0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E,
		0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A,
		0x34, 0x29, 0x12, 0x24, 0x08, 0x11, 0x22, 0x04, 0x09, 0x13,
		0x26, 0x0c, 0x19, 0x32, 0x25, 0x0a, 0x15, 0x2a, 0x14, 0x28,
		0x10, 0x20};

FILE* fic;


// Extract and apply the subtweakey to the internal state (must be the two top rows XORed together), then update the tweakey state
void AddKey(unsigned char state[4][4], unsigned char keyCells[3][4][4], int ver)
{
	int i, j, k;
	unsigned char pos;
	unsigned char keyCells_tmp[3][4][4];

    // apply the subtweakey to the internal state
    for(i = 0; i <= 1; i++)
    {
        for(j = 0; j < 4; j++)
        {
            state[i][j] ^= keyCells[0][i][j];
            if (2*versions[ver][0]==versions[ver][1])
                state[i][j] ^= keyCells[1][i][j];
            else if (3*versions[ver][0]==versions[ver][1])
               state[i][j] ^= keyCells[1][i][j] ^ keyCells[2][i][j];
        }
    }

    // update the subtweakey states with the permutation
    for(k = 0; k <(int)(versions[ver][1]/versions[ver][0]); k++){
        for(i = 0; i < 4; i++){
            for(j = 0; j < 4; j++){
                //application of the TWEAKEY permutation
                pos=TWEAKEY_P[j+4*i];
                keyCells_tmp[k][i][j]=keyCells[k][pos>>2][pos&0x3];
            }
        }
    }

    // update the subtweakey states with the LFSRs
    for(k = 0; k <(int)(versions[ver][1]/versions[ver][0]); k++){
        for(i = 0; i <= 1; i++){
            for(j = 0; j < 4; j++){
                //application of LFSRs for TK updates
                if (k==1)
                {
                    if (versions[ver][0]==64)
                        keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]<<1)&0xE)^((keyCells_tmp[k][i][j]>>3)&0x1)^((keyCells_tmp[k][i][j]>>2)&0x1);
                    else
                        keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]<<1)&0xFE)^((keyCells_tmp[k][i][j]>>7)&0x01)^((keyCells_tmp[k][i][j]>>5)&0x01);
                }
                else if (k==2)
                {
                    if (versions[ver][0]==64)
                        keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]>>1)&0x7)^((keyCells_tmp[k][i][j])&0x8)^((keyCells_tmp[k][i][j]<<3)&0x8);
                    else
                        keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]>>1)&0x7F)^((keyCells_tmp[k][i][j]<<7)&0x80)^((keyCells_tmp[k][i][j]<<1)&0x80);
                }
            }
        }
    }

    for(k = 0; k <(int)(versions[ver][1]/versions[ver][0]); k++){
        for(i = 0; i < 4; i++){
            for(j = 0; j < 4; j++){
                keyCells[k][i][j]=keyCells_tmp[k][i][j];
            }
        }
    }
}


// Extract and apply the subtweakey to the internal state (must be the two top rows XORed together), then update the tweakey state (inverse function}
void AddKey_inv(unsigned char state[4][4], unsigned char keyCells[3][4][4], int ver)
{
	int i, j, k;
	unsigned char pos;
	unsigned char keyCells_tmp[3][4][4];

    // update the subtweakey states with the permutation
    for(k = 0; k <(int)(versions[ver][1]/versions[ver][0]); k++){
        for(i = 0; i < 4; i++){
            for(j = 0; j < 4; j++){
                //application of the inverse TWEAKEY permutation
                pos=TWEAKEY_P_inv[j+4*i];
                keyCells_tmp[k][i][j]=keyCells[k][pos>>2][pos&0x3];
            }
        }
    }

    // update the subtweakey states with the LFSRs
    for(k = 0; k <(int)(versions[ver][1]/versions[ver][0]); k++){
        for(i = 2; i <= 3; i++){
            for(j = 0; j < 4; j++){
                //application of inverse LFSRs for TK updates
                if (k==1)
                {
                    if (versions[ver][0]==64)
                        keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]>>1)&0x7)^((keyCells_tmp[k][i][j]<<3)&0x8)^((keyCells_tmp[k][i][j])&0x8);
                    else
                        keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]>>1)&0x7F)^((keyCells_tmp[k][i][j]<<7)&0x80)^((keyCells_tmp[k][i][j]<<1)&0x80);
                }
                else if (k==2)
                {
                    if (versions[ver][0]==64)
                        keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]<<1)&0xE)^((keyCells_tmp[k][i][j]>>3)&0x1)^((keyCells_tmp[k][i][j]>>2)&0x1);
                    else
                        keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]<<1)&0xFE)^((keyCells_tmp[k][i][j]>>7)&0x01)^((keyCells_tmp[k][i][j]>>5)&0x01);
                }
            }
        }
    }

    for(k = 0; k <(int)(versions[ver][1]/versions[ver][0]); k++){
        for(i = 0; i < 4; i++){
            for(j = 0; j < 4; j++){
                keyCells[k][i][j]=keyCells_tmp[k][i][j];
            }
        }
    }


    // apply the subtweakey to the internal state
    for(i = 0; i <= 1; i++)
    {
        for(j = 0; j < 4; j++)
        {
            state[i][j] ^= keyCells[0][i][j];
            if (2*versions[ver][0]==versions[ver][1])
                state[i][j] ^= keyCells[1][i][j];
            else if (3*versions[ver][0]==versions[ver][1])
                state[i][j] ^= keyCells[1][i][j] ^ keyCells[2][i][j];
        }
    }
}


// Apply the constants: using a LFSR counter on 6 bits, we XOR the 6 bits to the first 6 bits of the internal state
void AddConstants(unsigned char state[4][4], int r)
{
	state[0][0] ^= (RC[r] & 0xf);
	state[1][0] ^= ((RC[r]>>4) & 0x3);
	state[2][0] ^= 0x2;
}

// apply the 4-bit Sbox
void SubCell4(unsigned char state[4][4])
{
	int i,j;
	for(i = 0; i < 4; i++)
		for(j = 0; j <  4; j++)
			state[i][j] = sbox_4[state[i][j]];
}

// apply the 4-bit inverse Sbox
void SubCell4_inv(unsigned char state[4][4])
{
	int i,j;
	for(i = 0; i < 4; i++)
		for(j = 0; j <  4; j++)
			state[i][j] = sbox_4_inv[state[i][j]];
}

// apply the 8-bit Sbox
void SubCell8(unsigned char state[4][4])
{
	int i,j;
	for(i = 0; i < 4; i++)
		for(j = 0; j <  4; j++)
			state[i][j] = sbox_8[state[i][j]];
}

// apply the 8-bit inverse Sbox
void SubCell8_inv(unsigned char state[4][4])
{
	int i,j;
	for(i = 0; i < 4; i++)
		for(j = 0; j <  4; j++)
			state[i][j] = sbox_8_inv[state[i][j]];
}

// Apply the ShiftRows function
void ShiftRows(unsigned char state[4][4])
{
	int i, j, pos;

	unsigned char state_tmp[4][4];
    for(i = 0; i < 4; i++)
    {
        for(j = 0; j < 4; j++)
        {
            //application of the ShiftRows permutation
            pos=P[j+4*i];
            state_tmp[i][j]=state[pos>>2][pos&0x3];
        }
    }

    for(i = 0; i < 4; i++)
    {
        for(j = 0; j < 4; j++)
        {
            state[i][j]=state_tmp[i][j];
        }
    }
}

// Apply the inverse ShiftRows function
void ShiftRows_inv(unsigned char state[4][4])
{
	int i, j, pos;

	unsigned char state_tmp[4][4];
    for(i = 0; i < 4; i++)
    {
        for(j = 0; j < 4; j++)
        {
            //application of the inverse ShiftRows permutation
            pos=P_inv[j+4*i];
            state_tmp[i][j]=state[pos>>2][pos&0x3];
        }
    }

    for(i = 0; i < 4; i++)
    {
        for(j = 0; j < 4; j++)
        {
            state[i][j]=state_tmp[i][j];
        }
    }
}

// Apply the linear diffusion matrix
//M =
//1 0 1 1
//1 0 0 0
//0 1 1 0
//1 0 1 0
void MixColumn(unsigned char state[4][4])
{
	int j;
    unsigned char temp;

	for(j = 0; j < 4; j++){
        state[1][j]^=state[2][j];
        state[2][j]^=state[0][j];
        state[3][j]^=state[2][j];

        temp=state[3][j];
        state[3][j]=state[2][j];
        state[2][j]=state[1][j];
        state[1][j]=state[0][j];
        state[0][j]=temp;
	}
}

// Apply the inverse linear diffusion matrix
void MixColumn_inv(unsigned char state[4][4])
{
	int j;
    unsigned char temp;

	for(j = 0; j < 4; j++){
        temp=state[3][j];
        state[3][j]=state[0][j];
        state[0][j]=state[1][j];
        state[1][j]=state[2][j];
        state[2][j]=temp;

        state[3][j]^=state[2][j];
        state[2][j]^=state[0][j];
        state[1][j]^=state[2][j];
	}
}

// decryption function of Skinny
void dec(unsigned char* input, const unsigned char* userkey, int ver)
{
	unsigned char state[4][4];
	unsigned char dummy[4][4]={{0}};
	unsigned char keyCells[3][4][4];
	int i;

    memset(keyCells, 0, 48);
	for(i = 0; i < 16; i++) {
        if (versions[ver][0]==64){
            if(i&1)
            {
                state[i>>2][i&0x3] = input[i>>1]&0xF;
                keyCells[0][i>>2][i&0x3] = userkey[i>>1]&0xF;
                if (versions[ver][1]>=128)
                    keyCells[1][i>>2][i&0x3] = userkey[(i+16)>>1]&0xF;
                if (versions[ver][1]>=192)
                    keyCells[2][i>>2][i&0x3] = userkey[(i+32)>>1]&0xF;
            }
            else
            {
                state[i>>2][i&0x3] = (input[i>>1]>>4)&0xF;
                keyCells[0][i>>2][i&0x3] = (userkey[i>>1]>>4)&0xF;
                if (versions[ver][1]>=128)
                    keyCells[1][i>>2][i&0x3] = (userkey[(i+16)>>1]>>4)&0xF;
                if (versions[ver][1]>=192)
                    keyCells[2][i>>2][i&0x3] = (userkey[(i+32)>>1]>>4)&0xF;
            }
        }
        else if (versions[ver][0]==128){
            state[i>>2][i&0x3] = input[i]&0xFF;

            keyCells[0][i>>2][i&0x3] = userkey[i]&0xFF;
            if (versions[ver][1]>=256)
                keyCells[1][i>>2][i&0x3] = userkey[i+16]&0xFF;
            if (versions[ver][1]>=384)
                keyCells[2][i>>2][i&0x3] = userkey[i+32]&0xFF;
        }
    }

    for(i = versions[ver][2]-1; i >=0 ; i--){
        AddKey(dummy, keyCells, ver);
    }

    #ifdef DEBUG
        //f//printf(fic,"DEC - initial state:                     ");display_cipher_state(state,keyCells,ver);//f//printf(fic,"\n");
    #endif

	for(i = versions[ver][2]-1; i >=0 ; i--){
        MixColumn_inv(state);
            #ifdef DEBUG
            //f//printf(fic,"DEC - round %.2i - after MixColumn_inv:    ",i);display_cipher_state(state,keyCells,ver);//f//printf(fic,"\n");
            #endif
        ShiftRows_inv(state);
            #ifdef DEBUG
            //f//printf(fic,"DEC - round %.2i - after ShiftRows_inv:    ",i);display_cipher_state(state,keyCells,ver);//f//printf(fic,"\n");
            #endif
        AddKey_inv(state, keyCells, ver);
            #ifdef DEBUG
            //f//printf(fic,"DEC - round %.2i - after AddKey_inv:       ",i);display_cipher_state(state,keyCells,ver);//f//printf(fic,"\n");
            #endif
        AddConstants(state, i);
            #ifdef DEBUG
            //f//printf(fic,"DEC - round %.2i - after AddConstants_inv: ",i);display_cipher_state(state,keyCells,ver);//f//printf(fic,"\n");
            #endif
        if (versions[ver][0]==64)
            SubCell4_inv(state);
        else
            SubCell8_inv(state);
            #ifdef DEBUG
            //f//printf(fic,"DEC - round %.2i - after SubCell_inv:      ",i);display_cipher_state(state,keyCells,ver);//f//printf(fic,"\n");
            #endif
	}

	#ifdef DEBUG
        //f//printf(fic,"DEC - final state:                       ");display_cipher_state(state,keyCells,ver);//f//printf(fic,"\n");
    #endif

    if (versions[ver][0]==64)
    {
        for(i = 0; i < 8; i++)
            input[i] = ((state[(2*i)>>2][(2*i)&0x3] & 0xF) << 4) | (state[(2*i+1)>>2][(2*i+1)&0x3] & 0xF);
    }
    else if (versions[ver][0]==128)
    {
        for(i = 0; i < 16; i++)
            input[i] = state[i>>2][i&0x3] & 0xFF;
    }
}

// encryption function of Skinny
void enc(unsigned char* input, const unsigned char* userkey, int ver)
{
	unsigned char state[4][4];
	unsigned char keyCells[3][4][4];
	int i;

	memset(keyCells, 0, 48);
	for(i = 0; i < 16; i++) {
        if (versions[ver][0]==64){
            if(i&1)
            {
                state[i>>2][i&0x3] = input[i>>1]&0xF;
                keyCells[0][i>>2][i&0x3] = userkey[i>>1]&0xF;
                if (versions[ver][1]>=128)
                    keyCells[1][i>>2][i&0x3] = userkey[(i+16)>>1]&0xF;
                if (versions[ver][1]>=192)
                    keyCells[2][i>>2][i&0x3] = userkey[(i+32)>>1]&0xF;
            }
            else
            {
                state[i>>2][i&0x3] = (input[i>>1]>>4)&0xF;
                keyCells[0][i>>2][i&0x3] = (userkey[i>>1]>>4)&0xF;
                if (versions[ver][1]>=128)
                    keyCells[1][i>>2][i&0x3] = (userkey[(i+16)>>1]>>4)&0xF;
                if (versions[ver][1]>=192)
                    keyCells[2][i>>2][i&0x3] = (userkey[(i+32)>>1]>>4)&0xF;
            }
        }
        else if (versions[ver][0]==128){
            state[i>>2][i&0x3] = input[i]&0xFF;
            keyCells[0][i>>2][i&0x3] = userkey[i]&0xFF;
            if (versions[ver][1]>=256)
                keyCells[1][i>>2][i&0x3] = userkey[i+16]&0xFF;
            if (versions[ver][1]>=384)
                keyCells[2][i>>2][i&0x3] = userkey[i+32]&0xFF;
        }
	}

    #ifdef DEBUG
        //printf("ENC - initial state:                 ");display_cipher_state(state,keyCells,ver);//printf("\n");
    #endif
	for(i = 0; i < versions[ver][2]; i++){
        if (versions[ver][0]==64)
            SubCell4(state);
        else
            SubCell8(state);
            #ifdef DEBUG
            //printf("ENC - round %.2i - after SubCell:      ",i);display_cipher_state(state,keyCells,ver);//printf("\n");
            #endif
        AddConstants(state, i);
            #ifdef DEBUG
            //printf("ENC - round %.2i - after AddConstants: ",i);display_cipher_state(state,keyCells,ver);//printf("\n");
            #endif
        AddKey(state, keyCells, ver);
            #ifdef DEBUG
            //printf("ENC - round %.2i - after AddKey:       ",i);display_cipher_state(state,keyCells,ver);//printf("\n");
            #endif
        ShiftRows(state);
            #ifdef DEBUG
            //printf("ENC - round %.2i - after ShiftRows:    ",i);display_cipher_state(state,keyCells,ver);//printf("\n");
            #endif
        MixColumn(state);
            #ifdef DEBUG
            //printf("ENC - round %.2i - after MixColumn:    ",i);display_cipher_state(state,keyCells,ver);//printf("\n");
            #endif
	}  //The last subtweakey should not be added

	#ifdef DEBUG
        //printf("ENC - final state:                   ");display_cipher_state(state,keyCells,ver);//printf("\n");
    #endif

    if (versions[ver][0]==64)
    {
        for(i = 0; i < 8; i++)
            input[i] = ((state[(2*i)>>2][(2*i)&0x3] & 0xF) << 4) | (state[(2*i+1)>>2][(2*i+1)&0x3] & 0xF);
    }
    else if (versions[ver][0]==128)
    {
        for(i = 0; i < 16; i++)
            input[i] = state[i>>2][i&0x3] & 0xFF;
    }
}

void skinny_128_384_enc (unsigned char* input, const unsigned char* userkey) {
  enc(input,userkey,5);
}

// generate test vectors for all the versions of Skinny
void TestVectors(int ver)
{
	unsigned char p[16];
	unsigned char c[16];
	unsigned char k[48];
	int n;

	for(n = 1; n < 10; n++)
	{
		int i;
		for(i = 0; i < (versions[ver][0]>>3); i++) c[i] = p[i] = rand() & 0xff;
		for(i = 0; i < (versions[ver][1]>>3); i++) k[i] = rand() & 0xff;
		//printf("TK = "); for(i = 0; i < (versions[ver][1]>>3); i++) //printf("%02x", k[i]); //printf("\n");
		//printf("P =  "); for(i = 0; i < (versions[ver][0]>>3); i++) //printf("%02x", p[i]); //printf("\n");
		enc(c,k,ver);
		//printf("C =  "); for(i = 0; i < (versions[ver][0]>>3); i++) //printf("%02x", c[i]); //printf("\n");
		dec(c,k,ver);
		//printf("P' = "); for(i = 0; i < (versions[ver][0]>>3); i++) //printf("%02x", c[i]); //printf("\n\n");
	}
}

/* int main() { */
/*     unsigned int i; */
/*     char name[30]; */

/*     srand((unsigned) time (NULL)); */

/*     //test all versions of Skinny */
/* 	for (i=0; i<(sizeof(versions)/sizeof(*versions));i++) */
/* 	{ */
/* 	    s//printf(name, "test_vectors_%i_%i.txt", versions[i][0], versions[i][1]); */
/* 	    fic=fopen(name,"w"); */
/* 		//printf("\n\nSkinny-%i/%i: \n",versions[i][0],versions[i][1]); */
/* 		TestVectors(i); */
/* 		fclose(fic); */
/* 		//printf("Generating test vectors for Skinny-%i/%i  -  saved in file test_vectors_%i_%i.txt \n",versions[i][0],versions[i][1],versions[i][0],versions[i][1]); */
/* 	} */

/* 	return 0; */
/* } */

void string2hexString(unsigned char* input, int clen, char* output);
void *hextobyte(char *hexstring, unsigned char* bytearray );

int main (int argc, char *argv[]) {


  unsigned long long mlen;
  unsigned long long clen;

  unsigned char plaintext[CRYPTO_BYTES];
  unsigned char cipher[CRYPTO_BYTES];
  unsigned char npub[CRYPTO_NPUBBYTES]="";
  unsigned char ad[CRYPTO_ABYTES]="";
  unsigned char nsec[CRYPTO_ABYTES]="";

  unsigned char key[CRYPTO_KEYBYTES];

  char pl[CRYPTO_BYTES]="";
  printf("Masukkin plaintext yang mau kamu enkripsiin dongs: ");
  scanf("%s", pl);
  //char pl[CRYPTO_BYTES]="hello";
  char chex[CRYPTO_BYTES]="";
  char keyhex[2*CRYPTO_KEYBYTES+1]="0123456789ABCDEF0123456789ABCDEF";
  char nonce[2*CRYPTO_NPUBBYTES+1]="000000000000111111111111";
   char add[CRYPTO_ABYTES]="";

  if( argc > 1 ) {
      strcpy(pl,argv[1]);
  }
  if( argc > 2 ) {
      strcpy(keyhex,argv[2]);
  }
    if( argc > 3 ) {
      strcpy(nonce,argv[3]);
  }
     if( argc > 4 ) {
      strcpy(add,argv[4]);
  }


  if (strlen(keyhex)!=32) {
	printf("Key length needs to be 16 bytes");
	return(0);
  }

  strcpy(plaintext,pl);
  strcpy(ad,add);
  hextobyte(keyhex,key);
  hextobyte(nonce,npub);

  printf("\n---JENG JENG JENG JENG---\n");
  printf("Ini loh hasilnya: \n\n");
  printf("Romulus-AEAD light-weight cipher\n");
  printf("Plaintext: %s\n",plaintext);
  printf("Key: %s\n",keyhex);
  printf("Nonce: %s\n",nonce);
  printf("Additional Information: %s\n\n",ad);

  printf("Plaintext: %s\n",plaintext);


  int ret = crypto_aead_encrypt(cipher,&clen,plaintext,strlen(plaintext),ad,strlen(ad),nsec,npub,key);


string2hexString(cipher,clen,chex);

  printf("Cipher: %s, Len: %llu\n",chex, clen);



  ret = crypto_aead_decrypt(plaintext,&mlen,nsec,cipher,clen,ad,strlen(ad),npub,key);

  plaintext[mlen]='\0';
  printf("Plaintext: %s, Len: %llu\n",plaintext, mlen);




  if (ret==0) {
    printf("Success!\n");
  }

	return 0;
}
void string2hexString(unsigned char* input, int clen, char* output)
{
    int loop;
    int i;

    i=0;
    loop=0;

    for (i=0;i<clen;i+=2){
        sprintf((char*)(output+i),"%02X", input[loop]);
        loop+=1;

    }
    //insert NULL at the end of the output string
    output[i++] = '\0';
}
void *hextobyte(char *hexstring, unsigned char* bytearray ) {

    int i;

    int str_len = strlen(hexstring);

    for (i = 0; i < (str_len / 2); i++) {
        sscanf(hexstring + 2*i, "%02x", &bytearray[i]);
    }

}
