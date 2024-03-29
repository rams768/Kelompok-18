#include "api.h"
#include "crypto_aead.h"
#include <stdio.h>
#include <string.h>

#define CRYPTO_BYTES 64


void string2hexString(unsigned char* input, int clen, char* output);
void *hextobyte(char *hexstring, unsigned char* bytearray );

unsigned char* getCipher(unsigned char *cipher, int clen) {
    unsigned char* output = (unsigned char*) malloc(clen * sizeof(unsigned char));

    for (int i = 0; i < clen; i++) {
        output[i] = cipher[i];
    }

    return output;
}

int main (int argc, char *argv[]) {

  unsigned long long mlen;
  unsigned long long clen;

  unsigned char plaintext[CRYPTO_BYTES];
  unsigned char cipher[CRYPTO_BYTES];
  unsigned char tes_cipher[CRYPTO_BYTES];
  unsigned char npub[CRYPTO_NPUBBYTES]="";
  unsigned char ad[CRYPTO_ABYTES]="";
  unsigned char nsec[CRYPTO_ABYTES]="";

  unsigned char key[CRYPTO_KEYBYTES];

  char pl[CRYPTO_BYTES]="";
  char chex[CRYPTO_BYTES]="";
  char tes_chex[CRYPTO_BYTES]="";
  char keyhex[2*CRYPTO_KEYBYTES+1]="0123456789ABCDEF0123456789ABCDEF";
  char nonce[2*CRYPTO_NPUBBYTES+1]="000000000000111111111111";
  char add[CRYPTO_ABYTES]="";

  printf("Masukkan plaintext: ");
  scanf("%s", pl);

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

  /*
  printf("Romulus-AEAD light-weight cipher\n");
  printf("Plaintext: %s\n",plaintext);
  printf("Key: %s\n",keyhex);
  printf("Nonce: %s\n",nonce);
  printf("Additional Information: %s\n\n",ad);

  printf("Plaintext: %s\n",plaintext);
  */

  int ret = crypto_aead_encrypt(cipher,&clen,plaintext,strlen(plaintext),ad,strlen(ad),nsec,npub,key);


  string2hexString(cipher,clen,chex);

  //PERINTAH MENAMPILKAN CHIPER
  printf("Cipher: %s, Len: %llu\n",cipher, clen);
  //printf("AWAL\n");
  printf("cipher dalam hexadecimal : %s\n", chex);
  //printf("cipher : %s, Len: %d\n", cipher, strlen(cipher));
  //printf("tes : %s", tes);
  ret = crypto_aead_decrypt(plaintext,&mlen,nsec,cipher,clen,ad,strlen(ad),npub,key);
  plaintext[mlen]='\0';
  printf("Plaintext: %s, Len: %llu\n",plaintext, mlen);

  /*
  printf("\nAKHIR\n");
  printf("chex : %s\n", chex);
  printf("Plaintext-Tes: %s, Len: %llu\n",plaintext, mlen);
  printf("chex : %s\n", chex);
  */

  /*
  hexString2string(chex, strlen(chex), tes_cipher);
  ret = crypto_aead_decrypt(plaintext,&mlen,nsec,tes_cipher,clen,ad,strlen(ad),npub,key);
  printf("\nAKHIR\n");
  printf("chex : %s\n", chex);
  printf("tes cipher : %s\n", tes_cipher);
  printf("Plaintext-Tes: %s, Len: %llu\n",plaintext, mlen);
  string2hexString(tes_cipher,clen,chex);
  printf("chex : %s\n", chex);
  */

  if (ret==0) {
    //printf("Success!\n");
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

void hexString2string(char* hex, int hexlen, char* output) {
    int i, j;
    char two_chars[3];
    two_chars[2] = '\0';

    for (i = 0, j = 0; i < hexlen; i += 2, j++) {
        two_chars[0] = hex[i];
        two_chars[1] = hex[i + 1];
        output[j] = (char)strtol(two_chars, NULL, 16);
    }
    output[j] = '\0';
}



void *hextobyte(char *hexstring, unsigned char* bytearray ) {

    int i;

    int str_len = strlen(hexstring);

    for (i = 0; i < (str_len / 2); i++) {
        sscanf(hexstring + 2*i, "%02x", &bytearray[i]);
    }

}
