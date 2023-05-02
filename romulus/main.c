#include "api.h"
#include "crypto_aead.h"
#include <stdio.h>
#include <string.h>

#define CRYPTO_BYTES 64


void string2hexString(unsigned char* input, int clen, char* output);
void *hextobyte(char *hexstring, unsigned char* bytearray );
void romulus_aead_encrypt(unsigned char* cipher, unsigned long long* clen, const unsigned char* plaintext, const unsigned char* keyhex, const unsigned char* nonce, const unsigned char* add);
void romulus_aead_decrypt(unsigned char* plaintext, unsigned long long* mlen, const unsigned char* cipher, unsigned long long clen, const unsigned char* keyhex, const unsigned char* nonce, const unsigned char* add);

int main(int argc, char *argv[]) {

  unsigned long long mlen;
  unsigned long long clen;

  unsigned char plaintext[CRYPTO_BYTES];
  unsigned char cipher[CRYPTO_BYTES];
  unsigned char npub[CRYPTO_NPUBBYTES] = "";
  unsigned char ad[CRYPTO_ABYTES] = "";
  unsigned char nsec[CRYPTO_ABYTES] = "";

  char pl[CRYPTO_BYTES] = "";
  char chex[CRYPTO_BYTES] = "";
  char keyhex[2*CRYPTO_KEYBYTES+1] = "0123456789ABCDEF0123456789ABCDEF";
  char nonce[2*CRYPTO_NPUBBYTES+1] = "000000000000111111111111";
  char add[CRYPTO_ABYTES] = "";

  printf("Masukkan plaintext: ");
  scanf("%s", pl);

  if (argc > 1) {
    strcpy(pl, argv[1]);
  }
  if (argc > 2) {
    strcpy(keyhex, argv[2]);
  }
  if (argc > 3) {
    strcpy(nonce, argv[3]);
  }
  if (argc > 4) {
    strcpy(add, argv[4]);
  }

  if (strlen(keyhex) != 32) {
    printf("Key length needs to be 16 bytes");
    return 0;
  }

  strcpy(plaintext,pl);
  // mengenkripsi plaintext menggunakan fungsi romulus_aead_encrypt()
  romulus_aead_encrypt(cipher, &clen, plaintext, keyhex, nonce, add);

  // mendekripsi cipher yang telah dihasilkan dengan fungsi romulus_aead_decrypt()
  romulus_aead_decrypt(plaintext, &mlen, cipher, clen, keyhex, nonce, add);
  plaintext[mlen] = '\0';
  printf("Plaintext: %s, Len: %llu\n",plaintext, mlen);
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

void romulus_aead_encrypt(unsigned char* cipher, unsigned long long* clen, const unsigned char* plaintext, const unsigned char* keyhex, const unsigned char* nonce, const unsigned char* add) {
    unsigned long long mlen = strlen((char*)plaintext);
    unsigned char key[CRYPTO_KEYBYTES];
    unsigned char npub[CRYPTO_NPUBBYTES];
    unsigned char ad[CRYPTO_ABYTES];
    unsigned char nsec[CRYPTO_ABYTES];

    // copy key, nonce, and add to byte arrays
    hextobyte(keyhex, key);
    hextobyte(nonce, npub);
    strcpy(ad, add);

    // encrypt plaintext
    int ret = crypto_aead_encrypt(cipher, clen, plaintext, mlen, ad, strlen((char*)ad), nsec, npub, key);

    // print cipher in hexadecimal format
    unsigned char chex[*clen*2+1];
    string2hexString(cipher, *clen, chex);
    printf("Cipher: %s, Len: %llu\n", chex, *clen);

    // check if encryption was successful
    if (ret == 0) {
        printf("Encryption successful.\n");
    } else {
        printf("Encryption failed.\n");
    }
}

void romulus_aead_decrypt(unsigned char* plaintext, unsigned long long* mlen, const unsigned char* cipher, unsigned long long clen, const unsigned char* keyhex, const unsigned char* nonce, const unsigned char* add) {
    unsigned char key[CRYPTO_KEYBYTES];
    unsigned char npub[CRYPTO_NPUBBYTES];
    unsigned char ad[CRYPTO_ABYTES];
    unsigned char nsec[CRYPTO_ABYTES];

    // copy key, nonce, and add to byte arrays
    hextobyte(keyhex, key);
    hextobyte(nonce, npub);
    strcpy(ad, add);
    //printf("Plaintext: %s\n", plaintext);
    // decrypt cipher
    int ret = crypto_aead_decrypt(plaintext, mlen, nsec, cipher, clen, ad, strlen((char*)ad), npub, key);

    printf("Plaintext: %s\n", plaintext);
    // check if decryption was successful
    if (ret == 0) {
        printf("Decryption successful.\n");
    } else {
        printf("Decryption failed. ret = %d\n", ret);
    }
}
