#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "api.h"
#include "crypto_aead.h"
#include "romulus_m.h"
#include "skinny.h"
#include "variant.h"

#define MAX_MSG_LENGTH 1024
#define AD_BLK_LEN_EVN 16

int main() {
    unsigned char key[CRYPTO_KEYBYTES];
    unsigned char nonce[CRYPTO_NPUBBYTES];
    unsigned char plaintext[MAX_MSG_LENGTH];
    unsigned char ciphertext[MAX_MSG_LENGTH + CRYPTO_ABYTES];
    unsigned char ad[AD_BLK_LEN_EVN] = "1234";
    unsigned long long plaintext_len, ad_len, ciphertext_len;

    // Inisialisasi kunci dan nonce
    memset(key, 0, sizeof(key));
    memset(nonce, 0, sizeof(nonce));

    ad_len = strlen((char*) ad) - 1;
    ad[ad_len] = '\0';

    // Input plaintext
    printf("Masukkan plaintext: ");
    fgets((char*) plaintext, MAX_MSG_LENGTH, stdin);
    plaintext_len = strlen((char*) plaintext) - 1;
    plaintext[plaintext_len] = '\0';

    // Input additional data
    //printf("Masukkan additional data: ");
    //fgets((char*) ad, AD_BLK_LEN_EVN, stdin);


    // Enkripsi plaintext
    if (crypto_aead_encrypt(ciphertext, &ciphertext_len, plaintext, plaintext_len, ad, ad_len, NULL, nonce, key) != 0) {
        printf("Enkripsi gagal\n");
        return 1;
    }

    printf("Ciphertext: ");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    return 0;
}
