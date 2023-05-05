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

    // Input plaintext
    printf("Masukkan plaintext: ");
    fgets((char*) plaintext, MAX_MSG_LENGTH, stdin);
    plaintext_len = strlen((char*) plaintext) - 1;
    plaintext[plaintext_len] = '\0';

    // Input additional data
    //printf("Masukkan additional data: ");
    //fgets((char*) ad, AD_BLK_LEN_EVN, stdin);
    ad_len = strlen((char*) ad) - 1;
    ad[ad_len] = '\0';

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

    // Input ciphertext
    printf("Masukkan ciphertext: ");
    char hex[MAX_MSG_LENGTH * 2 + 1];
    fgets(hex, sizeof(hex), stdin);
    ciphertext_len = (strlen(hex));
    hex[ciphertext_len-1] = '\0';

    // Konversi dari hexadecimal ke binary
    for (int i = 0; i < ciphertext_len; i += 2) {
        sscanf(hex + i, "%2hhx", ciphertext + i / 2);
    }

    // Dekripsi ciphertext
    if (crypto_aead_decrypt(plaintext, &plaintext_len, NULL, ciphertext, ciphertext_len / 2, ad, ad_len, nonce, key) != 0) {
        printf("Dekripsi gagal\n");
        return 1;
    }

    printf("Plaintext: %s\n", plaintext);

    return 0;
}
