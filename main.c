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

void enkripsi(unsigned char plaintext[MAX_MSG_LENGTH]){
    unsigned char key[CRYPTO_KEYBYTES];
    unsigned char nonce[CRYPTO_NPUBBYTES];
    unsigned char ciphertext[MAX_MSG_LENGTH + CRYPTO_ABYTES];
    unsigned char ad[AD_BLK_LEN_EVN] = "1234";
    unsigned long long plaintext_len, ad_len, ciphertext_len;

    // Inisialisasi kunci dan nonce
    memset(key, 0, sizeof(key));
    memset(nonce, 0, sizeof(nonce));

    ad_len = strlen((char*) ad) - 1;
    ad[ad_len] = '\0';

    plaintext_len = strlen((char*) plaintext) - 1;
    plaintext[plaintext_len] = '\0';

    // Enkripsi plaintext
    if (crypto_aead_encrypt(ciphertext, &ciphertext_len, plaintext, plaintext_len, ad, ad_len, NULL, nonce, key) != 0) {
        printf("Enkripsi gagal\n");
        return 1;
    }

    char ciphertext_hex[2 * ciphertext_len + 1];
    for (int i = 0; i < ciphertext_len; i++) {
        sprintf(&ciphertext_hex[2 * i], "%02x", ciphertext[i]);
    }
    printf("Ciphertext: %s\n", ciphertext_hex);
    //sreturn(ciphertext_hex);
}

int dekripsi(char hex[MAX_MSG_LENGTH * 2 + 1]){
    unsigned char ciphertext[MAX_MSG_LENGTH + CRYPTO_ABYTES];
    unsigned char key[CRYPTO_KEYBYTES];
    unsigned char plaintext[MAX_MSG_LENGTH];
    unsigned char nonce[CRYPTO_NPUBBYTES];
    unsigned char ad[AD_BLK_LEN_EVN] = "1234";
    unsigned long long plaintext_len, ad_len, ciphertext_len;

    // Inisialisasi kunci dan nonce
    memset(key, 0, sizeof(key));
    memset(nonce, 0, sizeof(nonce));

    ad_len = strlen((char*) ad) - 1;
    ad[ad_len] = '\0';

    plaintext_len = strlen((char*) plaintext) - 1;
    plaintext[plaintext_len] = '\0';
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

    return plaintext;
}

int main() {
    char plain[5] = "rafli";
    enkripsi(plain);
    char cipher[100] = "f29df7e1139eddaeeabdf79a4066478da68f371c08f489";
    dekripsi(cipher);
    /*
    printf("Masukkan plaintext: ");
    fgets((char*) plaintext, MAX_MSG_LENGTH, stdin);
    */


    // Input additional data
    //printf("Masukkan additional data: ");
    //fgets((char*) ad, AD_BLK_LEN_EVN, stdin);


    // Input ciphertext
    /*
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
    */
    return 0;
}
