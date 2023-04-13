#include <stdio.h>
#include "decrypt.h"
#include <stdint.h>

static const unsigned char sBox[16][16] =
        {{0x65 , 0x4c , 0x6a , 0x42 , 0x4b , 0x63 , 0x43 , 0x6b , 0x55 , 0x75 , 0x5a , 0x7a , 0x53 , 0x73 , 0x5b , 0x7b},
         {0x35 , 0x8c , 0x3a , 0x81 , 0x89 , 0x33 , 0x80 , 0x3b , 0x95 , 0x25 , 0x98 , 0x2a , 0x90 , 0x23 , 0x99 , 0x2b},
         {0xe5 , 0xcc , 0xe8 , 0xc1 , 0xc9 , 0xe0 , 0xc0 , 0xe9 , 0xd5 , 0xf5 , 0xd8 , 0xf8 , 0xd0 , 0xf0 , 0xd9 , 0xf9},
         {0xa5 , 0x1c , 0xa8 , 0x12 , 0x1b , 0xa0 , 0x13 , 0xa9 , 0x05 , 0xb5 , 0x0a , 0xb8 , 0x03 , 0xb0 , 0x0b , 0xb9},
         {0x32 , 0x88 , 0x3c , 0x85 , 0x8d , 0x34 , 0x84 , 0x3d , 0x91 , 0x22 , 0x9c , 0x2c , 0x94 , 0x24 , 0x9d , 0x2d},
         {0x62 , 0x4a , 0x6c , 0x45 , 0x4d , 0x64 , 0x44 , 0x6d , 0x52 , 0x72 , 0x5c , 0x7c , 0x54 , 0x74 , 0x5d , 0x7d},
         {0xa1 , 0x1a , 0xac , 0x15 , 0x1d , 0xa4 , 0x14 , 0xad , 0x02 , 0xb1 , 0x0c , 0xbc , 0x04 , 0xb4 , 0x0d , 0xbd},
         {0xe1 , 0xc8 , 0xec , 0xc5 , 0xcd , 0xe4 , 0xc4 , 0xed , 0xd1 , 0xf1 , 0xdc , 0xfc , 0xd4 , 0xf4 , 0xdd , 0xfd},
         {0x36 , 0x8e , 0x38 , 0x82 , 0x8b , 0x30 , 0x83 , 0x39 , 0x96 , 0x26 , 0x9a , 0x28 , 0x93 , 0x20 , 0x9b , 0x29},
         {0x66 , 0x4e , 0x68 , 0x41 , 0x49 , 0x60 , 0x40 , 0x69 , 0x56 , 0x76 , 0x58 , 0x78 , 0x50 , 0x70 , 0x59 , 0x79},
         {0xa6 , 0x1e , 0xaa , 0x11 , 0x19 , 0xa3 , 0x10 , 0xab , 0x06 , 0xb6 , 0x08 , 0xba , 0x00 , 0xb3 , 0x09 , 0xbb},
         {0xe6 , 0xce , 0xea , 0xc2 , 0xcb , 0xe3 , 0xc3 , 0xeb , 0xd6 , 0xf6 , 0xda , 0xfa , 0xd3 , 0xf3 , 0xdb , 0xfb},
         {0x31 , 0x8a , 0x3e , 0x86 , 0x8f , 0x37 , 0x87 , 0x3f , 0x92 , 0x21 , 0x9e , 0x2e , 0x97 , 0x27 , 0x9f , 0x2f},
         {0x61 , 0x48 , 0x6e , 0x46 , 0x4f , 0x67 , 0x47 , 0x6f , 0x51 , 0x71 , 0x5e , 0x7e , 0x57 , 0x77 , 0x5f , 0x7f},
         {0xa2 , 0x18 , 0xae , 0x16 , 0x1f , 0xa7 , 0x17 , 0xaf , 0x01 , 0xb2 , 0x0e , 0xbe , 0x07 , 0xb7 , 0x0f , 0xbf},
         {0xe2 , 0xca , 0xee , 0xc6 , 0xcf , 0xe7 , 0xc7 , 0xef , 0xd2 , 0xf2 , 0xde , 0xfe , 0xd7 , 0xf7 , 0xdf , 0xff}};

void xor_128(uint64_t* c, const uint64_t* a, const uint64_t* b) {
    c[0] = a[0] ^ b[0];
    c[1] = a[1] ^ b[1];
}

void lfsr(unsigned char *tmp, const unsigned char *key) {
    unsigned char feedback = 0;
    for (int i = 15; i >= 0; i--) {
        unsigned char bit = *key & (1 << i);
        feedback ^= bit >> i;
    }
    feedback &= 0x01;
    *tmp = (*tmp << 1) | feedback;
}

unsigned char gf_mul(unsigned char a, unsigned char b) {
    unsigned char p = 0;
    unsigned char counter;
    unsigned char carry;
    for (counter = 0; counter < 8; counter++) {
        if (b & 1)
            p ^= a;
        carry = a & 0x80;
        a <<= 1;
        if (carry)
            a ^= 0x1B; // 0x1B is the irreducible polynomial x^8 + x^4 + x^3 + x + 1
        b >>= 1;
    }
    return p;
}
void key_schedule(unsigned char key[], unsigned char round_keys[][16]) {
    unsigned char c[16] = {0};
    unsigned char tmp[16] = {0};
    unsigned char constant[16] = {
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    // Inisialisasi round keys pertama dengan kunci
    for (int i = 0; i < 16; i++) {
        round_keys[0][i] = key[i];
    }

    // Generate round keys ke-1 hingga ke-9
    for (int r = 1; r <= 9; r++) {
        // Hitung nilai c
        memcpy(c, constant, 16);
        constant[0] = xtime(constant[0]);
        xor_128(c, round_keys[r-1], c);

        // Hitung round key baru dengan fungsi LFSR
        lfsr(tmp, round_keys[r-1]);
        xor_128(tmp, c, tmp);
        xor_128(tmp, round_keys[r-1]+12, round_keys[r]);
        memcpy(round_keys[r]+4, round_keys[r-1]+4, 12);
    }

    // Generate round keys ke-10
    // Hitung nilai c
    memcpy(c, constant, 16);
    constant[0] = xtime(constant[0]);
    xor_128(c, round_keys[9], c);

    // Hitung round key baru dengan fungsi LFSR
    lfsr(tmp, round_keys[9]);
    xor_128(tmp, c, tmp);
    xor_128(tmp, round_keys[9]+12, round_keys[10]);
    memcpy(round_keys[10]+4, round_keys[9]+4, 12);
}

void add_round_key(unsigned char state[4][4], unsigned char round_key[16])
{
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[j][i] ^= round_key[i*4+j];
        }
    }
}

void inv_mix_columns(unsigned char state[4][4])
{
    unsigned char temp[4];

    for (int i = 0; i < 4; i++) {
        // copy the column to temp
        for (int j = 0; j < 4; j++) {
            temp[j] = state[j][i];
        }

        // perform inverse mix columns operation
        state[0][i] = gf_mul(temp[0], 0x0E) ^ gf_mul(temp[1], 0x0B) ^
                      gf_mul(temp[2], 0x0D) ^ gf_mul(temp[3], 0x09);
        state[1][i] = gf_mul(temp[0], 0x09) ^ gf_mul(temp[1], 0x0E) ^
                      gf_mul(temp[2], 0x0B) ^ gf_mul(temp[3], 0x0D);
        state[2][i] = gf_mul(temp[0], 0x0D) ^ gf_mul(temp[1], 0x09) ^
                      gf_mul(temp[2], 0x0E) ^ gf_mul(temp[3], 0x0B);
        state[3][i] = gf_mul(temp[0], 0x0B) ^ gf_mul(temp[1], 0x0D) ^
                      gf_mul(temp[2], 0x09) ^ gf_mul(temp[3], 0x0E);
    }
}

void inv_shift_rows(unsigned char state[4][4]) {
    unsigned char temp;

    // shift row 1 right by 1
    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;

    // shift row 2 right by 2
    temp = state[2][3];
    state[2][3] = state[2][1];
    state[2][1] = temp;
    temp = state[2][2];
    state[2][2] = state[2][0];
    state[2][0] = temp;

    // shift row 3 right by 3
    temp = state[3][3];
    state[3][3] = state[3][0];
    state[3][0] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = temp;
}

void inv_sub_bytes(unsigned char state[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = get_inv_s_box(sBox, state[i][j]);
        }
    }
}

// Definisi fungsi decrypt
void decrypt(unsigned char state[][4]){
    unsigned char round_keys[16][4] = {0};
    unsigned char key[16] = {0x00, 0x01, 0x02, 0x03,
                             0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0a, 0x0b,
                             0x0c, 0x0d, 0x0e, 0x0f};

    // Membuat kunci putaran dari kunci master
    key_schedule(key, round_keys);

    // Putaran ke-19, tidak ada operasi ShiftRows
    add_round_key(state, round_keys[19]);

    //putaran ke-18 hingga ke 1
    for(int i = 18; i > 0; i--){
        inv_mix_columns(state);
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, round_keys[i]);
    }
}

unsigned char get_inv_s_box(unsigned char sBox[16][16], unsigned char value) {
    int row = (value >> 4) & 0x0f;
    int col = value & 0x0f;
    return sBox[row][col];
}

/*
int main()
{
    unsigned char plaintext[16] = {0};
    unsigned char ciphertext[16] = {0};
    unsigned char state[4][4] = {
        {0x68, 0x61, 0x63, 0x6B},
        {0x74, 0x68, 0x65, 0x20},
        {0x70, 0x75, 0x63, 0x6B},
        {0x79, 0x21, 0x20, 0x21}
    };

    // Menerima input ciphertext dari pengguna
    printf("Masukkan ciphertext (16 byte): ");
    scanf("%s", ciphertext);

    // Inisialisasi state dengan ciphertext
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[j][i] = ciphertext[i*4+j];
        }
    }

    // Lakukan deskripsi Romulus pada state
    decrypt(state);

    // Mengambil plaintext dari state yang telah dideskripsi
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            plaintext[i*4+j] = state[j][i];
        }
    }

    // Output hasil deskripsi berupa plaintext
    printf("Hasil deskripsi: ");
    for (int i = 0; i < 16; i++) {
        printf("%c", plaintext[i]);
    }

    return 0;
}
*/
