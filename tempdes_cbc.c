#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>

void hex_to_bin(const char *hex, unsigned char *bin, int len) {
    for (int i = 0; i < len; i++) {
        sscanf(hex + 2 * i, "%2hhx", &bin[i]);
    }
}

int is_valid_hex(const char *str, int len) {
    if (strlen(str) != len * 2) return 0;
    for (int i = 0; i < len * 2; i++) {
        if (!((str[i] >= '0' && str[i] <= '9') || 
              (str[i] >= 'a' && str[i] <= 'f') || 
              (str[i] >= 'A' && str[i] <= 'F'))) {
            return 0;
        }
    }
    return 1;
}

long get_file_size(FILE *file) {
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    return size;
}

void cbc_encrypt(unsigned char *in, unsigned char *out, long length, 
                DES_key_schedule *schedule, unsigned char *iv) {
    unsigned char prev_block[8], temp[8];
    memcpy(prev_block, iv, 8);
    
    for (long i = 0; i < length; i += 8) {
        for (int j = 0; j < 8; j++) {
            temp[j] = in[i + j] ^ prev_block[j];
        }
        DES_encrypt1((DES_LONG *)temp, schedule, DES_ENCRYPT);
        memcpy(prev_block, temp, 8);
        memcpy(out + i, temp, 8);
    }
}

void cbc_decrypt(unsigned char *in, unsigned char *out, long length, 
                 DES_key_schedule *schedule, unsigned char *iv) {
    unsigned char prev_block[8], temp[8];
    memcpy(prev_block, iv, 8);
    
    for (long i = 0; i < length; i += 8) {
        memcpy(temp, in + i, 8);
        DES_encrypt1((DES_LONG *)temp, schedule, DES_DECRYPT);
        for (int j = 0; j < 8; j++) {
            out[i + j] = temp[j] ^ prev_block[j];
        }
        memcpy(prev_block, in + i, 8);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s iv key inputfile outputfile\n", argv[0]);
        return 1;
    }

    if (!is_valid_hex(argv[1], 8) || !is_valid_hex(argv[2], 8)) {
        fprintf(stderr, "IV and key must be 16 hex characters\n");
        return 1;
    }

    unsigned char iv[8], key[8];
    hex_to_bin(argv[1], iv, 8);
    hex_to_bin(argv[2], key, 8);

    FILE *in = fopen(argv[3], "rb");
    FILE *out = fopen(argv[4], "wb");
    if (!in || !out) {
        fprintf(stderr, "Error opening files\n");
        if (in) fclose(in);
        if (out) fclose(out);
        return 1;
    }

    long size = get_file_size(in);
    if (size % 8 != 0) {
        fprintf(stderr, "File size must be a multiple of 8 bytes\n");
        fclose(in);
        fclose(out);
        return 1;
    }

    DES_cblock des_key;
    DES_key_schedule schedule;
    memcpy(des_key, key, 8);
    DES_set_key_unchecked(&des_key, &schedule);

    unsigned char *in_buf = malloc(size);
    unsigned char *out_buf = malloc(size);
    fread(in_buf, 1, size, in);

    if (strstr(argv[4], ".des")) {
        cbc_encrypt(in_buf, out_buf, size, &schedule, iv);
    } else {
        cbc_decrypt(in_buf, out_buf, size, &schedule, iv);
    }

    fwrite(out_buf, 1, size, out);

    fclose(in);
    fclose(out);
    free(in_buf);
    free(out_buf);
    printf("Operation successful!\n");
    return 0;
}
