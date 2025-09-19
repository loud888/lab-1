#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <openssl/des.h>

long get_file_size(FILE *file) {
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    return size;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s inputfile\n", argv[0]);
        return 1;
    }

    FILE *in = fopen(argv[1], "rb");
    if (!in) {
        fprintf(stderr, "Error opening file\n");
        return 1;
    }

    long size = get_file_size(in);
    unsigned char *input = malloc(size);
    unsigned char *output = malloc(size);
    fread(input, 1, size, in);
    fclose(in);

    DES_cblock key = {0x40, 0xfe, 0xdf, 0x38, 0x6d, 0xa1, 0x3d, 0x57};
    DES_cblock iv = {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    DES_key_schedule schedule;
    DES_set_key_unchecked(&key, &schedule);

    struct timeval t_start, t_end;
    long enc_times[5], dec_times[5];

    for (int i = 0; i < 5; i++) {
        gettimeofday(&t_start, 0);
        DES_cbc_encrypt(input, output, size, &schedule, &iv, DES_ENCRYPT);
        gettimeofday(&t_end, 0);
        enc_times[i] = (t_end.tv_sec - t_start.tv_sec) * 1000000 + (t_end.tv_usec - t_start.tv_usec);

        gettimeofday(&t_start, 0);
        DES_cbc_encrypt(output, input, size, &schedule, &iv, DES_DECRYPT);
        gettimeofday(&t_end, 0);
        dec_times[i] = (t_end.tv_sec - t_start.tv_sec) * 1000000 + (t_end.tv_usec - t_start.tv_usec);
    }

    long enc_avg = 0, dec_avg = 0;
    for (int i = 0; i < 5; i++) {
        enc_avg += enc_times[i];
        dec_avg += dec_times[i];
    }
    enc_avg /= 5;
    dec_avg /= 5;

    printf("File contains %ld bytes\n", size);
    printf("Encryption time: %ld us\n", enc_avg);
    printf("Decryption time: %ld us\n", dec_avg);

    free(input);
    free(output);
    return 0;
}
