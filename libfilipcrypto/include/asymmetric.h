
#ifndef __ASYMMETRIC_H__
#define __ASYMMETRIC_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>


enum asymmetric_action{
    ASYMMETRIC_ENCRYPT,
    ASYMMETRIC_DECRYPT,
};

typedef struct asymmetric_t
{
    RSA* public_key, *private_key;
    char* path_to_public_key, * path_to_private_key;
    enum asymmetric_action action;
    int key_size;
} asymmetric_t;

int generate_rsa_key_pair(const char *public_key_filename, const char *private_key_filename, unsigned int key_size);

RSA* get_public_key_from_file(const char *path);

RSA* get_private_key_from_file(const char *path);

int asymmetric_new(asymmetric_t* ctx, enum asymmetric_action action, const char* path_to_p_key);
int asymmetric_encrypt_decrypt(asymmetric_t* ctx, unsigned char* input, const int in_size, unsigned char* output, int *out_size);

void asymmetric_free(asymmetric_t* ctx);

int asymmetric_get_max_buffer_size(asymmetric_t *ctx);

#endif