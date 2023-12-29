
#ifndef __ASYMMETRIC_H__
#define __ASYMMETRIC_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>


typedef struct asymmetric_t
{
    RSA* public_key, *private_key;
    char* output_buffer, * path_to_public_key, * path_to_private_key;
    int output_size, key_size;
} asymmetric_t;


int generate_rsa_key_pair(const char *public_key_filename, const char *private_key_filename, unsigned int key_size);

RSA* get_public_key_from_file(const char *path);

RSA* get_private_key_from_file(const char *path);

int asymmetric_encrypt_new(asymmetric_t* ctx, const char* path_to_public_key, size_t key_size);
int asymmetric_encrypt(asymmetric_t* ctx, char* input, const int in_size);


int asymmetric_decrypt_new(asymmetric_t* ctx, const char* path_to_private_key, size_t key_size);
int asymmetric_decrypt(asymmetric_t* ctx, char* input, const int in_size);


void asymmetric_free(asymmetric_t* ctx);

#endif