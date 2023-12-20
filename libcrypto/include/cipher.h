

#ifndef __CIPHER_H__
#define __CIPHER_H__


#include "asymmetric.h"
#include "symmetric.h"

enum cipher_type {
    CIPHER_AES256_CBC, 
    CIPHER_AES256_CTR, 
    CIPHER_AES256_GCM,
    CIPHER_AES192_CBC, 
    CIPHER_AES192_CTR, 
    CIPHER_AES192_GCM,
    CIPHER_AES128_CBC, 
    CIPHER_AES128_CTR, 
    CIPHER_AES128_GCM,
    CIPHER_3DES_CBC,
    CIPHER_3DES_CFB,
    CIPHER_XOR,
    CIPHER_RSA
};

typedef struct cipher{
    symmetric_t sym;
    asymmetric_t asym;
    int is_symmetric;
    char* output_buffer;
    int output_size;
    char* tag;
}cipher_t;

int cipher_encrypt_new(cipher_t *ctx, enum cipher_type type, unsigned char *key, size_t key_len, unsigned char *iv, const char* public_key_path, const int public_key_size);
int cipher_encrypt_update(cipher_t *ctx, unsigned char *new_key, size_t new_key_len, unsigned char *new_iv);
int cipher_encrypt(cipher_t* ctx, char* input, const int in_size, unsigned char* aad, size_t aad_size);
void cipher_encrypt_free(cipher_t* ctx);




int cipher_decrypt_new(cipher_t *ctx, enum cipher_type type, unsigned char *key, size_t key_len, unsigned char *iv, const char* private_key_path, const int private_key_size);
int cipher_decrypt_update(cipher_t *ctx, unsigned char *new_key, size_t new_key_len, unsigned char *new_iv);
int cipher_decrypt(cipher_t* ctx, char* input, const int in_size, unsigned char* aad, size_t aad_size, unsigned char *tag);
void cipher_decrypt_free(cipher_t* ctx);

#endif