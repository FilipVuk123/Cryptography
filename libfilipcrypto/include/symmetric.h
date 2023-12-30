
#ifndef __SYMMETRIC_H__
#define __SYMMETRIC_H__


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/des.h>

enum symmetric_type
{
    SYMMETRIC_AES256_CBC, 
    SYMMETRIC_AES256_CTR, 
    SYMMETRIC_AES256_OFB,
    SYMMETRIC_AES192_CBC, 
    SYMMETRIC_AES192_CTR, 
    SYMMETRIC_AES192_OFB,
    SYMMETRIC_AES128_CBC, 
    SYMMETRIC_AES128_CTR, 
    SYMMETRIC_AES128_OFB,
    SYMMETRIC_3DES_CBC,
    SYMMETRIC_3DES_CFB,
    SYMMETRIC_XOR,
};

enum symmetric_action{
    SYMMETRIC_ENCRYPT,
    SYMMETRIC_DECRYPT,
};

typedef struct symmetric
{
    EVP_CIPHER_CTX *evp;
    EVP_CIPHER *cipher;
    enum symmetric_type type;
    enum symmetric_action action;
    unsigned char *key, *iv;
    int key_len; // used only in XOR

} symmetric_t;

int symmetric_new(symmetric_t *ctx, enum symmetric_action action, enum symmetric_type type, unsigned char *key, size_t key_len, unsigned char *iv);
int symmetric_update_keys(symmetric_t *ctx, unsigned char *new_key, size_t new_key_len, unsigned char *new_iv);
int symmetric_encrypt_decrypt(symmetric_t* ctx, unsigned char* input, const int in_size, unsigned char* output, int * out_size);

void symmetric_free(symmetric_t* ctx);

#endif