
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
    SYMMETRIC_AES256_GCM,
    SYMMETRIC_AES192_CBC, 
    SYMMETRIC_AES192_CTR, 
    SYMMETRIC_AES192_GCM,
    SYMMETRIC_AES128_CBC, 
    SYMMETRIC_AES128_CTR, 
    SYMMETRIC_AES128_GCM,
    SYMMETRIC_3DES_CBC,
    SYMMETRIC_3DES_CFB,
    SYMMETRIC_XOR,
};

typedef struct symmetric
{
    EVP_CIPHER_CTX *evp;
    EVP_CIPHER *cipher;
    enum symmetric_type type;
    unsigned char *key, *iv;
    unsigned char *aad; // used only in GCM AES!
    unsigned char *tag; // used only in GCM AES! Always 16 bytes
    unsigned char* output_buffer;
    size_t output_size; 
    size_t key_len; // used only in XOR
} symmetric_t;

int symmetric_encrypt_new(symmetric_t *ctx, enum symmetric_type type, unsigned char *key, size_t key_len, unsigned char *iv);
int symmetric_encrypt_update(symmetric_t *ctx, unsigned char *new_key, size_t new_key_len, unsigned char *new_iv);
int symmetric_encrypt(symmetric_t* ctx, char* input, const int in_size, unsigned char* add, size_t aad_size);
void symmetric_encrypt_free(symmetric_t* ctx);


int symmetric_decrypt_new(symmetric_t *ctx, enum symmetric_type type, unsigned char *key, size_t key_len, unsigned char *iv);
int symmetric_decrypt_update(symmetric_t *ctx, unsigned char *new_key, size_t new_key_len, unsigned char *new_iv);
int symmetric_decrypt(symmetric_t* ctx, char* input, const int in_size, unsigned char* add, size_t aad_size, unsigned char *tag);
void symmetric_decrypt_free(symmetric_t* ctx);

void printEncryptedHex(unsigned char* buffer, size_t size);

#endif