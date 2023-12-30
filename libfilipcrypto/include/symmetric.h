
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

/**
 * The function initializes a symmetric encryption or decryption context with the specified action,
 * type, key, and initialization vector.
 * 
 * @param ctx A pointer to a symmetric_t structure, which is used to store the context information for
 * the symmetric encryption/decryption operation.
 * @param action The "action" parameter is an enum that specifies the action to be performed. It can
 * have one of the following values: SYMMETRIC_ENCRYPT or SYMMETRIC_DECRYPT
 * @param type The "type" parameter in the function "symmetric_new" is an enum that represents the type
 * of symmetric encryption algorithm to be used. It can take one of the following values:
 * @param key A pointer to the key used for encryption or decryption.
 * @param key_len The parameter `key_len` represents the length of the key in bytes.
 * @param iv A pointer to the iv used for encryption or decryption.
 * 
 * @return an integer value. 0 on success and 1 on error
 */
int symmetric_new(symmetric_t *ctx, enum symmetric_action action, enum symmetric_type type, unsigned char *key, size_t key_len, unsigned char *iv);

/**
 * The function `symmetric_update_keys` updates the key and initialization vector (IV) used for
 * symmetric encryption or decryption.
 * 
 * @param ctx A pointer to a symmetric_t structure, which contains information about the symmetric
 * encryption/decryption context.
 * @param new_key The `new_key` parameter is a pointer to an unsigned char array that represents the
 * new encryption key.
 * @param new_key_len The parameter `new_key_len` represents the length of the new key in bytes.
 * @param new_iv The `new_iv` parameter is a pointer to an unsigned char array that represents the new
 * initialization vector (IV) 
 * 
 * @return an integer value. 0 on success and 1 on error
 */
int symmetric_update_keys(symmetric_t *ctx, unsigned char *new_key, size_t new_key_len, unsigned char *new_iv);

/**
 * The function symmetric_encrypt_decrypt performs symmetric encryption or decryption using a specified
 * context and returns the result in the output buffer.
 * 
 * @param ctx The parameter `ctx` is a pointer to a structure of type `symmetric_t`. 
 * @param input The input is a pointer to the input data that needs to be encrypted or decrypted. It is
 * of type unsigned char*.
 * @param in_size The parameter `in_size` represents the size of the input data (`input`) in bytes.
 * @param output The `output` parameter is a pointer to an unsigned char array where the encrypted or
 * decrypted data will be stored. Before using this function make sure you allocate a buffer with enough size
 * To calculate the max buffer size use this formula: in_size + cipher_block_size. cipher_block_size is 0 for every cipher 
 * except 3DES_CBC where it is 8 and AESxxx_CBC where it is 16. You can use `symmetric_get_max_buffer_size` function
 * @param out_size The `out_size` parameter is a pointer to an integer that will be used to store the
 * size of the output data after encryption or decryption. The function will update the value of
 * `out_size` with the actual size of the output data.
 * 
 * @return an integer value. 0 on success and >=1 on error
 */
int symmetric_encrypt_decrypt(symmetric_t* ctx, unsigned char* input, const int in_size, unsigned char* output, int *out_size);

/**
 * The function `symmetric_get_max_buffer_size` calculates the maximum buffer size required for
 * symmetric encryption based on the input size and the type of encryption algorithm.
 * 
 * @param ctx A pointer to a structure of type symmetric_t, which contains information about the
 * symmetric encryption algorithm being used.
 * @param in_size The parameter `in_size` represents the size of the input data that needs to be
 * encrypted or decrypted.
 * 
 * @return the maximum buffer size required for symmetric encryption, given the input size.
 */
int symmetric_get_max_buffer_size(symmetric_t *ctx, const int in_size);

/**
 * The function `symmetric_free` frees the memory allocated for the `evp` field of the `symmetric_t`
 * structure.
 * 
 * @param ctx The parameter `ctx` is a pointer to a structure of type `symmetric_t`.
 */
void symmetric_free(symmetric_t* ctx);

#endif