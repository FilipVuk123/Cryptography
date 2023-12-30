
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

/**
 * The function generates an RSA key pair of a specified size and saves the public and private keys to
 * separate files.
 * 
 * @param public_key_filename The `public_key_filename` parameter is a string that specifies the
 * filename for the public key file. This file will store the generated RSA public key.
 * @param private_key_filename The `private_key_filename` parameter is a string that specifies the
 * filename for the private key file. This file will store the generated RSA private key.
 * @param key_size The `key_size` parameter specifies the size of the RSA key in bits. It determines
 * the strength of the encryption and the length of the generated key. Common key sizes are 1024, 2048,
 * or 4096 bits.
 * 
 * @return The function `generate_rsa_key_pair` returns an integer value. It returns 0 if the RSA key
 * pair generation and saving process is successful. It returns 1 if there is an error during the
 * process.
 */
int generate_rsa_key_pair(const char *public_key_filename, const char *private_key_filename, unsigned int key_size);

/**
 * The function `get_public_key_from_file` reads a public key from a file and returns it as an RSA
 * structure.
 * 
 * @param path The `path` parameter is a string that represents the file path to the public key file im pem format.
 * 
 * @return a pointer to an RSA structure, which represents the public key read from the file.
 */
RSA* get_public_key_from_file(const char *path);

/**
 * The function `get_private_key_from_file` reads a private key from a file and returns it as an RSA
 * structure.
 * 
 * @param path The `path` parameter is a string that represents the file path to the private key file in pem format.
 * 
 * @return a pointer to an RSA private key.
 */
RSA* get_private_key_from_file(const char *path);

/**
 * The function `asymmetric_new` initializes an `asymmetric_t` structure based on the specified action
 * and path to a public or private key file.
 * 
 * @param ctx The `ctx` parameter is a pointer to an `asymmetric_t` structure. This structure contains
 * various fields that store information related to asymmetric encryption and decryption.
 * @param action The "action" parameter is an enum that specifies the action to be performed. It can
 * have one of the following values: ASYMMETRIC_ENCRYPT or ASYMMETRIC_DECRYPT
 * @param path_to_p_key The `path_to_p_key` parameter is a string that represents the path to the
 * public or private key file, depending on the value of the `action` parameter. If the `action` is set
 * to `ASYMMETRIC_ENCRYPT`, then `path_to_p_key` should point to public key, if the `action` is set
 * to `ASYMMETRIC_DECRYPT`, then `path_to_p_key` should point to private key
 * 
 * @return an integer value. 0 on success and 1 on error
 */
int asymmetric_new(asymmetric_t* ctx, enum asymmetric_action action, const char* path_to_p_key);

/**
 * The function `asymmetric_encrypt_decrypt` performs asymmetric encryption or decryption using RSA
 * algorithm.
 * 
 * @param ctx A pointer to an asymmetric_t structure, which contains the necessary information for
 * encryption or decryption.
 * @param input The input parameter is a pointer to an unsigned char array that contains the data to be
 * encrypted or decrypted.
 * @param in_size The size of the input data in bytes.
 * @param output The `output` parameter is a pointer to an unsigned char array where the encrypted or
 * decrypted data will be stored. Make sure you allocate enough space for this buffer. You can use 
 * `asymmetric_get_max_buffer_size` to make sure you do.
 * @param out_size The `out_size` parameter is a pointer to an integer that will store the size of the
 * output after encryption or decryption. The function will update the value of `out_size` with the
 * actual size of the output data.
 * 
 * @return an integer value. 0 on success and 1 on error
 */
int asymmetric_encrypt_decrypt(asymmetric_t* ctx, unsigned char* input, const int in_size, unsigned char* output, int *out_size);

/**
 * The function `asymmetric_free` frees the memory allocated for the private and public keys in an
 * `asymmetric_t` structure.
 * 
 * @param ctx The parameter `ctx` is a pointer to a structure of type `asymmetric_t`.
 */
void asymmetric_free(asymmetric_t* ctx);

/**
 * The function returns the maximum encrypted buffer size for an asymmetric context.
 * 
 * @param ctx A pointer to an asymmetric_t structure.
 * 
 * @return the key size of the asymmetric context.
 */
int asymmetric_get_max_buffer_size(asymmetric_t *ctx);

#endif