#ifndef __HASH_H__
#define __HASH_H__


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>

enum hash_type
{
    HASH_SHA256, // returns 32 bytes
    HASH_SHA384, // returns 48 bytes
    HASH_SHA512, // returns 64 bytes
};

typedef struct hash{
    char* hash_buffer;
    int hash_length;
    enum hash_type hash_type;
} hash_t;

/**
 * The function `hash` takes in a hash type, input buffer, input lengt and returns the result of the corresponding hash function
 * applied to the input buffer as outbuf.
 * 
 * @param type The "type" parameter is an enumeration value that specifies the type of hash algorithm
 * to use. It can have one of the following values: HASH_SHA256, HASH_SHA384, HASH_SHA512
 * @param inbuf The `inbuf` parameter is a pointer to the input buffer that contains the data to be
 * hashed. 
 * @param inlen The parameter "inlen" represents the length of the input buffer "inbuf". 
 * @param outbuf The `outbuf` parameter is a pointer to the buffer where the resulting hash value will
 * be stored. The hash value is represented as an array of unsigned characters (bytes).
 * 
 * @return The function `hash` returns an integer value.
 */
int hash_one(enum hash_type type, const unsigned char *inbuf, size_t inlen, unsigned char *outbuf);


void hash_new(hash_t *ctx, enum hash_type type);
int hash(hash_t *ctx, const unsigned char *inbuf, size_t inlen);
void hash_free(hash_t *ctx);


#endif