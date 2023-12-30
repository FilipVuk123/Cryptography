
#include "hash.h"

static int sha256(const unsigned char *message, size_t message_len, unsigned char *outbuf)
{
    if (SHA256(message, message_len, outbuf) == NULL)
    {
        printf("SHA256\n");
        return 1;
    }
    return 0;
}

static int sha384(const unsigned char *message, size_t message_len, unsigned char *outbuf)
{
    if (SHA384(message, message_len, outbuf) == NULL)
    {
        printf("SHA384\n");
        return 1;
    }
    return 0;
}

static int sha512(const unsigned char *message, size_t message_len, unsigned char *outbuf)
{
    if (SHA512(message, message_len, outbuf) == NULL)
    {
        printf("SHA512\n");
        return 1;
    }
    return 0;
}

int hash_one(enum hash_type type, const unsigned char *inbuf, size_t inlen, unsigned char *outbuf)
{
    switch (type)
    {
    case HASH_SHA256:
        return sha256(inbuf, inlen, outbuf);
        break;

    case HASH_SHA384:
        return sha384(inbuf, inlen, outbuf);
        break;

    case HASH_SHA512:
        return sha512(inbuf, inlen, outbuf);
        break;

    default:
        return sha256(inbuf, inlen, outbuf);
        break;
    }
}

void hash_new(hash_t *ctx, enum hash_type type)
{
    ctx->hash_type = type;
    switch (type)
    {
    case HASH_SHA256:
        ctx->hash_length = 32;
        break;
    case HASH_SHA384:
        ctx->hash_length = 48;
        break;
    case HASH_SHA512:
        ctx->hash_length = 64;
        break;
    default:
        ctx->hash_length = 32;
        break;
    }
    ctx->hash_buffer = malloc(ctx->hash_length);
}

int hash(hash_t *ctx, const unsigned char *inbuf, size_t inlen)
{
    return hash_one(ctx->hash_type, inbuf, inlen, (unsigned char*) ctx->hash_buffer);
}

void hash_free(hash_t *ctx)
{
    if (ctx->hash_buffer != NULL){
        free(ctx->hash_buffer);
    }
}
