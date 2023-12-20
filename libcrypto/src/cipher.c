#include "cipher.h"

static enum symmetric_type getSymmetricType(enum cipher_type type)
{
    switch (type)
    {
    case CIPHER_AES256_CBC:
        return SYMMETRIC_AES256_CBC;

    case CIPHER_AES256_CTR:
        return SYMMETRIC_AES256_CTR;

    case CIPHER_AES256_GCM:
        return SYMMETRIC_AES256_GCM;

    case CIPHER_AES192_CBC:
        return SYMMETRIC_AES192_CBC;

    case CIPHER_AES192_CTR:
        return SYMMETRIC_AES192_CTR;

    case CIPHER_AES192_GCM:
        return SYMMETRIC_AES192_GCM;

    case CIPHER_AES128_CBC:
        return SYMMETRIC_AES128_CBC;

    case CIPHER_AES128_CTR:
        return SYMMETRIC_AES128_CTR;

    case CIPHER_AES128_GCM:
        return SYMMETRIC_AES128_GCM;

    case CIPHER_3DES_CBC:
        return SYMMETRIC_3DES_CBC;

    case CIPHER_3DES_CFB:
        return SYMMETRIC_3DES_CFB;

    case CIPHER_XOR:
        return SYMMETRIC_XOR;

    default:
        return SYMMETRIC_AES256_CBC;
    }
}

int cipher_encrypt_new(cipher_t *ctx, enum cipher_type type, unsigned char *key, size_t key_len, unsigned char *iv, const char *public_key_path, const int public_key_size)
{
    if (type == CIPHER_RSA)
    {
        ctx->is_symmetric = 0;
        return asymmetric_encrypt_new(&ctx->asym, public_key_path, public_key_size);
    }
    ctx->is_symmetric = 1;
    enum symmetric_type symmetric_type = getSymmetricType(type);
    return symmetric_encrypt_new(&ctx->sym, symmetric_type, key, key_len, iv);
}

int cipher_encrypt_update(cipher_t *ctx, unsigned char *new_key, size_t new_key_len, unsigned char *new_iv)
{
    if (ctx->is_symmetric)
    {
        return symmetric_encrypt_update(&ctx->sym, new_key, new_key_len, new_iv);
    }
    printf("There is nothing to update while using RSA");
    return 1;
}

int cipher_encrypt(cipher_t *ctx, char *input, const int in_size, unsigned char *aad, size_t aad_size)
{
    if (ctx->is_symmetric)
    {
        if (symmetric_encrypt(&ctx->sym, input, in_size, aad, aad_size) > 0)
        {
            return 1;
        }
        ctx->output_buffer = ctx->sym.output_buffer;
        ctx->output_size = ctx->sym.output_size;
        ctx->tag = ctx->sym.tag;
        return 0;
    }
    if (asymmetric_encrypt(&ctx->asym, input, in_size) > 0)
    {
        return 1;
    }
    ctx->output_buffer = ctx->asym.output_buffer;
    ctx->output_size = ctx->asym.output_size;
    return 0;
}

void cipher_encrypt_free(cipher_t *ctx)
{
    if (ctx->is_symmetric)
        symmetric_encrypt_free(&ctx->sym);
    else
        asymmetric_encrypt_free(&ctx->asym);
}

int cipher_decrypt_new(cipher_t *ctx, enum cipher_type type, unsigned char *key, size_t key_len, unsigned char *iv, const char *private_key_path, const int private_key_size)
{
    if (type == CIPHER_RSA)
    {
        ctx->is_symmetric = 0;
        return asymmetric_decrypt_new(&ctx->asym, private_key_path, private_key_size);
    }
    ctx->is_symmetric = 1;
    enum symmetric_type symmetric_type = getSymmetricType(type);
    return symmetric_decrypt_new(&ctx->sym, symmetric_type, key, key_len, iv);
}

int cipher_decrypt_update(cipher_t *ctx, unsigned char *new_key, size_t new_key_len, unsigned char *new_iv)
{
    if (ctx->is_symmetric)
    {
        return symmetric_decrypt_update(&ctx->sym, new_key, new_key_len, new_iv);
    }
    printf("There is nothing to update while using RSA");
    return 1;
}

int cipher_decrypt(cipher_t *ctx, char *input, const int in_size, unsigned char *aad, size_t aad_size, unsigned char *tag)
{
    if (ctx->is_symmetric)
    {
        if (symmetric_decrypt(&ctx->sym, input, in_size, aad, aad_size, tag) > 0)
        {
            return 1;
        }
        ctx->output_buffer = ctx->sym.output_buffer;
        ctx->output_size = ctx->sym.output_size;
        ctx->tag = ctx->sym.tag;
        return 0;
    }
    if (asymmetric_decrypt(&ctx->asym, input, in_size) > 0)
    {
        return 1;
    }
    ctx->output_buffer = ctx->asym.output_buffer;
    ctx->output_size = ctx->asym.output_size;
    return 0;
}

void cipher_decrypt_free(cipher_t *ctx)
{
    if (ctx->is_symmetric)
        symmetric_decrypt_free(&ctx->sym);
    else
        asymmetric_decrypt_free(&ctx->asym);
}
