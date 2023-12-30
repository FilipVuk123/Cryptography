#include "symmetric.h"

static void XORCipher(char *input, unsigned char *key, int dataLen, int keyLen, char *output)
{
    for (int i = 0; i < dataLen; ++i)
    {
        output[i] = input[i] ^ key[i % keyLen];
    }
    output[dataLen] = '\0';
}

static EVP_CIPHER *getCipher(enum symmetric_type type)
{
    EVP_CIPHER *cipher = NULL;
    switch (type)
    {
    case SYMMETRIC_AES256_CBC:
        cipher = (EVP_CIPHER *)EVP_aes_256_cbc();
        break;
    case SYMMETRIC_AES256_CTR:
        cipher = (EVP_CIPHER *)EVP_aes_256_ctr();
        break;
    case SYMMETRIC_AES256_OFB:
        cipher = (EVP_CIPHER *)EVP_aes_256_ofb();
        break;
    case SYMMETRIC_AES128_CBC:
        cipher = (EVP_CIPHER *)EVP_aes_128_cbc();
        break;
    case SYMMETRIC_AES128_CTR:
        cipher = (EVP_CIPHER *)EVP_aes_128_ctr();
        break;
    case SYMMETRIC_AES128_OFB:
        cipher = (EVP_CIPHER *)EVP_aes_128_ofb();
        break;
    case SYMMETRIC_AES192_CBC:
        cipher = (EVP_CIPHER *)EVP_aes_192_cbc();
        break;
    case SYMMETRIC_AES192_CTR:
        cipher = (EVP_CIPHER *)EVP_aes_192_ctr();
        break;
    case SYMMETRIC_AES192_OFB:
        cipher = (EVP_CIPHER *)EVP_aes_192_ofb();
        break;
    case SYMMETRIC_3DES_CBC:
        cipher = (EVP_CIPHER *)EVP_des_ede3_cbc();
        break;
    case SYMMETRIC_3DES_CFB:
        cipher = (EVP_CIPHER *)EVP_des_ede3_cfb();
        break;

    default:
        cipher = (EVP_CIPHER *)EVP_aes_256_cbc();
        break;
    }
    return cipher;
}

int symmetric_new(symmetric_t *ctx, enum symmetric_action action, enum symmetric_type type, unsigned char *key, size_t key_len, unsigned char *iv)
{
    ctx->key = key;
    ctx->type = type;
    ctx->iv = iv;
    ctx->evp = NULL;
    ctx->action = action;
    ctx->key_len = key_len;

    if (type == SYMMETRIC_XOR)
    {
        return 1;
    }

    ctx->cipher = getCipher(type);

    if (!(ctx->evp = EVP_CIPHER_CTX_new()))
    {
        printf("Error: EVP_CIPHER_CTX_new in symmetric_encrypt_new\n");
        return 1;
    }
    if (ctx->action == SYMMETRIC_ENCRYPT)
    {

        if (1 != EVP_EncryptInit(ctx->evp, ctx->cipher, key, iv))
        {
            printf("Error: EVP_EncryptInit in symmetric_encrypt_new\n");
            return 1;
        }
    }
    else if (ctx->action == SYMMETRIC_DECRYPT)
    {
        if (1 != EVP_DecryptInit(ctx->evp, ctx->cipher, key, iv))
        {
            printf("Error: EVP_EncryptInit in symmetric_encrypt_new\n");
            return 1;
        }
    }
    else
    {
        printf("Invalid action!\n");
        return 1;
    }

    return 0;
}

int symmetric_update_keys(symmetric_t *ctx, unsigned char *new_key, size_t new_key_len, unsigned char *new_iv)
{
    if (new_key != NULL)
    {
        ctx->key = new_key;
    }
    if (new_key_len > 0)
    {
        ctx->key_len = new_key_len;
    }
    if (ctx->type == SYMMETRIC_XOR)
    {
        return 0;
    }

    if (new_iv != NULL)
    {
        ctx->iv = new_iv;
    }
    if (ctx->action == SYMMETRIC_ENCRYPT)
    {

        if (1 != EVP_EncryptInit(ctx->evp, ctx->cipher, ctx->key, ctx->iv))
        {
            printf("Error: EVP_EncryptInit EVP_aes_256_cbc\n");
            return 1;
        }
    }
    else
    {
        if (1 != EVP_DecryptInit(ctx->evp, ctx->cipher, ctx->key, ctx->iv))
        {
            printf("Error: EVP_EncryptInit EVP_aes_256_cbc\n");
            return 1;
        }
    }

    return 0;
}

int symmetric_encrypt_decrypt(symmetric_t *ctx, unsigned char *input, const int in_size, unsigned char *output, int *out_size)
{
    if (NULL == output || NULL == out_size){
        printf("Invalid output or out_size arguments!\n");
        return 1;
    }
    if (ctx->type == SYMMETRIC_XOR)
    {
        
        XORCipher((char*) input, ctx->key, in_size, ctx->key_len, (char *)output);
        *out_size = in_size;
        

        return 0;
    }

   
    int total = 0;
    int len;
    int to_ret = 0;
    if (ctx->action == SYMMETRIC_ENCRYPT)
    {

        if (1 != EVP_EncryptUpdate(ctx->evp, output, &len, (const unsigned char *)input, in_size))
        {
            printf("Error: EVP_EncryptUpdate\n");
            to_ret += 1;
        }
        total += len;

        if (1 != EVP_EncryptFinal(ctx->evp, output + total, &len))
        {
            printf("Error: EVP_EncryptFinal\n");
            to_ret += 1;
        }
        total += len;
    }
    else
    {
        if (1 != EVP_DecryptUpdate(ctx->evp, output, &len, (const unsigned char *)input, in_size))
        {
            printf("Error: EVP_EncryptUpdate\n");
            to_ret += 1;
        }
        total += len;

        if (1 != EVP_DecryptFinal(ctx->evp, output + total, &len))
        {
            printf("Error: EVP_EncryptFinal\n");
            to_ret += 1;
        }
        total += len;
    }
    output[total] = '\0';
    *out_size = total;
  

    return to_ret;
}

void symmetric_free(symmetric_t *ctx)
{
    if (ctx->evp != NULL)
    {
        EVP_CIPHER_CTX_free(ctx->evp);
    }
}
