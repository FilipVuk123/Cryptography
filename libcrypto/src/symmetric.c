#include "symmetric.h"

static void XORCipher(char *input, unsigned char *key, int dataLen, int keyLen, char* output)
{
    for (int i = 0; i < dataLen; ++i)
    {
        output[i] = input[i] ^ key[i % keyLen];
    }
    output[dataLen] = '\0';
}

static EVP_CIPHER * getCipher(enum symmetric_type type){
    EVP_CIPHER * cipher = NULL;
    switch (type)
    {
    case SYMMETRIC_AES256_CBC:
        cipher = (EVP_CIPHER*) EVP_aes_256_cbc();
        break;
    case SYMMETRIC_AES256_CTR:
        cipher = (EVP_CIPHER*) EVP_aes_256_ctr();
        break;
    case SYMMETRIC_AES256_GCM:
        cipher = (EVP_CIPHER*) EVP_aes_256_gcm();
        break;
    case SYMMETRIC_AES128_CBC:
        cipher = (EVP_CIPHER*) EVP_aes_128_cbc();
        break;
    case SYMMETRIC_AES128_CTR:
        cipher = (EVP_CIPHER*) EVP_aes_128_ctr();
        break;
    case SYMMETRIC_AES128_GCM:
        cipher = (EVP_CIPHER*) EVP_aes_128_gcm();
        break;
    case SYMMETRIC_AES192_CBC:
        cipher = (EVP_CIPHER*) EVP_aes_192_cbc();
        break;
    case SYMMETRIC_AES192_CTR:
        cipher = (EVP_CIPHER*) EVP_aes_192_ctr();
        break;
    case SYMMETRIC_AES192_GCM:
        cipher = (EVP_CIPHER*) EVP_aes_192_gcm();
        break;
    case SYMMETRIC_3DES_CBC:
        cipher = (EVP_CIPHER*) EVP_des_ede3_cbc();
        break;
    case SYMMETRIC_3DES_CFB:
        cipher = (EVP_CIPHER*) EVP_des_ede3_cfb();
        break;

    default:
        cipher = (EVP_CIPHER*) EVP_aes_256_cbc();
        break;
    }
    return cipher;
}


int symmetric_encrypt_new(symmetric_t *ctx, enum symmetric_type type, unsigned char *key, size_t key_len, unsigned char *iv)
{
    ctx->key = key;
    ctx->type = type;
    ctx->iv = iv;
    ctx->evp = NULL;
    ctx->tag = NULL;
    ctx->output_buffer = NULL;
    ctx->output_size = 0;
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

    if (1 != EVP_EncryptInit(ctx->evp, ctx->cipher, key, iv))
    {
        printf("Error: EVP_EncryptInit in symmetric_encrypt_new\n");
        return 1;
    }
    
    return 0;
}

int symmetric_encrypt_update(symmetric_t *ctx, unsigned char *new_key, size_t new_key_len, unsigned char *new_iv)
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

    if (1 != EVP_EncryptInit(ctx->evp, ctx->cipher, ctx->key, ctx->iv))
    {
        printf("Error: EVP_EncryptInit EVP_aes_256_cbc\n");
        return 1;
    }

    return 0;
}

int symmetric_encrypt(symmetric_t *ctx, char *input, const int in_size, unsigned char *aad, size_t aad_size)
{
    if (ctx->type == SYMMETRIC_XOR)
    {
        ctx->output_buffer = realloc(ctx->output_buffer, in_size);
        XORCipher(input, ctx->key, in_size, ctx->key_len, (char *) ctx->output_buffer);
        ctx->output_size = in_size;

        return 0;
    }
    ctx->aad = aad;
    size_t cipher_block_size = 0;
    switch (ctx->type)
    {
    case SYMMETRIC_3DES_CBC:
        cipher_block_size = 8;
        break;

    case SYMMETRIC_AES128_CBC:
    case SYMMETRIC_AES256_CBC:
    case SYMMETRIC_AES192_CBC:
        cipher_block_size = 16;
        break;

    default:
        break;
    }

    if (ctx->type == SYMMETRIC_AES128_GCM || ctx->type == SYMMETRIC_AES192_GCM || ctx->type == SYMMETRIC_AES256_GCM)
    {
        int len;
        if (1 != EVP_EncryptUpdate(ctx->evp, NULL, &len, (const unsigned char*)ctx->aad, aad_size))
        {
            printf("Error: EVP_EncryptUpdate aad in symmetric_encrypt_new\n");
            return 1;
        }
    }

    ctx->output_buffer = realloc(ctx->output_buffer, in_size + cipher_block_size);
    memset(ctx->output_buffer, 0, in_size + cipher_block_size);

    int total = 0;
    int len;
    int to_ret = 0;
    if (1 != EVP_EncryptUpdate(ctx->evp, ctx->output_buffer, &len, (const unsigned char*)input, in_size))
    {
        printf("Error: EVP_EncryptUpdate\n");
        to_ret += 1;
    }
    total += len;

    if (1 != EVP_EncryptFinal(ctx->evp, ctx->output_buffer + total, &len))
    {
        printf("Error: EVP_EncryptFinal\n");
        to_ret += 1;
    }
    total += len;

    ctx->output_buffer[total] = '\0';
    ctx->output_size = total;
    if (ctx->type == SYMMETRIC_AES128_GCM || ctx->type == SYMMETRIC_AES192_GCM || ctx->type == SYMMETRIC_AES256_GCM)
    {
        
        ctx->tag = realloc(ctx->tag, 16);
        if (1 != EVP_CIPHER_CTX_ctrl(ctx->evp, EVP_CTRL_GCM_GET_TAG, 16, ctx->tag))
        {
            printf("Error: EVP_CIPHER_CTX_ctrl\n");
            to_ret += 1;
        }
    }

    return to_ret;
}

void symmetric_encrypt_free(symmetric_t *ctx)
{
    if (ctx->output_buffer != NULL)
    {
        free(ctx->output_buffer);
    }
    if (ctx->tag != NULL)
    {
        free(ctx->tag);
    }
    if (ctx->evp != NULL)
    {
        EVP_CIPHER_CTX_free(ctx->evp);
    }
}


int symmetric_decrypt_new(symmetric_t *ctx, enum symmetric_type type, unsigned char *key, size_t key_len, unsigned char *iv){
    ctx->key = key;
    ctx->type = type;
    ctx->iv = iv;
    ctx->evp = NULL;
    ctx->tag = NULL;
    ctx->output_buffer = NULL;
    ctx->output_size = 0;
    ctx->key_len = key_len;

    if (type == SYMMETRIC_XOR)
    {
        return 1;
    }

    ctx->cipher = getCipher(type);

    if (!(ctx->evp = EVP_CIPHER_CTX_new()))
    {
        printf("Error: EVP_CIPHER_CTX_new in symmetric_decrypt_new\n");
        return 1;
    }

    if (1 != EVP_DecryptInit(ctx->evp, ctx->cipher, key, iv))
    {
        printf("Error: EVP_EncryptInit in symmetric_decrypt_new\n");
        return 1;
    }

    return 0;
}

int symmetric_decrypt_update(symmetric_t *ctx, unsigned char *new_key, size_t new_key_len, unsigned char *new_iv){
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

    if (1 != EVP_DecryptInit(ctx->evp, ctx->cipher, ctx->key, ctx->iv))
    {
        printf("Error: EVP_EncryptInit EVP_aes_256_cbc\n");
        return 1;
    }

    return 0;
}

int symmetric_decrypt(symmetric_t* ctx, char* input, const int in_size, unsigned char *aad, size_t aad_size, unsigned char *tag){
    if (ctx->type == SYMMETRIC_XOR)
    {
        ctx->output_size = in_size;
        ctx->output_buffer = realloc(ctx->output_buffer, ctx->output_size);
        XORCipher(input, ctx->key, in_size, ctx->key_len, (char *) ctx->output_buffer);

        return 0;
    }

    ctx->tag = tag;
    ctx->aad = aad;
    

    if (ctx->type == SYMMETRIC_AES128_GCM || ctx->type == SYMMETRIC_AES192_GCM || ctx->type == SYMMETRIC_AES256_GCM)
    {
        int len;
        if (1 != EVP_DecryptUpdate(ctx->evp, NULL, &len, (const unsigned char*)ctx->aad, aad_size))
        {
            printf("Error: EVP_EncryptUpdate aad in symmetric_decrypt_new\n");
            return 1;
        }
    }

    ctx->output_buffer = realloc(ctx->output_buffer, in_size);
    memset(ctx->output_buffer, 0, in_size);
    int total = 0;
    int len;
    int to_ret = 0;
    if (1 != EVP_DecryptUpdate(ctx->evp, ctx->output_buffer, &len, (const unsigned char*)input, in_size))
    {
        printf("Error: EVP_EncryptUpdate\n");
        to_ret += 1;
    }
    total += len;

    if (ctx->type == SYMMETRIC_AES128_GCM || ctx->type == SYMMETRIC_AES192_GCM || ctx->type == SYMMETRIC_AES256_GCM)
    {
        
        if (1 != EVP_CIPHER_CTX_ctrl(ctx->evp, EVP_CTRL_GCM_SET_TAG, 16, tag))
        {
            printf("Error: EVP_CIPHER_CTX_ctrl\n");
            to_ret += 1;
        }
    }


    if (1 != EVP_DecryptFinal(ctx->evp, ctx->output_buffer + total, &len))
    {
        printf("Error: EVP_DecryptFinal\n");
        to_ret += 1;
    }
    total += len;
    ctx->output_buffer[total] = '\0';
    ctx->output_size = total;

    return to_ret;
}

void symmetric_decrypt_free(symmetric_t* ctx){
     if (ctx->output_buffer != NULL)
    {
        free(ctx->output_buffer);
    }
    if (ctx->evp != NULL)
    {
        EVP_CIPHER_CTX_free(ctx->evp);
    }
}


void printEncryptedHex(unsigned char* buffer, size_t size){
    for (size_t i = 0; i < size; i++)
    {
        printf("%02X ", buffer[i]);
    }
    printf("\n");
}