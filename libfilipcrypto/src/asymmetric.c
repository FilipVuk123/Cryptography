#include "asymmetric.h"

int generate_rsa_key_pair(const char *public_key_filename, const char *private_key_filename, unsigned int key_size)
{
    // Seed the random number generator
    if (RAND_poll() != 1)
    {
        fprintf(stderr, "Error seeding random number generator.\n");
        return 1;
    }

    RSA *keypair = RSA_new();
    BIGNUM *e = BN_new();

    if (!keypair || !e)
    {
        fprintf(stderr, "Error allocating memory for RSA key pair.\n");
        goto cleanup;
    }

    if (BN_set_word(e, RSA_F4) != 1)
    {
        fprintf(stderr, "Error setting public exponent.\n");
        goto cleanup;
    }

    if (RSA_generate_key_ex(keypair, key_size, e, NULL) != 1)
    {
        fprintf(stderr, "Error generating RSA key pair.\n");
        goto cleanup;
    }

    // Save private key
    FILE *private_key_fp = fopen(private_key_filename, "w");
    if (!private_key_fp)
    {
        fprintf(stderr, "Error opening private key file.\n");
        goto cleanup;
    }
    if (PEM_write_RSAPrivateKey(private_key_fp, keypair, NULL, NULL, 0, NULL, NULL) != 1)
    {
        fprintf(stderr, "Error writing private key.\n");
        fclose(private_key_fp);
        goto cleanup;
    }
    fclose(private_key_fp);

    // Save public key
    FILE *public_key_fp = fopen(public_key_filename, "w");
    if (!public_key_fp)
    {
        fprintf(stderr, "Error opening public key file.\n");
        goto cleanup;
    }
    if (PEM_write_RSA_PUBKEY(public_key_fp, keypair) != 1)
    {
        fprintf(stderr, "Error writing public key.\n");
        fclose(public_key_fp);
        goto cleanup;
    }
    fclose(public_key_fp);

    RSA_free(keypair);
    BN_free(e);
    return 0;
cleanup:
    RSA_free(keypair);
    BN_free(e);
    return 1;
}

RSA *get_public_key_from_file(const char *path)
{
    FILE *fp = fopen(path, "r\n");
    if (fp == NULL)
    {
        printf("file error\n");
        return NULL;
    }
    RSA *pkey = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    if (pkey == NULL)
    {
        printf("PEM_read_PUBKEY\n");
        return NULL;
    }
    return pkey;
}

RSA *get_private_key_from_file(const char *path)
{
    FILE *fp = fopen(path, "r\n");
    if (fp == NULL)
    {
        printf("file error\n");
        return NULL;
    }
    RSA *pkey = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (pkey == NULL)
    {
        printf("PEM_read_PrivateKey\n");
        return NULL;
    }

    return pkey;
}

int asymmetric_new(asymmetric_t *ctx, enum asymmetric_action action, const char *path_to_p_key)
{
    ctx->public_key = NULL;
    ctx->private_key = NULL;
    ctx->path_to_private_key = NULL;
    ctx->path_to_public_key = NULL;
    ctx->key_size = 0;
    ctx->action = action;

    if (ctx->action == ASYMMETRIC_ENCRYPT)
    {
        ctx->path_to_public_key = path_to_p_key;
        ctx->public_key = get_public_key_from_file(path_to_p_key);
        if (ctx->public_key == NULL)
        {
            printf("Error in get_public_key_from_file\n");
            return 1;
        }
        ctx->key_size = RSA_size(ctx->public_key);
    }
    else if (ctx->action == ASYMMETRIC_DECRYPT)
    {
        ctx->path_to_private_key = path_to_p_key;
        ctx->private_key = get_private_key_from_file(path_to_p_key);
        if (ctx->private_key == NULL)
        {
            printf("Error in get_private_key_from_file\n");
            return 1;
        }
        ctx->key_size = RSA_size(ctx->private_key);
    }
    else
    {
        printf("Invalid action!\n");
        return 1;
    }

    return 0;
}

int asymmetric_get_max_buffer_size(asymmetric_t *ctx){
    return ctx->key_size;
}

int asymmetric_encrypt_decrypt(asymmetric_t *ctx, unsigned char *input, const int in_size, unsigned char *output, int *out_size)
{
    int outl;
    if (ctx->action == ASYMMETRIC_ENCRYPT)
    {

        outl = RSA_public_encrypt(in_size, (const unsigned char *)input, (unsigned char *)output, ctx->public_key, RSA_PKCS1_PADDING);
        if (outl == -1)
        {
            printf("Error in RSA_public_encrypt\n");
            return 1;
        }
    }
    else
    {
        outl = RSA_private_decrypt(in_size, (const unsigned char *)input, (unsigned char *)output, ctx->private_key, RSA_PKCS1_PADDING);
        if (outl == -1)
        {
            printf("Error in RSA_private_decrypt\n");
            return 1;
        }
    }
    output[outl] = '\0';
    *out_size = outl;

    return 0;
}

void asymmetric_free(asymmetric_t *ctx)
{

    if (ctx->private_key != NULL)
    {
        RSA_free(ctx->private_key);
    }
    if (ctx->public_key != NULL)
    {
        RSA_free(ctx->public_key);
    }
}
