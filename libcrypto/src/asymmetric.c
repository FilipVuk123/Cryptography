#include "asymmetric.h"

static int MaxRsaBufSize(const int key_size_in_bits)
{
    return key_size_in_bits / 8 - RSA_PKCS1_PADDING_SIZE;
}


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

RSA* get_public_key_from_file(const char *path){
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

RSA* get_private_key_from_file(const char *path){
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

int asymmetric_encrypt_new(asymmetric_t* ctx, const char* path_to_public_key, size_t key_size){
    ctx->output_buffer = NULL;
    ctx->public_key = NULL;
    ctx->private_key = NULL;
    ctx->path_to_private_key = NULL;
    ctx->path_to_public_key = NULL;
    ctx->path_to_public_key = path_to_public_key;
    ctx->key_size = key_size;
    ctx->output_size = 0;
    ctx->public_key = get_public_key_from_file(path_to_public_key);
    if(ctx->public_key == NULL){
        printf("Error in get_public_key_from_file\n");
        return 1;
    }
    ctx->output_buffer = realloc(ctx->output_buffer, key_size / 8);
    return 0;
}

int asymmetric_encrypt(asymmetric_t* ctx, char* input, const int in_size){
    int outl;
    
    outl = RSA_public_encrypt(in_size, (const unsigned char*)input, (unsigned char *) ctx->output_buffer, ctx->public_key, RSA_PKCS1_PADDING);
    if (outl == -1) {
        printf("Error in RSA_public_encrypt\n");
        return 1;
    }
    ctx->output_buffer[outl] = '\0';
    ctx->output_size = outl;

    return 0;
}


int asymmetric_decrypt_new(asymmetric_t* ctx, const char* path_to_private_key, size_t key_size){
    ctx->output_buffer = NULL;
    ctx->public_key = NULL;
    ctx->private_key = NULL;
    ctx->path_to_private_key = NULL;
    ctx->path_to_public_key = NULL;
    ctx->key_size = key_size;
    ctx->path_to_private_key = path_to_private_key;
    ctx->output_size = 0;
    ctx->private_key = get_private_key_from_file(path_to_private_key);
    if(ctx->private_key == NULL){
        printf("Error in get_private_key_from_file\n");
        return 1;
    }
    ctx->output_buffer = realloc(ctx->output_buffer, key_size / 8);
    return 0;
}

int asymmetric_decrypt(asymmetric_t* ctx, char* input, const int in_size){
    int outl;
    outl = RSA_private_decrypt(in_size, (const unsigned char* )input, (unsigned char* )ctx->output_buffer, ctx->private_key, RSA_PKCS1_PADDING);
    if (outl == -1) {
        printf("Error in RSA_private_decrypt\n");
        return 1;
    }
    
    ctx->output_buffer[outl] = '\0';
    ctx->output_size = outl;
    return 0;
}

void asymmetric_free(asymmetric_t* ctx){
    if(ctx->output_buffer != NULL){
        free(ctx->output_buffer);
    }
    if(ctx->private_key != NULL){
        RSA_free(ctx->private_key);
    }
    if(ctx->public_key != NULL){
        RSA_free(ctx->public_key);
    }
}



