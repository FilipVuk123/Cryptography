#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

int encryptAES256cbc(char *inbuf, int inlen, char *key, char *iv, char *outbuf, int *outlen)
{
    int len, total = 0;
    int to_ret = 0;
    EVP_CIPHER_CTX *ctx;
    if(!(ctx = EVP_CIPHER_CTX_new())){
        perror("EVP_CIPHER_CTX_new");
        return 1;
    }
    if (1 != EVP_EncryptInit(ctx, EVP_aes_256_cbc(), key, iv)){
        perror("EVP_EncryptInit EVP_aes_256_cbc");
        to_ret += 1;
    }
    if (1 != EVP_EncryptUpdate(ctx, outbuf, &len, inbuf, inlen)){
        perror("EVP_EncryptUpdate");
        to_ret += 1;
    }

    total += len;

    if (1 != EVP_EncryptFinal(ctx, outbuf + total, &len)){
        perror("EVP_EncryptFinal");
        to_ret += 1;
    }

    total += len;

    EVP_CIPHER_CTX_free(ctx);
    outbuf[total] = '\0';

    *outlen = total;

    return to_ret;
}

int decryptAES256cbc(char *inbuf, int inlen, char *key, char *iv, char *outbuf, int *outlen)
{
    int len, total = 0;
    int to_ret = 0;
    EVP_CIPHER_CTX *ctx;
    if(!(ctx = EVP_CIPHER_CTX_new())){
        perror("EVP_CIPHER_CTX_new");
        return 1;
    }
    if (1 != EVP_DecryptInit(ctx, EVP_aes_256_cbc(), key, iv)){
        perror("EVP_DecryptInit EVP_aes_256_cbc");
        to_ret += 1;
    }
    if (1 != EVP_DecryptUpdate(ctx, outbuf, &len, inbuf, inlen)){
        perror("EVP_DecryptUpdate");
        to_ret += 1;
    }

    total += len;

    if (1 != EVP_DecryptFinal(ctx, outbuf + total, &len)){
        perror("EVP_DecryptFinal");
        to_ret += 1;
    }

    total += len;

    EVP_CIPHER_CTX_free(ctx);
    outbuf[total] = '\0';

    *outlen = total;

    return to_ret;
}

int main()
{

    unsigned char ckey[] = "thiskeyisverybadthiskeyisverybad";
    unsigned char ivec[] = "dontusethisinput";

    char message[] = "Message to encrypt!!! Message to encrypt!!! Message to encrypt!!! 123123 321213 Message to encrypt!!! Message to encrypt!!! Message to encrypt!!! ";
    int messageLen = strlen(message);
    printf("%d\n", messageLen);

    char encryptedData[messageLen + AES_BLOCK_SIZE];
    char decryptedData[messageLen];

    int size;

    int ret = encryptAES256cbc(message, messageLen, ckey, ivec, encryptedData, &size);
    if(ret > 0)
        perror("encryptAES256cbc");

    for (int i = 0; i < size; i++)
    {
        printf("%#x", encryptedData[i]);
    }

    printf("\n");

    decryptAES256cbc(encryptedData, size, ckey, ivec, decryptedData, &size);
    if(ret > 0)
        perror("decryptAES256cbc");

    printf("%s\n", decryptedData);

    return 0;
}