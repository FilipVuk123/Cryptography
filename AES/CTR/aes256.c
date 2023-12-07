#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

int encryptAES256ctr(char *inbuf, int inlen, char *key, char *nonce, char *outbuf, int *outlen)
{
    int len, total = 0;
    int to_ret = 0;
    EVP_CIPHER_CTX *ctx;
    if (!(ctx = EVP_CIPHER_CTX_new())){
        perror("EVP_CIPHER_CTX_new");
        return 1;
    }
    if (1 != EVP_EncryptInit(ctx, EVP_aes_256_ctr(), key, nonce)){
        perror("EVP_EncryptInit EVP_aes_256_ctr");
        to_ret =+ 1;
    }
    if (1 != EVP_EncryptUpdate(ctx, outbuf, &len, inbuf, inlen)){
        perror("EVP_EncryptUpdate");
        to_ret =+ 1;
    }
    total += len;
    if (1 != EVP_EncryptFinal(ctx, outbuf + total, &len)){
        perror("EVP_EncryptFinal");
        to_ret =+ 1;
    }
    total += len;
    EVP_CIPHER_CTX_free(ctx);
    
    outbuf[total] = '\0';

    *outlen = total;

    return to_ret;
}

int decryptAES256ctr(char *inbuf, int inlen, char *key, char *nonce, char *outbuf, int *outlen)
{
    int len, total = 0;
    int to_ret = 0;
    EVP_CIPHER_CTX *ctx;
    if (!(ctx = EVP_CIPHER_CTX_new())){
        perror("EVP_CIPHER_CTX_new");
        return 1;
    }
    if (1 != EVP_DecryptInit(ctx, EVP_aes_256_ctr(), key, nonce)){
        perror("EVP_DecryptInit EVP_aes_256_ctr");
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
    unsigned char nonce[] = "dontusethisinput";

    char message[] = "Message to encrypt!!! Message to encrypt!!! Message to encrypt!!! 123123 321213 Message to encrypt!!! Message to encrypt!!! Message to encrypt!!! ";
    int messageLen = strlen(message);
    printf("%d\n", messageLen);

    char encryptedData[messageLen];
    char decryptedData[messageLen];

    int size;


    int ret = encryptAES256ctr(message, messageLen, ckey, nonce, encryptedData, &size);
    if (ret > 0) 
        perror("encryptAES256ctr");

    printf("%d\n", size);

    for (int i = 0; i < size; i++)
    {
        printf("%#x", encryptedData[i]);
    }

    printf("\n");

    ret = decryptAES256ctr(encryptedData, messageLen, ckey, nonce, decryptedData, &size);
    if (ret > 0) 
        perror("decryptAES256ctr");

    printf("%s\n", decryptedData);

    return 0;
}