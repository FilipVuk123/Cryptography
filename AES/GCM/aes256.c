#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>


int encryptAES256gcm(char *inbuf, int inlen, char *aad, int addlen, char *key, char *iv, char *outbuf, int *outlen, char *outtag)
{
    int len, total = 0;
    int to_ret = 0;
    EVP_CIPHER_CTX *ctx;
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        printf("Error: EVP_CIPHER_CTX_new\n");
        return 1;
    }

    if (1 != EVP_EncryptInit(ctx, EVP_aes_256_gcm(), key, iv))
    {
        printf("Error: EVP_EncryptInit EVP_aes_256_gcm\n");
        to_ret += 1;
    }
    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, addlen))
    {
        printf("Error: EVP_EncryptUpdate aad\n");
        to_ret += 1;
    }
    if (1 != EVP_EncryptUpdate(ctx, outbuf, &len, inbuf, inlen))
    {
        printf("Error: EVP_EncryptUpdate\n");
        to_ret += 1;
    }
    total += len;
    printf("Total: %d\n", total);
    if (1 != EVP_EncryptFinal(ctx, outbuf + total, &len))
    {
        printf("Error: EVP_EncryptFinal\n");
        to_ret += 1;
    }
    total += len;
    printf("Total: %d\n", total);
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, outtag))
    {
        printf("Error: EVP_CIPHER_CTX_ctrl\n");
        to_ret += 1;
    }
    EVP_CIPHER_CTX_free(ctx);

    outbuf[total] = '\0';

    *outlen = total;

    return to_ret;
}

int decryptAES256gcm(char *inbuf, int inlen, char *aad, int addlen, char *key, char *iv, char *outbuf, int *outlen, char *intag)
{
    int len, total = 0;
    int to_ret = 0;
    EVP_CIPHER_CTX *ctx;
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        printf("Error: EVP_CIPHER_CTX_new\n");

        return 1;
    }

    if (1 != EVP_DecryptInit(ctx, EVP_aes_256_gcm(), key, iv))
    {
        printf("Error: EVP_DecryptInit EVP_aes_256_gcm\n");

        to_ret += 1;
    }
    if (1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, addlen))
    {
        printf("Error: EVP_DecryptUpdate aad\n");

        to_ret += 1;
    }
    if (1 != EVP_DecryptUpdate(ctx, outbuf, &len, inbuf, inlen))
    {
        printf("Error: EVP_DecryptUpdate\n");
        to_ret += 1;
    }
    total += len;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, intag))
    {
        printf("Error: EVP_CIPHER_CTX_ctrl tag\n");
        to_ret += 1;
    }
    if (1 != EVP_DecryptFinal(ctx, outbuf + total, &len))
    {
        printf("Error: EVP_DecryptFinal\n");
        to_ret += 1;
    }
    total += len;
    EVP_CIPHER_CTX_free(ctx);

    *outlen = total;

    outbuf[total] = '\0';
    return to_ret;
}

int main()
{
    
    unsigned char ckey[] = "ThisisverybadkeyThisisverybadkey";
    unsigned char ivec[] = "Thisisverybadkey";

    char message[] = "Testing text to encrypt and decrypt!";
    int messageLen = strlen(message);

    printf("%s\n", message);

    char aad[] = "Additional Auth Data";
    int aadSize = strlen(aad);

    char tag[16];

    char encryptedData[messageLen];
    char decryptedData[messageLen];

    int size;

    int ret = encryptAES256gcm(message, messageLen, aad, aadSize, ckey, ivec, encryptedData, &size, tag);
    if (ret > 0)
        printf("encryptAES256gcm\n");

    printf("Encrypted data: \t\n");
    for (int i = 0; i < size; i++)
    {
        printf("%02X ", encryptedData[i]);
    }
    
    printf("\n");
    printf("Tag: \t\n");
    for (int i = 0; i < 16; i++)
    {
        printf("%02X ", tag[i]);
    }

    printf("\n");
    ret = decryptAES256gcm(encryptedData, messageLen, aad, aadSize, ckey, ivec, decryptedData, &size, tag);
    if (ret > 0)
        printf("decryptAES256gcm\n");

    printf("%s\n", decryptedData);

    printf("Tag: \t\n");
    for (int i = 0; i < 16; i++)
    {
        printf("%02X ", tag[i]);
    }

    printf("\n");
    
    return 0;
}
