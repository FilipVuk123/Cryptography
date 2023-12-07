#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

int encryptAES256gcm(char *inbuf, int inlen, char* aad, int addlen, char *key, char *iv, char *outbuf, int *outlen, char* outtag)
{
    int len, total = 0;
    int to_ret = 0;
    EVP_CIPHER_CTX *ctx;
    if (!( ctx = EVP_CIPHER_CTX_new())){
        perror("EVP_CIPHER_CTX_new");
        return 1;
    }

    if ( 1 != EVP_EncryptInit(ctx, EVP_aes_256_gcm(), key, iv)){
        perror("EVP_EncryptInit EVP_aes_256_gcm");
        to_ret += 1;
    }
    if ( 1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, addlen)){
        perror("EVP_EncryptUpdate aad");
        to_ret += 1;
    }
    if ( 1 != EVP_EncryptUpdate(ctx, outbuf, &len, inbuf, inlen)){
        perror("EVP_EncryptUpdate");
        to_ret += 1;
    }
    total+=len;
    if ( 1 != EVP_EncryptFinal(ctx, outbuf + total, &len)){
        perror("EVP_EncryptFinal");
        to_ret += 1;
    }
    total+=len;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, outtag)){
        perror("EVP_CIPHER_CTX_ctrl");
        to_ret += 1;
    }
    EVP_CIPHER_CTX_free(ctx);

    outbuf[total] = '\0';

    *outlen = total;

    return to_ret;
}

int decryptAES256gcm(char *inbuf, int inlen, char* aad, int addlen, char *key, char *iv, char *outbuf, int *outlen, char* intag)
{
    int len, total = 0;
    int to_ret = 0;
    EVP_CIPHER_CTX *ctx;
    if (!(ctx = EVP_CIPHER_CTX_new())){
        perror("EVP_CIPHER_CTX_new");
        return 1;
    }

    if( 1 != EVP_DecryptInit(ctx, EVP_aes_256_gcm(), key, iv)){
        perror("EVP_DecryptInit EVP_aes_256_gcm");
        to_ret += 1;
    }
    if( 1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, addlen)){
        perror("EVP_DecryptUpdate aad");
        to_ret += 1;
    }
    if( 1 != EVP_DecryptUpdate(ctx, outbuf, &len, inbuf, inlen)){
        perror("EVP_DecryptUpdate");
        to_ret += 1;
    }
    total += len;
    if( 1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, intag)){
        perror("EVP_CIPHER_CTX_ctrl tag");
        to_ret += 1;
    }
    if( 1 != EVP_DecryptFinal(ctx, outbuf + total, &len)){
        perror("EVP_DecryptFinal");
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
    unsigned char ckey[] = "thiskeyisverybadthiskeyisverybad";
    unsigned char ivec[] = "dontusethisinput";

    char message[] = "Message to encrypt!!! Message to encrypt!!! Message to encrypt!!! 123123 321213 Message to encrypt!!! Message to encrypt!!! Message to encr ";
    int messageLen = strlen(message);

    printf("%s\n", message);

    char aad[] = "456654";
    int aadSize = strlen(aad);

    char tag[16];

    char encryptedData[messageLen];
    char decryptedData[messageLen];

    int size;

    int ret = encryptAES256gcm(message, messageLen, aad, aadSize, ckey, ivec, encryptedData, &size, tag);
    if(ret > 0)
        perror("encryptAES256gcm");

    printf("Encrypted data: \t");
    for (int i = 0; i < size; i++)
    {
        printf("%#x", encryptedData[i]);
    }


    printf("\n");
    printf("Tag: \t");
    for (int i = 0; i < 16; i++)
    {
        printf("%#x", tag[i]);
    }

    printf("\n");
    ret = decryptAES256gcm(encryptedData, messageLen, aad, aadSize, ckey, ivec, decryptedData, &size, tag);
    if(ret > 0)
        perror("decryptAES256gcm");

    printf("%s\n", decryptedData);


    printf("Tag: \t");
    for (int i = 0; i < 16; i++)
    {
        printf("%#x", tag[i]);
    }

    printf("\n");

    return 0;
}
