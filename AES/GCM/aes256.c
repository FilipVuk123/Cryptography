#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

int encryptAES256gcm(char *bufferToEncrypt, int bufferSize, char *aad, int aadSize, char *encryptedBuffer, char *key, char *iv)
{
    int outLen1 = 0;
    int outLen2 = 0;
    int outLen3 = 0;

    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();

    // Set up encryption with AAD
    EVP_EncryptInit(ctx, EVP_aes_256_gcm(), key, iv);
    EVP_EncryptUpdate(ctx, NULL, &outLen1, aad, aadSize); // AAD
    EVP_EncryptUpdate(ctx, encryptedBuffer, &outLen2, bufferToEncrypt, bufferSize);
    EVP_EncryptFinal(ctx, encryptedBuffer + outLen2, &outLen3);

    EVP_CIPHER_CTX_free(ctx);

    encryptedBuffer[outLen1 + outLen2 + outLen3] = '\0';

    return outLen1 + outLen2 + outLen3;
}

int decryptAES256gcm(char *bufferToDecrypt, int bufferSize, char *aad, int aadSize, char *decryptedBuffer, char *key, char *iv)
{
    int outLen1 = 0;
    int outLen2 = 0;
    int outLen3 = 0;

    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();

    // Setup decryption with AAD
    EVP_DecryptInit(ctx, EVP_aes_256_gcm(), key, iv);
    EVP_DecryptUpdate(ctx, NULL, &outLen1, aad, aadSize); // AAD
    EVP_DecryptUpdate(ctx, decryptedBuffer, &outLen2, bufferToDecrypt, bufferSize);
    EVP_DecryptFinal(ctx, decryptedBuffer + outLen2, &outLen3);

    EVP_CIPHER_CTX_free(ctx);

    decryptedBuffer[outLen1 + outLen2 + outLen3] = '\0';

    return outLen1 + outLen2 + outLen3;
}

int main()
{
    unsigned char ckey[] = "thiskeyisverybadthiskeyisverybad";
    unsigned char ivec[] = "dontusethisinput";

    char message[] = "Message to encrypt!!! Message to encrypt!!! Message to encrypt!!! 123123 321213 Message to encrypt!!! Message to encrypt!!! Message to encr ";
    int messageLen = strlen(message);

    char aad[] = "Additional Authenticated Data";
    int aadSize = strlen(aad);

    printf("%d\n", messageLen);

    char encryptedData[messageLen];
    char decryptedData[messageLen];

    encryptAES256gcm(message, messageLen, aad, aadSize, encryptedData, ckey, ivec);

    for (int i = 0; i < messageLen; i++)
    {
        printf("%02x", encryptedData[i]);
    }

    printf("\n");

    decryptAES256gcm(encryptedData, messageLen, aad, aadSize, decryptedData, ckey, ivec);

    printf("%s\n", decryptedData);

    return 0;
}
