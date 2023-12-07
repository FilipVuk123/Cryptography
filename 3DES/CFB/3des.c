#include <stdint.h>
#include <string.h>
#include <openssl/des.h>
#include <openssl/evp.h>

int encrypt3DesCfb(char *inbuf, int inlen, char *key, char *iv, char *outbuf, int *outlen)
{
    int outl = 0;
    int ciphertext_total = 0;
    int to_ret = 0;

    EVP_CIPHER_CTX *ctx;
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        printf("Error: EVP_CIPHER_CTX_new\n");
        return 1;
    }

    if (1 != EVP_EncryptInit(ctx, EVP_des_ede3_cfb(), key, iv))
    {
        printf("Error: EVP_EncryptInit EVP_des_ede3_cfb\n");
        to_ret += 1;
    }

    if (1 != EVP_EncryptUpdate(ctx, outbuf, &outl, inbuf, inlen))
    {
        printf("Error: EVP_EncryptUpdate\n");
        to_ret += 1;
    }
    ciphertext_total += outl;

    if (1 != EVP_EncryptFinal(ctx, outbuf + ciphertext_total, &outl))
    {
        printf("Error: EVP_EncryptFinal\n");
        to_ret += 1;
    }
    ciphertext_total += outl;

    outbuf[ciphertext_total] = '\0';

    *outlen = ciphertext_total;

    return to_ret;
}

int decrypt3DesCfb(char *inbuf, int inlen, char *key, char *iv, char *outbuf, int *outlen)
{
    int outl = 0;
    int decrypted_total = 0;
    int to_ret = 0;

    EVP_CIPHER_CTX *ctx;
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        printf("Error: EVP_CIPHER_CTX_new\n");
        return 1;
    }
    if (1 != EVP_DecryptInit(ctx, EVP_des_ede3_cfb(), key, iv))
    {
        printf("Error: EVP_DecryptInit EVP_des_ede3_cfb\n");
        to_ret += 1;
    }

    if (1 != EVP_DecryptUpdate(ctx, outbuf, &outl, inbuf, inlen))
    {
        printf("Error: EVP_DecryptUpdate\n");
        to_ret += 1;
    }
    decrypted_total += outl;

    if (1 != EVP_DecryptFinal(ctx, outbuf + decrypted_total, &outl))
    {
        printf("Error: EVP_DecryptFinal\n");
        to_ret += 1;
    }
    decrypted_total += outl;

    outbuf[decrypted_total] = '\0';

    *outlen = decrypted_total;

    return to_ret;
}

int main(int argc, char *argv[])
{
    char key[] = "112233445566778821324354";

    char iv[] = "12345678";

    char message[] = "Test Test Test 123 321 aaa bbb xcsadd 12345";

    int messageLen = strlen(message);
    char ciphertext[messageLen + 8];
    char decrypted[messageLen];

    printf("Key = %s\n", key);

    printf("Iv = %s\n", iv);

    printf("Message = %s\n", message);

    int ciphertext_total, decrypted_total;
    int ret = encrypt3DesCfb(message, messageLen, key, iv, ciphertext, &ciphertext_total);
    if (ret > 0)
        printf("encrypt3DesCfb\n");

    printf("Cipher total %d\n", ciphertext_total);
    printf("Ciphertext:          \n");
    {
        int i;
        for (i = 0; i < ciphertext_total; i++)
        {
            printf("%#x ", ciphertext[i]);
        }
        printf("\n\n");
    }

    ret = decrypt3DesCfb(ciphertext, ciphertext_total, key, iv, decrypted, &decrypted_total);
    if (ret > 0)
        printf("decrypt3DesCfb\n");

    decrypted[messageLen] = '\0';

    printf("Decrypted total %d\n", ciphertext_total);

    printf("Decrypted:           \n");
    printf("%s\n", decrypted);
}