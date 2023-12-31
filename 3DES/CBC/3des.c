#include <stdint.h>
#include <string.h>
#include <openssl/des.h>
#include <openssl/evp.h>

int encrypt3DesCbc(char *inbuf, int inlen, char *key, char *iv, char *outbuf, int *outlen)
{
    int len = 0;
    int total_len = 0;
    int to_ret = 0;

    EVP_CIPHER_CTX *ctx;
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        printf("Error: EVP_CIPHER_CTX_new\n");
        return 1;
    }
    if (1 != EVP_EncryptInit(ctx, EVP_des_ede3_cbc(), key, iv))
    {
        printf("Error: EVP_EncryptInit EVP_des_ede3_cbc\n");
        to_ret += 1;
    }

    if (1 != EVP_EncryptUpdate(ctx, outbuf, &len, inbuf, inlen))
    {
        printf("Error: EVP_EncryptUpdate\n");
        to_ret += 1;
    }
    total_len += len;
    printf("Total: %d\n", total_len);
    if (1 != EVP_EncryptFinal(ctx, outbuf + total_len, &len))
    {
        printf("Error: EVP_EncryptFinal\n");
        to_ret += 1;
    }
    EVP_CIPHER_CTX_free(ctx);

    total_len += len;
    printf("Total: %d\n", total_len);
    *outlen = total_len;

    outbuf[total_len] = '\0';

    return to_ret;
}

int decrypt3DesCbc(char *inbuf, int inlen, char *key, char *iv, char *outbuf, int *outlen)
{
    int len = 0;
    int total_len = 0;
    int to_ret = 0;

    EVP_CIPHER_CTX *ctx;
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        printf("Error: EVP_CIPHER_CTX_new\n");
        return 1;
    }

    if (1 != EVP_DecryptInit(ctx, EVP_des_ede3_cbc(), key, iv))
    {
        printf("Error: EVP_DecryptInit EVP_des_ede3_cbc\n");
        to_ret += 1;
    }

    if (1 != EVP_DecryptUpdate(ctx, outbuf, &len, inbuf, inlen))
    {
        printf("Error: EVP_DecryptUpdate\n");
        to_ret += 1;
    }
    total_len += len;

    if (1 != EVP_DecryptFinal(ctx, outbuf + total_len, &len))
    {
        printf("Error: EVP_DecryptFinal\n");
        to_ret += 1;
    }
    EVP_CIPHER_CTX_free(ctx);

    total_len += len;

    *outlen = total_len;

    outbuf[total_len] = '\0';

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

    int ret = encrypt3DesCbc(message, messageLen, key, iv, ciphertext, &ciphertext_total);
    if (ret > 0)
        printf("encrypt3DesCbc\n");

    printf("Cipher total %d\n", ciphertext_total);
    printf("Ciphertext:          \n");
    {
        int i;
        for (i = 0; i < ciphertext_total; i++)
        {
            printf("%02X ", ciphertext[i]);
        }
        printf("\n");
    }

    ret = decrypt3DesCbc(ciphertext, ciphertext_total, key, iv, decrypted, &decrypted_total);
    if (ret > 0)
        printf("decrypt3DesCbc\n");

    printf("Decrypted total %d\n", decrypted_total);

    printf("Decrypted:           \n");
    printf("%s\n", decrypted);
}