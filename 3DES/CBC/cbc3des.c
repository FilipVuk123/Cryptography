#include <stdint.h>
#include <string.h>
#include <openssl/des.h>
#include <openssl/evp.h>

int encrypt3DesCbc(char *input, int input_size, char *key, char *iv, char *output)
{
        int outl = 0; 
        int ciphertext_total = 0;
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit(ctx, EVP_des_ede3_cbc(), key, iv);

        EVP_EncryptUpdate(ctx, output, &outl, input, input_size);
        ciphertext_total += outl;

        EVP_EncryptFinal(ctx, output + ciphertext_total, &outl);
        ciphertext_total += outl;

        return ciphertext_total;
}

int decrypt3DesCbc(char *input, int input_size, char *key, char *iv, char *output)
{
        int outl = 0;
        int decrypted_total = 0;
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit(ctx, EVP_des_ede3_cbc(), key, iv);

        EVP_DecryptUpdate(ctx, output, &outl, input, input_size);
        decrypted_total += outl;

        EVP_DecryptFinal(ctx, output + decrypted_total, &outl);
        decrypted_total += outl;

        return decrypted_total;
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

        int ciphertext_total = encrypt3DesCbc(message, messageLen, key, iv, ciphertext);

        printf("Cipher total %d\n", ciphertext_total);
        printf("Ciphertext:          ");
        {
                int i;
                for (i = 0; i < ciphertext_total; i++)
                {
                        printf("%02x ", ciphertext[i]);
                }
                printf("\n");
        }

        decrypt3DesCbc(ciphertext, ciphertext_total, key, iv, decrypted);

        decrypted[messageLen] = '\0';

        printf("Decrypted total %d\n", ciphertext_total);

        printf("Decrypted:           ");
        printf("%s\n", decrypted);
}