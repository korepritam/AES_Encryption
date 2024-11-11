/*
 * AESserver.cpp
 *
 *  Created on: 10 Nov 2024
 *      Author: pritam
 */

#include "AES_GCM_256_ENCRYPTION.h"

AES_GCM_256_ENCRYPTION *AES_GCM_256_ENCRYPTION::obj = nullptr;

AES_GCM_256_ENCRYPTION::AES_GCM_256_ENCRYPTION(const char *key_, const char* iv_)
{
	memcpy(key, key_, AES_32_BYTES);
	memcpy(IV, iv_, EVP_MAX_IV_LENGTH);

    std::cout << "Cryptographic Key[";
    for (int i = 0; i < AES_32_BYTES; ++i) {
        printf("%02x", key[i]);
    }
    printf("]\n");

    std::cout << "IV[";
    for (int i = 0; i < EVP_MAX_IV_LENGTH; ++i) {
        printf("%02x", key[i]);
    }
    printf("]\n");

    encrypt = EVP_CIPHER_CTX_new();
    if (encrypt == nullptr) {
        perror("Error initializing Encrypt cipher context.");
        abort();
    }

    decrypt = EVP_CIPHER_CTX_new();
    if(decrypt == nullptr) {
        perror("Error initializing Decrypt cipher context.");
        abort();
    }
}

AES_GCM_256_ENCRYPTION::~AES_GCM_256_ENCRYPTION()
{
	EVP_CIPHER_CTX_free(encrypt); encrypt = nullptr;
	EVP_CIPHER_CTX_free(decrypt); decrypt = nullptr;
}

int AES_GCM_256_ENCRYPTION::encryptMessage(const unsigned char *plaintext, int plaintext_len, unsigned char *iv, unsigned char *ciphertext)
{
    int len = 0;
    int ciphertext_len = 0;

    if (EVP_EncryptInit_ex(encrypt, EVP_aes_256_cbc(), nullptr, key, iv) != 1)
    {
        perror("Error during encryption initialization: ");
        return -1;
    }

    if (EVP_EncryptUpdate(encrypt, ciphertext, &len, plaintext, plaintext_len) != 1)
    {
        perror("Error during encryption update: ");
        return -1;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(encrypt, ciphertext + len, &len) != 1)
    {
        perror("Error during final encryption: ");
        return -1;
    }
    ciphertext_len += len;
    return ciphertext_len;
}

int AES_GCM_256_ENCRYPTION::decryptMessage(const unsigned char *ciphertext, int ciphertext_len, unsigned char *iv, unsigned char *plaintext)
{
    int len = 0;
    int plaintext_len = 0;

    if (EVP_DecryptInit_ex(decrypt, EVP_aes_256_cbc(), nullptr, key, iv) != 1)
    {
        perror("Error initializing decryption: ");
        return -1;
    }

    if (EVP_DecryptUpdate(decrypt, plaintext, &len, ciphertext, ciphertext_len) != 1)
    {
        perror("Error during decryption update: ");
        return -1;
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(decrypt, plaintext + len, &len) != 1)
    {
        perror("Error during final decryption: ");
        return -1;
    }
    plaintext_len += len;
    return plaintext_len;
}
