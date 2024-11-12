/*
 * AESserver.cpp
 *
 *  Created on: 10 Nov 2024
 *      Author: pritam
 */

#include "AES_GCM_256_ENCRYPTION.h"
#define NANO_MULTIPLIER 1000000000

AES_GCM_256_ENCRYPTION *AES_GCM_256_ENCRYPTION::obj = nullptr;

AES_GCM_256_ENCRYPTION::AES_GCM_256_ENCRYPTION(const char *key_, const char* iv_)
{
	memcpy(key, key_, AES_32_BYTES);
	memcpy(IV, iv_, EVP_MAX_IV_LENGTH);

    cout << "Cryptographic Key[";
    for (int i = 0; i < AES_32_BYTES; ++i) {
        printf("%c", key[i]);
    }
    printf("]\n");

    cout << "IV[";
    for (int i = 0; i < EVP_MAX_IV_LENGTH; ++i) {
        printf("%c", IV[i]);
    }
    printf("]\n");

    encrypt = EVP_CIPHER_CTX_new();
    if(encrypt == nullptr) {
        perror("Error initializing Encrypt cipher context.");
        abort();
    }

    if(EVP_EncryptInit_ex(encrypt, EVP_aes_256_cbc(), nullptr, key, IV) != 1) {
        perror("Error during encryption initialization: ");
        abort();
    }

    decrypt = EVP_CIPHER_CTX_new();
    if(decrypt == nullptr) {
        perror("Error initializing Decrypt cipher context.");
        abort();
    }
    if(EVP_DecryptInit_ex(decrypt, EVP_aes_256_cbc(), nullptr, key, IV) != 1) {
        perror("Error initializing decryption: ");
        abort();
    }
}

AES_GCM_256_ENCRYPTION::~AES_GCM_256_ENCRYPTION()
{
	EVP_CIPHER_CTX_free(encrypt); encrypt = nullptr;
	EVP_CIPHER_CTX_free(decrypt); decrypt = nullptr;
}

unsigned long get_latency(struct timespec& start, struct timespec& end)
{
    long seconds = end.tv_sec - start.tv_sec;
    long nanoseconds = end.tv_nsec - start.tv_nsec;

    if (nanoseconds < 0) {
        seconds--;
        nanoseconds += NANO_MULTIPLIER;
    }

    return (seconds * NANO_MULTIPLIER) + nanoseconds;
}

timespec LATENCY_PROFILE_ENCRYPT[3];
int AES_GCM_256_ENCRYPTION::encryptMessage(const unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext)
{
#ifdef LATENCY_PROFILE
	for(int i=0; i<3; i++) memset(&LATENCY_PROFILE_ENCRYPT[i], 0, sizeof(timespec));
#endif
    int len = 0;
    int ciphertext_len = 0;

#ifdef LATENCY_PROFILE
    clock_gettime(CLOCK_MONOTONIC, &LATENCY_PROFILE_ENCRYPT[0]);
#endif

    if(EVP_EncryptUpdate(encrypt, ciphertext, &len, plaintext, plaintext_len) != 1) {
        perror("Error during encryption update: ");
        return -1;
    }
    ciphertext_len = len;
#ifdef LATENCY_PROFILE
    clock_gettime(CLOCK_MONOTONIC, &LATENCY_PROFILE_ENCRYPT[1]);
#endif
    if(EVP_EncryptFinal_ex(encrypt, ciphertext + len, &len) != 1) {
        perror("Error during final encryption: ");
        return -1;
    }
    ciphertext_len += len;

#ifdef LATENCY_PROFILE
    clock_gettime(CLOCK_MONOTONIC, &LATENCY_PROFILE_ENCRYPT[2]);

    cout << endl;
    cout << "Encrypt Latency Profile =>" << endl;
    cout << "EncryptUpdate [" << get_latency(LATENCY_PROFILE_ENCRYPT[0],LATENCY_PROFILE_ENCRYPT[1]) << "]" << endl;
    cout << "EncryptFinal_ex [" << get_latency(LATENCY_PROFILE_ENCRYPT[1],LATENCY_PROFILE_ENCRYPT[2]) << "]" << endl;
    cout << endl;
#endif
    return ciphertext_len;
}

timespec LATENCY_PROFILE_DECRYPT[3];

int AES_GCM_256_ENCRYPTION::decryptMessage(const unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext)
{
#ifdef LATENCY_PROFILE
	for(int i=0; i<3; i++) memset(&LATENCY_PROFILE_DECRYPT[i], 0, sizeof(timespec));
#endif
    int len = 0;
    int plaintext_len = 0;
#ifdef LATENCY_PROFILE
    clock_gettime(CLOCK_MONOTONIC, &LATENCY_PROFILE_DECRYPT[0]);
#endif
    if(EVP_DecryptUpdate(decrypt, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        perror("Error during decryption update: ");
        return -1;
    }
    plaintext_len = len;
#ifdef LATENCY_PROFILE
    clock_gettime(CLOCK_MONOTONIC, &LATENCY_PROFILE_DECRYPT[1]);
#endif
    if(EVP_DecryptFinal_ex(decrypt, plaintext + len, &len) != 1) {
        perror("Error during final decryption: ");
        return -1;
    }
    plaintext_len += len;
#ifdef LATENCY_PROFILE
    clock_gettime(CLOCK_MONOTONIC, &LATENCY_PROFILE_DECRYPT[2]);

    cout << endl;
    cout << "Decrypt Latency Profile =>" << endl;
    cout << "DecryptUpdate [" << get_latency(LATENCY_PROFILE_DECRYPT[0],LATENCY_PROFILE_DECRYPT[1]) << "]" << endl;
    cout << "DecryptFinal_ex [" << get_latency(LATENCY_PROFILE_DECRYPT[1],LATENCY_PROFILE_DECRYPT[2]) << "]" << endl;
    cout << endl;
#endif
    return plaintext_len;
}
