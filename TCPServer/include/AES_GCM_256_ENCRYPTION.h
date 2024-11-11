	/*
 * AESserver.h
 *
 *  Created on: 10 Nov 2024
 *      Author: pritam
 */

#ifndef AES_GCM_256_ENCRYPTION_H_
#define AES_GCM_256_ENCRYPTION_H_

#include "StandardIncludes.h"
#include "AESIncludes.h"

class AES_GCM_256_ENCRYPTION
{
    unsigned char key[AES_32_BYTES];
    unsigned char IV[EVP_MAX_IV_LENGTH];

    EVP_CIPHER_CTX *encrypt;
    EVP_CIPHER_CTX *decrypt;

    static AES_GCM_256_ENCRYPTION *obj;
    AES_GCM_256_ENCRYPTION(const char*, const char*);
    ~AES_GCM_256_ENCRYPTION();

public:
    static AES_GCM_256_ENCRYPTION& getInstance(const char *key_ = NULL, const char* iv_ = NULL)
    {
        if (obj == NULL && key_ != NULL && iv_ != NULL)
        {
            obj = new AES_GCM_256_ENCRYPTION(key_, iv_);
        }
        return *obj;
    }

    int encryptMessage(const unsigned char *plaintext, int plaintext_len, unsigned char *iv, unsigned char *ciphertext);
    int decryptMessage(const unsigned char *ciphertext, int ciphertext_len, unsigned char *iv, unsigned char *plaintext);
};

#endif /* AES_GCM_256_ENCRYPTION_H_ */

