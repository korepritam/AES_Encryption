/*
 * AESserver.h
 *
 *  Created on: 10 Nov 2024
 *      Author: pritam
 */

#ifndef AESWRAPPER_H_
#define AESWRAPPER_H_

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <iostream>
#include <cstring>

#define AES_16_BYTES 16 // 128-bit key length

class AESWrapper {
    unsigned char key[AES_16_BYTES];

    static AESWrapper *obj;
    AESWrapper(const char*);
    ~AESWrapper();

public:
    static AESWrapper& getInstance(const char *key_ = NULL)
    {
        if (obj == NULL && key_ != NULL) {
            obj = new AESWrapper(key_);
        }
        return *obj;
    }

    int encrypt(const unsigned char *plaintext, int plaintext_len, unsigned char *iv, unsigned char *ciphertext);
    int decrypt(const unsigned char *ciphertext, int ciphertext_len, unsigned char *iv, unsigned char *plaintext);
    void generate_random_iv(unsigned char *iv);
    void generate_random_key(unsigned char *key);  // New method to generate random key
};

#endif /* AESWRAPPER_H_ */
