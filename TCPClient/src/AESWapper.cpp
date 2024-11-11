#include "AESWrapper.h"

AESWrapper *AESWrapper::obj = nullptr;

AESWrapper::AESWrapper(const char *key_) {
    if (key_ == nullptr) {
        std::cerr << "Error: NULL key passed to AESWrapper." << std::endl;
        return;
    }
    memcpy(key, key_, AES_16_BYTES);
    std::cout << "Key: ";
    for (int i = 0; i < AES_16_BYTES; ++i) {
        printf("%02x", key[i]);
    }
    printf("\n");
}

AESWrapper::~AESWrapper() {}

int AESWrapper::encrypt(const unsigned char *plaintext, int plaintext_len, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        std::cerr << "Error initializing cipher context." << std::endl;
        return -1;
    }

    int len = 0;
    int ciphertext_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv) != 1) {
        unsigned long err = ERR_get_error();
        char err_buf[120];
        ERR_error_string(err, err_buf);
        std::cerr << "Error during encryption initialization: " << err_buf << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        unsigned long err = ERR_get_error();
        char err_buf[120];
        ERR_error_string(err, err_buf);
        std::cerr << "Error during encryption update: " << err_buf << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        unsigned long err = ERR_get_error();
        char err_buf[120];
        ERR_error_string(err, err_buf);
        std::cerr << "Error during final encryption: " << err_buf << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int AESWrapper::decrypt(const unsigned char *ciphertext, int ciphertext_len, unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        std::cerr << "Error initializing cipher context." << std::endl;
        return -1;
    }

    int len = 0;
    int plaintext_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv) != 1) {
        unsigned long err = ERR_get_error();
        char err_buf[120];
        ERR_error_string(err, err_buf);
        std::cerr << "Error initializing decryption: " << err_buf << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        unsigned long err = ERR_get_error();
        char err_buf[120];
        ERR_error_string(err, err_buf);
        std::cerr << "Error during decryption update: " << err_buf << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        unsigned long err = ERR_get_error();
        char err_buf[120];
        ERR_error_string(err, err_buf);
        std::cerr << "Error during final decryption: " << err_buf << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

void AESWrapper::generate_random_iv(unsigned char *iv) {
    if (RAND_bytes(iv, EVP_MAX_IV_LENGTH) != 1) {
        std::cerr << "Error generating random IV." << std::endl;
    }
}
