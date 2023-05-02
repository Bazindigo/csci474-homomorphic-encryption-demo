
//
// use AES-256-CBC w/ PKCS#7 padding because it's the most common for things
// like medical data where this would be applied
//
#include <cmath>
#include <chrono>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <iostream>
using std::cout, std::endl;

#define AES_256_KEY_SIZE 32
#define AES_BLOCK_SIZE 16

struct KeyInformation {
    uint8_t key[AES_256_KEY_SIZE];
    uint8_t iv[AES_BLOCK_SIZE];
};

uint8_t *uint64_to_bytes(uint64_t in, int &len) {
    uint8_t *bytes = (uint8_t *)malloc(8);
    for (int i = 0; i < 8; i++) {
        bytes[i] = in >> (8 * i);
    }
    len = 8;
    return bytes;
}

uint64_t bytes_to_uint64(uint8_t *bytes, int len) {
    if (len > 8) {
        throw std::invalid_argument("cannot convert > 8 bytes to uint64_t");
    }

    uint64_t result = 0;
    for (int i = 0; i < len; i++) {
        uint64_t segment = bytes[i];
        segment = segment << (8 * i);
        result = result + segment;
    }

    free(bytes);
    return result;
}

KeyInformation generate_keyinfo() {
    KeyInformation ki;

    // initialize key and IV with cryptographically secure random bytes
    RAND_bytes(ki.key, sizeof(ki.key));
    RAND_bytes(ki.iv, sizeof(ki.iv));

    return ki;
}

uint8_t *standard_encrypt(uint64_t plaintext, int &cbytes, KeyInformation key_info) {
    // set up cipher
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(ctx, EVP_aes_256_cbc(), key_info.key, key_info.iv);

    // transform plaintext
    int plaintext_len;
    uint8_t *plaintext_bytes = uint64_to_bytes(plaintext, plaintext_len);

    // execute encryption
    int ciphertext_len;
    uint8_t *ciphertext_bytes = (uint8_t *)malloc(2 * AES_BLOCK_SIZE);

    EVP_EncryptUpdate(ctx, ciphertext_bytes, &ciphertext_len, plaintext_bytes, plaintext_len);
    cbytes = ciphertext_len;
    EVP_EncryptFinal(ctx, ciphertext_bytes + ciphertext_len, &ciphertext_len);
    cbytes += ciphertext_len;

    free(plaintext_bytes);

    // return
    EVP_CIPHER_CTX_cleanup(ctx);
    return ciphertext_bytes;
}

uint64_t standard_decrypt(uint8_t *ciphertext_bytes, int cbytes, KeyInformation key_info) {
    // set up cipher
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit(ctx, EVP_aes_256_cbc(), key_info.key, key_info.iv);

    // decrypt ciphertext that is cbytes long
    int pbytes;
    int plaintext_len;
    uint8_t *plaintext_bytes = (uint8_t *)malloc(2 * AES_BLOCK_SIZE);

    EVP_DecryptUpdate(ctx, plaintext_bytes, &plaintext_len, ciphertext_bytes, cbytes);
    pbytes = plaintext_len;
    EVP_DecryptFinal(ctx, plaintext_bytes + plaintext_len, &plaintext_len);
    pbytes += plaintext_len;

    free(ciphertext_bytes);

    // return
    EVP_CIPHER_CTX_cleanup(ctx);
    int result = bytes_to_uint64(plaintext_bytes, pbytes);
    return result;
}

// compute x^2 + 1
uint8_t *standard_operator(uint8_t *ciphertext, int &cbytes, KeyInformation key_info) {
    // decrypt
    uint64_t plain = standard_decrypt(ciphertext, cbytes, key_info);

    // perform operations
    plain = pow(plain, 2) + 1;

    // encrypt
    return standard_encrypt(plain, cbytes, key_info);
}

int standard_benchmark(uint64_t plaintext) {
    KeyInformation key_info = generate_keyinfo();

    int cbytes;
    uint8_t *ciphertext = standard_encrypt(plaintext, cbytes, key_info);

    auto start = std::chrono::high_resolution_clock::now();
    ciphertext = standard_operator(ciphertext, cbytes, key_info);
    auto end = std::chrono::high_resolution_clock::now();

    uint64_t result = standard_decrypt(ciphertext, cbytes, key_info);

    return std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
}