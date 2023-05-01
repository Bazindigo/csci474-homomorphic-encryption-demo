
//
// use AES-256-CBC w/ PKCS#7 padding because it's the most common for things
// like medical data where this would be applied
//

#include <openssl/evp.h>
#include <openssl/rand.h>

#define AES_256_KEY_SIZE 32
#define AES_BLOCK_SIZE 16

struct KeyInformation {
    uint8_t key[AES_256_KEY_SIZE];
    uint8_t iv[AES_BLOCK_SIZE];
};

uint8_t *uint64_to_bytes(uint64_t in, int &len) {

}

uint64_t bytes_to_uint64(uint8_t *bytes, int len) {

}

KeyInformation generate_keyinfo() {
    KeyInformation ki;

    // generate the key
    RAND_bytes(ki.key, sizeof(ki.key));

    // generate the IV
    RAND_bytes(ki.iv, sizeof(ki.iv));

    return ki;
}

uint8_t *standard_encrypt(uint64_t plaintext, int &cbytes, KeyInformation key_info) {
    // set up cipher
    EVP_CIPHER_CTX *ctx;
    EVP_EncryptInit(ctx, EVP_aes_256_cbc(), key_info.key, key_info.iv);

    // execute encryption
    int plaintext_len;
    uint8_t *out = (uint8_t *)malloc(2 * AES_BLOCK_SIZE);
    uint8_t *plaintext_bytes = uint64_to_bytes(plaintext, plaintext_len);
    int encrypted_bytes;
    EVP_EncryptUpdate(ctx, out, &encrypted_bytes, plaintext_bytes, plaintext_len);
    cbytes = encrypted_bytes;
    EVP_EncryptFinal(ctx, out + encrypted_bytes, &encrypted_bytes);
    cbytes += encrypted_bytes;
    free(plaintext_bytes);

    // return
    EVP_CIPHER_CTX_cleanup(ctx);
    return out;
}

uint64_t standard_decrypt(uint8_t *ciphertext, int cbytes, KeyInformation key_info) {
    // set up cipher
    EVP_CIPHER_CTX *ctx;
    EVP_EncryptInit(ctx, EVP_aes_256_cbc(), key_info.key, key_info.iv);

    // TODO decrypt ciphertext that is cbytes long

    // return
    EVP_CIPHER_CTX_cleanup(ctx);
    return 0;
}

// compute x^2 + 1
uint8_t *standard_operator(uint8_t *ciphertext, int &cbytes, KeyInformation key_info) {
    // decrypt
    uint64_t plain = standard_decrypt(ciphertext, cbytes, key_info);
    free(ciphertext);

    // perform operations
    plain = pow(plain, 2) + 1;

    // encrypt
    return standard_encrypt(plain, cbytes, key_info);
}

int standard_benchmark(uint64_t plaintext) {
    KeyInformation key_info = generate_keyinfo();
    int cbytes;
    uint8_t *ciphertext = standard_encrypt(plaintext, cbytes, key_info);
    ciphertext = standard_operator(ciphertext, cbytes, key_info);
    uint64_t result = standard_decrypt(ciphertext, cbytes, key_info);
    free(ciphertext);
    return 0;
}