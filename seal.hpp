#include <cstdint>
#include <string>
#include <chrono>

#include "seal/seal.h"

using namespace std;
using namespace seal;

struct KeyPair {
    SecretKey secret_key;
    PublicKey public_key;
};

SEALContext get_SEAL_context() {
    // set encryption parameters
    EncryptionParameters params(scheme_type::bfv);
    size_t polynomial_modulus_degree = 4096;
    params.set_poly_modulus_degree(polynomial_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::BFVDefault(polynomial_modulus_degree));
    params.set_plain_modulus(1024);

    // validate parameters
    SEALContext context(params);
    return context;
}

KeyPair generate_keypair() {
    SEALContext context = get_SEAL_context();

    // generate key
    KeyPair kp;
    KeyGenerator keygen(context);
    kp.secret_key = keygen.secret_key();
    keygen.create_public_key(kp.public_key);

    // return them
    return kp;
}

Ciphertext homomorphic_encrypt(uint64_t plaintext, PublicKey public_key) {
    SEALContext context = get_SEAL_context();

    // set up encryption object
    Encryptor encryptor(context, public_key);

    // create plaintext object
    Plaintext plain(util::uint_to_hex_string(&plaintext, size_t(1)));

    // create ciphertext object and execute encryption
    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);
    return encrypted;
}

// compute x^2 + 1
Ciphertext homomorphic_operator(Ciphertext ciphertext) {
    SEALContext context = get_SEAL_context();

    // create eval class
    Evaluator evaluator(context);

    // perform operations
    Ciphertext result;
    evaluator.square(ciphertext, result);
    Plaintext one("1");
    evaluator.add_plain_inplace(result, one);

    return result;
}

int homomorphic_decrypt(SecretKey secret_key, Ciphertext ciphertext) {
    SEALContext context = get_SEAL_context();

    // create eval class
    Decryptor decryptor(context, secret_key);

    // create objects and execute decryption
    Plaintext plain;
    decryptor.decrypt(ciphertext, plain);

    // return the value
    string decrypted_hex = plain.to_string();
    uint64_t result;
    util::hex_string_to_uint(decrypted_hex.c_str(), decrypted_hex.length(), size_t(1), &result);
    return result;
}

int homomorphic_benchmark(uint64_t plaintext) {
    KeyPair key_pair = generate_keypair();
    Ciphertext ciphertext = homomorphic_encrypt(plaintext, key_pair.public_key);
    auto start = std::chrono::high_resolution_clock::now();
    ciphertext = homomorphic_operator(ciphertext);
    auto end = std::chrono::high_resolution_clock::now();
    int result = homomorphic_decrypt(key_pair.secret_key, ciphertext);
    return std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
}