#include "seal.hpp"
#include "standard.hpp"

int main() {
    uint64_t plaintext = 64;
    homomorphic_benchmark(plaintext);
    standard_benchmark(plaintext);
}