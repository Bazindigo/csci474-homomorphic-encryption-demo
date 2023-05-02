#include <iostream>

#include "seal.hpp"
#include "standard.hpp"

int main() {
    uint64_t plaintext = 64;
    int ns_homomorphic = homomorphic_benchmark(plaintext);
    int ns_standard = standard_benchmark(plaintext);

    cout << "homomorphic operation (ns): " << ns_homomorphic << endl;
    cout << "AES-256-CBC operation (ns): " << ns_standard << endl;
}