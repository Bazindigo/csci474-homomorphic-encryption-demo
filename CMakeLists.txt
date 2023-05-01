cmake_minimum_required(VERSION 3.20)
project(SEAL_comparison)

# declare a target called test
add_executable(comparison comparison.cpp)

# require microsoft seal for target test
find_package(SEAL 4.1 REQUIRED)
target_link_libraries(comparison SEAL::seal)

# require openssl for target test
find_package(OpenSSL 3.0.8 REQUIRED)
target_link_libraries(comparison OpenSSL::Crypto)