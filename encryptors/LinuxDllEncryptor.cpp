// File: dll_encryptor_linux.cpp
#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/rand.h>

bool aes_encrypt(const std::vector<unsigned char>& plain, 
                std::vector<unsigned char>& encrypted,
                const std::string& password) {
    // Generate key and IV
    unsigned char key[32];
    unsigned char iv[16];
    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), NULL,
                  (const unsigned char*)password.c_str(),
                  password.length(), 1, key, iv);

    // Create and initialize context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    // Encrypt
    encrypted.resize(plain.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int len;
    EVP_EncryptUpdate(ctx, encrypted.data(), &len, plain.data(), plain.size());
    int ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, encrypted.data() + len, &len);
    ciphertext_len += len;
    encrypted.resize(ciphertext_len);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cout << "Usage: " << argv[0] << " <dll_path> <password>\n";
        return 1;
    }

    // Read DLL file
    std::ifstream file(argv[1], std::ios::binary);
    if (!file) {
        std::cerr << "Error opening file: " << argv[1] << std::endl;
        return 1;
    }

    std::vector<unsigned char> dllData(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>());

    // Encrypt
    std::vector<unsigned char> encrypted;
    if (!aes_encrypt(dllData, encrypted, argv[2])) {
        std::cerr << "Encryption failed!" << std::endl;
        return 1;
    }

    // Output
    std::cout << "// Replace in injector:\n";
    std::cout << "std::vector<BYTE> encryptedDllPath = {";
    for (size_t i = 0; i < encrypted.size(); i++) {
        if (i % 12 == 0) std::cout << "\n    ";
        std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') 
                 << (int)encrypted[i] << ", ";
    }
    std::cout << "\n};\n\n";
    std::cout << "Password: \"" << argv[2] << "\"\n";
    std::cout << "Original DLL size: " << std::dec << dllData.size() << " bytes\n";
    std::cout << "Encrypted size: " << encrypted.size() << " bytes\n";

    return 0;
}
