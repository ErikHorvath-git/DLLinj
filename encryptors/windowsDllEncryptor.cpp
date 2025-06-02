// File: dll_encryptor.cpp
#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#pragma comment(lib, "advapi32.lib")

namespace crypto {
    bool aes_encrypt(const std::vector<BYTE>& plain, std::vector<BYTE>& encrypted, const std::string& password) {
        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        HCRYPTKEY hKey = 0;
        BOOL success = FALSE;

        if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            std::cerr << "CryptAcquireContext failed: " << GetLastError() << std::endl;
            goto cleanup;
        }

        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            std::cerr << "CryptCreateHash failed: " << GetLastError() << std::endl;
            goto cleanup;
        }

        if (!CryptHashData(hHash, (BYTE*)password.c_str(), (DWORD)password.length(), 0)) {
            std::cerr << "CryptHashData failed: " << GetLastError() << std::endl;
            goto cleanup;
        }

        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, CRYPT_EXPORTABLE, &hKey)) {
            std::cerr << "CryptDeriveKey failed: " << GetLastError() << std::endl;
            goto cleanup;
        }

        encrypted = plain;
        DWORD dataLen = (DWORD)encrypted.size();
        if (!CryptEncrypt(hKey, 0, TRUE, 0, encrypted.data(), &dataLen, (DWORD)encrypted.capacity())) {
            std::cerr << "CryptEncrypt failed: " << GetLastError() << std::endl;
            goto cleanup;
        }
        encrypted.resize(dataLen);

        success = TRUE;

    cleanup:
        if (hKey) CryptDestroyKey(hKey);
        if (hHash) CryptDestroyHash(hHash);
        if (hProv) CryptReleaseContext(hProv, 0);
        return success;
    }
}

void generate_encrypted_payload(const std::string& dllPath, const std::string& password) {
    HANDLE hFile = CreateFileA(dllPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open DLL: " << GetLastError() << std::endl;
        return;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    std::vector<BYTE> dllData(fileSize);
    DWORD bytesRead;
    if (!ReadFile(hFile, dllData.data(), fileSize, &bytesRead, NULL)) {
        std::cerr << "Failed to read DLL: " << GetLastError() << std::endl;
        CloseHandle(hFile);
        return;
    }
    CloseHandle(hFile);

    std::vector<BYTE> encrypted;
    if (crypto::aes_encrypt(dllData, encrypted, password)) {
        std::cout << "// Replace in injector:\n";
        std::cout << "std::vector<BYTE> encryptedDllPath = {";
        for (size_t i = 0; i < encrypted.size(); i++) {
            if (i % 12 == 0) std::cout << "\n    ";
            std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)encrypted[i] << ", ";
        }
        std::cout << "\n};\n\n";
        std::cout << "Password: \"" << password << "\"\n";
        std::cout << "Original DLL size: " << std::dec << dllData.size() << " bytes\n";
        std::cout << "Encrypted size: " << encrypted.size() << " bytes\n";
    } else {
        std::cerr << "Encryption failed!\n";
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cout << "Usage: dll_encryptor.exe <dll_path> <password>\n";
        std::cout << "Example: dll_encryptor.exe testdll.dll supersecret\n";
        return 1;
    }

    std::string dllPath = argv[1];
    std::string password = argv[2];

    generate_encrypted_payload(dllPath, password);
    return 0;
}
