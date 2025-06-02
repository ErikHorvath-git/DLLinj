#include <windows.h>
#include <stdio.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        MessageBoxA(NULL, "DLL Injected Successfully!", "Injection Test", MB_OK);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

// Optional exported function
extern "C" __declspec(dllexport) void HelloWorld() {
    MessageBoxA(NULL, "Hello from the injected DLL!", "DLL Function", MB_OK);
}
