#include <Windows.h>
#include <MinHook.h>

#define KEY_PATH L"clion.key"

HANDLE (WINAPI * CreateFileW_t)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

HANDLE WINAPI CreateFileW_hk (LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    if (wcsstr(lpFileName, KEY_PATH)) {
        SuspendThread(GetCurrentThread());
        return NULL;
    }

    return CreateFileW_t(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

DWORD MainThread(LPVOID param) {
    if (MH_Initialize() != MH_OK) {
        MessageBoxA(NULL, "Failed to initialize MinHook", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    if (MH_OK != MH_CreateHook(CreateFileW, CreateFileW_hk, (LPVOID *) &CreateFileW_t)) {
        MessageBoxA(NULL, "Failed to set hooks", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    if (MH_OK != MH_EnableHook(MH_ALL_HOOKS)) {
        MessageBoxA(NULL, "Failed to enable hooks", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    while (TRUE) {
        Sleep(1000);
    }
}

BOOL WINAPI DllMain(HMODULE hinstance, DWORD dwReason, LPVOID reserved)
{
    if (dwReason == DLL_PROCESS_ATTACH) {
        if (NULL == CreateThread(NULL, 0, &MainThread, NULL, 0, NULL)) return FALSE;
    }

    return TRUE;
}
