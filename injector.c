#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

#define TARGET_EXE   L"clion64.exe"
#define DLL_NAME    L"libCLionCrack.dll"
#define MAX_KNOWN_PIDS 64

static DWORD gKnownPids[MAX_KNOWN_PIDS] = {0};
static size_t gKnownCount = 0;

static BOOL IsPidKnown(DWORD pid) {
    for (size_t i = 0; i < gKnownCount; ++i) {
        if (gKnownPids[i] == pid) return TRUE;
    }
    return FALSE;
}

static void AddPid(DWORD pid) {
    for (size_t i = 0; i < MAX_KNOWN_PIDS; ++i) {
        if (gKnownPids[i] == 0) {
            gKnownPids[i] = pid;
            if (i >= gKnownCount) gKnownCount = i + 1;
            return;
        }
    }
}

static void RemovePid(DWORD pid) {
    for (size_t i = 0; i < MAX_KNOWN_PIDS; ++i) {
        if (gKnownPids[i] == pid) {
            gKnownPids[i] = 0;
            while (gKnownCount > 0 && gKnownPids[gKnownCount - 1] == 0)
                --gKnownCount;
            return;
        }
    }
}

DWORD FindTargetPID(void) {
    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(pe);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    for (size_t i = 0; i < gKnownCount; ++i) {
        DWORD knownPid = gKnownPids[i];
        if (knownPid != 0) {
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, knownPid);
            if (h) {
                CloseHandle(h);
            } else {
                RemovePid(knownPid);
            }
        }
    }

    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, TARGET_EXE) == 0) {
                DWORD pid = pe.th32ProcessID;
                if (!IsPidKnown(pid)) {
                    AddPid(pid);
                    CloseHandle(snap);
                    return pid;
                }
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return 0;
}

static BOOL GetRelativeDLLPath(wchar_t *outPath, size_t outSize) {
    wchar_t exePath[MAX_PATH];
    if (!GetModuleFileNameW(NULL, exePath, MAX_PATH))
        return FALSE;

    wchar_t *lastSlash = wcsrchr(exePath, L'\\');
    if (!lastSlash) return FALSE;
    *(lastSlash + 1) = L'\0';

    if (swprintf_s(outPath, outSize, L"%s%ls", exePath, DLL_NAME) < 0)
        return FALSE;
    return TRUE;
}

BOOL InjectDLL(wchar_t *dllPath, DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD |
                               PROCESS_QUERY_INFORMATION |
                               PROCESS_VM_OPERATION |
                               PROCESS_VM_WRITE |
                               PROCESS_VM_READ,
                               FALSE, pid);
    if (!hProc) return FALSE;

    size_t pathSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    LPVOID remoteMem = VirtualAllocEx(hProc, NULL, pathSize,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        CloseHandle(hProc);
        return FALSE;
    }

    if (!WriteProcessMemory(hProc, remoteMem, dllPath, pathSize, NULL)) {
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return FALSE;
    }

    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)&LoadLibraryW,
                                        remoteMem, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProc);
    return TRUE;
}

int main(void) {
    wchar_t dllPath[MAX_PATH];
    if (!GetRelativeDLLPath(dllPath, MAX_PATH))
        return FALSE;
    wprintf(L"[*] DLL path: %ls\n", dllPath);

    if (INVALID_FILE_ATTRIBUTES == GetFileAttributesW(dllPath)) {
        wprintf(L"[-] Invalid DLL path. Is the DLL in the same directory as the injector?\n");
        return FALSE;
    }

    BOOL bNote = TRUE;
    while (1) {
        if (bNote) {
            bNote = FALSE;
            wprintf(L"[*] Searching for %ls...\n", TARGET_EXE);
        }
        DWORD pid = FindTargetPID();
        if (pid) {
            wprintf(L"[+] Found %ls (%lu), injecting... ", TARGET_EXE, pid);
            if (InjectDLL(dllPath, pid))
                wprintf(L"done!\n");
            else
                wprintf(L"failed, do you not have permissions?\n");
            bNote = TRUE;
        }
        Sleep(500);
    }
    return 0;
}
