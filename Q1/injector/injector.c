#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

static int EnableDebugPrivilege(void) {
    HANDLE token = NULL;
    TOKEN_PRIVILEGES privileges;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return 0;
    }

    if (!LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(token);
        return 0;
    }

    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = luid;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), NULL, NULL)) {
        CloseHandle(token);
        return 0;
    }

    CloseHandle(token);
    return GetLastError() == ERROR_SUCCESS;
}

static int ResolveFullPathA(const char *inputPath, char *outputPath, DWORD outputCount) {
    WCHAR wideInput[MAX_PATH * 2];
    WCHAR wideOutput[MAX_PATH * 2];
    DWORD wideLen;

    if (!inputPath || !outputPath || outputCount == 0) {
        return 0;
    }

    MultiByteToWideChar(CP_ACP, 0, inputPath, -1, wideInput, _countof(wideInput));
    wideLen = GetFullPathNameW(wideInput, _countof(wideOutput), wideOutput, NULL);
    if (wideLen == 0 || wideLen >= _countof(wideOutput)) {
        return 0;
    }

    return WideCharToMultiByte(CP_ACP, 0, wideOutput, -1, outputPath, outputCount, NULL, NULL) != 0;
}

static DWORD_PTR FindRemoteModuleBase(DWORD pid, const char *moduleName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    MODULEENTRY32 moduleEntry;

    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    moduleEntry.dwSize = sizeof(moduleEntry);
    if (Module32First(snapshot, &moduleEntry)) {
        do {
            if (_stricmp(moduleEntry.szModule, moduleName) == 0) {
                CloseHandle(snapshot);
                return (DWORD_PTR)moduleEntry.modBaseAddr;
            }
        } while (Module32Next(snapshot, &moduleEntry));
    }

    CloseHandle(snapshot);
    return 0;
}

DWORD FindProcessId(const char *processName) {
    PROCESSENTRY32 pe32;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, processName) == 0) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: %s <pid|processname> <full_path_to_monitor_dll>\n", argv[0]);
        return 1;
    }

    DWORD pid = 0;
    if (isdigit(argv[1][0])) pid = (DWORD)atoi(argv[1]);
    else pid = FindProcessId(argv[1]);

    if (pid == 0) {
        printf("Target process not found\n");
        return 1;
    }

    EnableDebugPrivilege();

    char dllFullPath[MAX_PATH * 2];
    if (!ResolveFullPathA(argv[2], dllFullPath, sizeof(dllFullPath))) {
        printf("Failed to resolve DLL path (%lu)\n", GetLastError());
        return 1;
    }

    HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                               PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) {
        printf("OpenProcess failed (%lu)\n", GetLastError());
        return 1;
    }

    size_t pathLen = (strlen(dllFullPath) + 1) * sizeof(wchar_t);
    WCHAR wideDllPath[MAX_PATH * 2];
    if (!MultiByteToWideChar(CP_ACP, 0, dllFullPath, -1, wideDllPath, _countof(wideDllPath))) {
        printf("MultiByteToWideChar failed (%lu)\n", GetLastError());
        CloseHandle(hProc);
        return 1;
    }

    LPVOID remoteMem = VirtualAllocEx(hProc, NULL, pathLen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!remoteMem) {
        printf("VirtualAllocEx failed (%lu)\n", GetLastError());
        CloseHandle(hProc);
        return 1;
    }

    if (!WriteProcessMemory(hProc, remoteMem, wideDllPath, pathLen, NULL)) {
        printf("WriteProcessMemory failed (%lu)\n", GetLastError());
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }

    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    FARPROC fLoadLibraryW = GetProcAddress(hKernel, "LoadLibraryW");
    if (!fLoadLibraryW) {
        printf("GetProcAddress(LoadLibraryW) failed (%lu)\n", GetLastError());
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }

    DWORD_PTR remoteLoaderBase = 0;
    DWORD_PTR localLoaderOffset = 0;
    LPTHREAD_START_ROUTINE startRoutine = (LPTHREAD_START_ROUTINE)(LPVOID)fLoadLibraryW;

    localLoaderOffset = (DWORD_PTR)fLoadLibraryW - (DWORD_PTR)hKernel;
    remoteLoaderBase = FindRemoteModuleBase(pid, "kernel32.dll");
    if (remoteLoaderBase != 0 && localLoaderOffset != 0) {
        startRoutine = (LPTHREAD_START_ROUTINE)(LPVOID)(remoteLoaderBase + localLoaderOffset);
    }

    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, startRoutine, remoteMem, 0, NULL);
    if (!hThread) {
        DWORD threadError = GetLastError();
        printf("CreateRemoteThread failed (%lu), trying CreateRemoteThreadEx\n", threadError);

        hThread = CreateRemoteThreadEx(hProc, NULL, 0, startRoutine, remoteMem, 0, NULL, NULL);
        if (!hThread) {
            printf("CreateRemoteThreadEx failed (%lu)\n", GetLastError());
            VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
            CloseHandle(hProc);
            return 1;
        }
    }

    WaitForSingleObject(hThread, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    printf("Injection thread exit code: %lu\n", exitCode);

    CloseHandle(hThread);
    VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProc);
    printf("Done.\n");
    return 0;
}
