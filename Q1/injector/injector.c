#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

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

    const char *dllPath = argv[2];
    HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                               PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) {
        printf("OpenProcess failed (%lu)\n", GetLastError());
        return 1;
    }

    size_t pathLen = strlen(dllPath) + 1;
    LPVOID remoteMem = VirtualAllocEx(hProc, NULL, pathLen, MEM_COMMIT, PAGE_READWRITE);
    if (!remoteMem) {
        printf("VirtualAllocEx failed (%lu)\n", GetLastError());
        CloseHandle(hProc);
        return 1;
    }

    if (!WriteProcessMemory(hProc, remoteMem, dllPath, pathLen, NULL)) {
        printf("WriteProcessMemory failed (%lu)\n", GetLastError());
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }

    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    FARPROC fLoadLibraryA = GetProcAddress(hKernel, "LoadLibraryA");
    if (!fLoadLibraryA) {
        printf("GetProcAddress(LoadLibraryA) failed\n");
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }

    LPTHREAD_START_ROUTINE startRoutine = (LPTHREAD_START_ROUTINE)(LPVOID)fLoadLibraryA;
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, startRoutine, remoteMem, 0, NULL);
    if (!hThread) {
        printf("CreateRemoteThread failed (%lu)\n", GetLastError());
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
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
