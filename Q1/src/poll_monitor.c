#define UNICODE
#define _UNICODE
#include <windows.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <wchar.h>
#include <strsafe.h>
#include <time.h>
#include <shlobj.h>
#include <stdbool.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")

#define POLL_INTERVAL_MS 2000
#define RECENT_SECONDS 30

static FILE *log_file = NULL;

static void format_time_now(wchar_t *buf, size_t bufsize) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    StringCchPrintfW(buf, bufsize, L"%04d-%02d-%02d %02d:%02d:%02d",
                     st.wYear, st.wMonth, st.wDay,
                     st.wHour, st.wMinute, st.wSecond);
}

static void log_event(DWORD pid, const wchar_t *proc, const wchar_t *remote, const wchar_t *file, unsigned long long bytes) {
    wchar_t ts[64], bytes_str[64];
    format_time_now(ts, 64);
    if (bytes < 1024) swprintf(bytes_str, 64, L"%lluB", bytes);
    else if (bytes < 1024*1024) swprintf(bytes_str, 64, L"%.0fKB", (double)bytes/1024.0);
    else if (bytes < 1024ULL*1024ULL*1024ULL) swprintf(bytes_str, 64, L"%.0fMB", (double)bytes/(1024.0*1024.0));
    else swprintf(bytes_str, 64, L"%.2fGB", (double)bytes/(1024.0*1024.0*1024.0));

    wchar_t line[2048];
    StringCchPrintfW(line, 2048, L"%s\tPID:%lu\tTCP\t%ls\tProcess:%ls\tDetectedFile:%ls (%ls)\n",
                     ts, pid, remote, proc, file, bytes_str);
    wprintf(L"%ls", line);
    if (log_file) { fwprintf(log_file, L"%ls", line); fflush(log_file); }
}

static void get_process_name(DWORD pid, wchar_t *name, size_t namesize) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) { wcscpy_s(name, namesize, L"unknown"); return; }
    wchar_t buf[MAX_PATH];
    if (GetModuleBaseNameW(h, NULL, buf, MAX_PATH)) {
        wcscpy_s(name, namesize, buf);
    } else {
        wcscpy_s(name, namesize, L"unknown");
    }
    CloseHandle(h);
}

static bool file_recent(const wchar_t *path, int seconds) {
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExW(path, GetFileExInfoStandard, &fad)) return false;
    FILETIME ft = fad.ftLastWriteTime;
    SYSTEMTIME stUTC, stLocal;
    FileTimeToSystemTime(&ft, &stUTC);
    SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);
    FILETIME ftLocal;
    SystemTimeToFileTime(&stLocal, &ftLocal);

    ULONGLONG fileTime = (((ULONGLONG)ftLocal.dwHighDateTime) << 32) | ftLocal.dwLowDateTime;
    ULONGLONG now;
    FILETIME nowFt;
    GetSystemTimeAsFileTime(&nowFt);
    FILETIME nowLocalFt;
    FileTimeToSystemTime(&nowFt, &stUTC);
    SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);
    SystemTimeToFileTime(&stLocal, &nowLocalFt);
    now = (((ULONGLONG)nowLocalFt.dwHighDateTime) << 32) | nowLocalFt.dwLowDateTime;

    ULONGLONG diff100ns = now - fileTime; // in 100-nanosecond intervals
    unsigned long diffSec = (unsigned long)(diff100ns / 10000000ULL);
    return diffSec <= (unsigned long)seconds;
}

static void scan_recent_files_for_pid(DWORD pid, wchar_t *out_file, size_t out_file_sz) {
    // Heuristic: check common user folders for recently modified files
    wchar_t *folders[] = {L"Downloads", L"Desktop", L"Documents", L"AppData\\Local\\Temp"};
    wchar_t userProfile[MAX_PATH];
    size_t len = GetEnvironmentVariableW(L"USERPROFILE", userProfile, MAX_PATH);
    if (len==0 || len>=MAX_PATH) { out_file[0]=0; return; }

    wchar_t path[MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE hFind;
    for (int i=0;i< (int)(sizeof(folders)/sizeof(folders[0])); i++) {
        StringCchPrintfW(path, MAX_PATH, L"%s\\%s\\*", userProfile, folders[i]);
        hFind = FindFirstFileW(path, &fd);
        if (hFind==INVALID_HANDLE_VALUE) continue;
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            wchar_t full[MAX_PATH];
            StringCchPrintfW(full, MAX_PATH, L"%s\\%s\\%s", userProfile, folders[i], fd.cFileName);
            if (file_recent(full, RECENT_SECONDS)) {
                // attribute-based heuristic: assume recent file by this process
                // Inaccurate but simple.
                wcscpy_s(out_file, out_file_sz, full);
                FindClose(hFind);
                return;
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }
    out_file[0]=0;
}

int wmain(int argc, wchar_t *argv[]) {
    wprintf(L"Poll-based Upload Monitor - Starting (heuristic detector)\n");
    log_file = _wfopen(L"upload_log.txt", L"a, ccs=UTF-8");
    if (log_file) wprintf(L"Logging to upload_log.txt\n");

    while (1) {
        DWORD dwSize = 0;
        PMIB_TCPTABLE_OWNER_PID pTcpTable = NULL;
        if (GetExtendedTcpTable(NULL, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
            pTcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(dwSize);
        }
        if (!pTcpTable) { Sleep(POLL_INTERVAL_MS); continue; }
        if (GetExtendedTcpTable(pTcpTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (DWORD i=0;i<pTcpTable->dwNumEntries;i++) {
                MIB_TCPROW_OWNER_PID *row = &pTcpTable->table[i];
                if (row->dwState == MIB_TCP_STATE_ESTAB) {
                    // Build remote ip:port
                    IN_ADDR addr;
                    addr.S_un.S_addr = row->dwRemoteAddr;
                    wchar_t remote[64];
                    StringCchPrintfW(remote, 64, L"%d.%d.%d.%d:%u",
                                     addr.S_un.S_un_b.s_b1, addr.S_un.S_un_b.s_b2, addr.S_un.S_un_b.s_b3, addr.S_un.S_un_b.s_b4,
                                     ntohs((u_short)row->dwRemotePort));
                    DWORD pid = row->dwOwningPid;
                    wchar_t proc[256]; get_process_name(pid, proc, 256);
                    wchar_t recentFile[MAX_PATH]; recentFile[0]=0;
                    scan_recent_files_for_pid(pid, recentFile, MAX_PATH);
                    if (recentFile[0]!=0) {
                        // We don't have per-connection bytes; approximate with 0
                        log_event(pid, proc, remote, recentFile, 0);
                    }
                }
            }
        }
        free(pTcpTable);
        Sleep(POLL_INTERVAL_MS);
    }
    return 0;
}
