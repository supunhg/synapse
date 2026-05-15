#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
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
#define DEDUPE_WINDOW 30

static FILE *log_file = NULL;

typedef struct {
    DWORD pid;
    wchar_t remote[64];
    wchar_t file[MAX_PATH];
    time_t ts;
} recent_entry;

static recent_entry recent[256];
static int recent_count = 0;

static bool should_log_and_update(DWORD pid, const wchar_t *remote, const wchar_t *file) {
    time_t now = time(NULL);
    for (int i = 0; i < recent_count; i++) {
        if (recent[i].pid == pid && wcscmp(recent[i].remote, remote) == 0 && wcscmp(recent[i].file, file) == 0) {
            if (now - recent[i].ts < DEDUPE_WINDOW) return false;
            recent[i].ts = now;
            return true;
        }
    }
    if (recent_count < (int)(sizeof(recent)/sizeof(recent[0]))) {
        recent[recent_count].pid = pid;
        wcscpy_s(recent[recent_count].remote, 64, remote);
        wcscpy_s(recent[recent_count].file, MAX_PATH, file);
        recent[recent_count].ts = now;
        recent_count++;
        return true;
    }
    // rotate oldest
    int oldest = 0;
    for (int i = 1; i < recent_count; i++) if (recent[i].ts < recent[oldest].ts) oldest = i;
    recent[oldest].pid = pid;
    wcscpy_s(recent[oldest].remote, 64, remote);
    wcscpy_s(recent[oldest].file, MAX_PATH, file);
    recent[oldest].ts = now;
    return true;
}

static bool is_likely_upload_client(const wchar_t *proc) {
    const wchar_t *names[] = {
        L"msedge.exe",
        L"msedgewebview2.exe",
        L"chrome.exe",
        L"firefox.exe",
        L"brave.exe",
        L"opera.exe",
        L"webview2.exe"
    };

    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        if (_wcsicmp(proc, names[i]) == 0) return true;
    }

    return false;
}

static bool is_temp_path(const wchar_t *path) {
    return wcsstr(path, L"\\AppData\\Local\\Temp\\") != NULL ||
           wcsstr(path, L"\\Temp\\") != NULL;
}

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
    // Heuristic: only treat temp-staged files as likely upload evidence.
    wchar_t *folders[] = {L"AppData\\Local\\Temp"};
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
                    if (recentFile[0]!=0 && is_likely_upload_client(proc)) {
                        WIN32_FILE_ATTRIBUTE_DATA recentFad;
                        unsigned long long fileSize = 0;
                        if (GetFileAttributesExW(recentFile, GetFileExInfoStandard, &recentFad)) {
                            fileSize = (((unsigned long long)recentFad.nFileSizeHigh) << 32) | recentFad.nFileSizeLow;
                        }
                        if (fileSize == 0 && is_temp_path(recentFile)) {
                            continue;
                        }
                        // Deduplicate frequent identical reports
                        if (should_log_and_update(pid, remote, recentFile)) {
                            // We don't have per-connection bytes; approximate with 0
                            log_event(pid, proc, remote, recentFile, fileSize);
                        }
                    }
                }
            }
        }
        free(pTcpTable);
        Sleep(POLL_INTERVAL_MS);
    }
    return 0;
}
