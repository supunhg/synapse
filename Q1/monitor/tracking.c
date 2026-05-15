#include "tracking.h"

#include "logger.h"

#include <stdio.h>
#include <string.h>
#include <ws2tcpip.h>

#define MAX_TRACKED_FILES 1024
#define MAX_TRACKED_SOCKETS 1024
#define CORRELATION_WINDOW_MS 5000ULL

static CRITICAL_SECTION g_cs;
static BOOL g_csReady = FALSE;
static FILE_TRACK g_files[MAX_TRACKED_FILES];
static SOCKET_TRACK g_sockets[MAX_TRACKED_SOCKETS];
static int g_fileCount = 0;
static int g_socketCount = 0;

static void utf16_to_utf8(const WCHAR *input, char *output, size_t outputCount) {
    if (!output || outputCount == 0) {
        return;
    }
    output[0] = '\0';
    if (!input) {
        return;
    }
    WideCharToMultiByte(CP_UTF8, 0, input, -1, output, (int)outputCount, NULL, NULL);
}

static void format_timestamp(char *buffer, size_t bufferCount) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    snprintf(buffer, bufferCount, "%04u-%02u-%02u %02u:%02u:%02u.%03u",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

static BOOL resolve_socket_endpoint(SOCKET s, char *ipOut, size_t ipOutCount, int *portOut) {
    struct sockaddr_storage addr;
    int addrLen = sizeof(addr);
    ipOut[0] = '\0';
    *portOut = 0;

    if (getpeername(s, (struct sockaddr *)&addr, &addrLen) != 0) {
        return FALSE;
    }

    if (addr.ss_family == AF_INET) {
        struct sockaddr_in *inAddr = (struct sockaddr_in *)&addr;
        if (!inet_ntop(AF_INET, &inAddr->sin_addr, ipOut, (socklen_t)ipOutCount)) {
            return FALSE;
        }
        *portOut = ntohs(inAddr->sin_port);
        return TRUE;
    }

    if (addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *in6Addr = (struct sockaddr_in6 *)&addr;
        if (!inet_ntop(AF_INET6, &in6Addr->sin6_addr, ipOut, (socklen_t)ipOutCount)) {
            return FALSE;
        }
        *portOut = ntohs(in6Addr->sin6_port);
        return TRUE;
    }

    return FALSE;
}

static FILE_TRACK *find_file_by_handle(HANDLE hFile) {
    for (int i = g_fileCount - 1; i >= 0; --i) {
        if (g_files[i].handle == hFile) {
            return &g_files[i];
        }
    }
    return NULL;
}

static SOCKET_TRACK *find_socket_by_handle(SOCKET s) {
    for (int i = g_socketCount - 1; i >= 0; --i) {
        if (g_sockets[i].socket == s) {
            return &g_sockets[i];
        }
    }
    return NULL;
}

void Tracking_Init(void) {
    if (!g_csReady) {
        InitializeCriticalSection(&g_cs);
        g_csReady = TRUE;
    }
}

void Tracking_Shutdown(void) {
    if (g_csReady) {
        DeleteCriticalSection(&g_cs);
        g_csReady = FALSE;
    }
}

void Tracking_AddFile(HANDLE hFile, const WCHAR *path, DWORD pid, const WCHAR *processName) {
    if (!g_csReady || !hFile || hFile == INVALID_HANDLE_VALUE || !path) {
        return;
    }

    EnterCriticalSection(&g_cs);
    FILE_TRACK *entry = find_file_by_handle(hFile);
    if (!entry && g_fileCount < MAX_TRACKED_FILES) {
        entry = &g_files[g_fileCount++];
    }
    if (entry) {
        entry->handle = hFile;
        wcsncpy_s(entry->path, _countof(entry->path), path, _TRUNCATE);
        entry->pid = pid;
        wcsncpy_s(entry->processName, _countof(entry->processName), processName ? processName : L"unknown", _TRUNCATE);
        entry->lastReadTick = GetTickCount64();
        entry->totalRead = 0;
        entry->lastCorrelatedTick = 0;
        char pathUtf8[MAX_PATH * 4];
        char procUtf8[MAX_PATH * 4];
        utf16_to_utf8(entry->path, pathUtf8, sizeof(pathUtf8));
        utf16_to_utf8(entry->processName, procUtf8, sizeof(procUtf8));
        LogDebugA("TrackFileOpen pid=%lu process=%s file=%s handle=0x%p", (unsigned long)pid, procUtf8, pathUtf8, hFile);
    }
    LeaveCriticalSection(&g_cs);
}

void Tracking_UpdateRead(HANDLE hFile, SIZE_T bytes) {
    if (!g_csReady || !hFile || hFile == INVALID_HANDLE_VALUE) {
        return;
    }

    EnterCriticalSection(&g_cs);
    FILE_TRACK *entry = find_file_by_handle(hFile);
    if (entry) {
        entry->totalRead += bytes;
        entry->lastReadTick = GetTickCount64();
        char pathUtf8[MAX_PATH * 4];
        utf16_to_utf8(entry->path, pathUtf8, sizeof(pathUtf8));
        LogDebugA("TrackFileRead file=%s bytes=%llu total=%llu", pathUtf8, (unsigned long long)bytes, (unsigned long long)entry->totalRead);
    }
    LeaveCriticalSection(&g_cs);
}

void Tracking_RemoveFile(HANDLE hFile) {
    if (!g_csReady || !hFile || hFile == INVALID_HANDLE_VALUE) {
        return;
    }

    EnterCriticalSection(&g_cs);
    for (int i = 0; i < g_fileCount; ++i) {
        if (g_files[i].handle == hFile) {
            for (int j = i; j + 1 < g_fileCount; ++j) {
                g_files[j] = g_files[j + 1];
            }
            ZeroMemory(&g_files[g_fileCount - 1], sizeof(g_files[g_fileCount - 1]));
            --g_fileCount;
            break;
        }
    }
    LeaveCriticalSection(&g_cs);
}

void Tracking_AddSocket(SOCKET s, DWORD pid, const WCHAR *processName) {
    if (!g_csReady || s == INVALID_SOCKET) {
        return;
    }

    EnterCriticalSection(&g_cs);
    SOCKET_TRACK *entry = find_socket_by_handle(s);
    if (!entry && g_socketCount < MAX_TRACKED_SOCKETS) {
        entry = &g_sockets[g_socketCount++];
    }
    if (entry) {
        entry->socket = s;
        entry->pid = pid;
        wcsncpy_s(entry->processName, _countof(entry->processName), processName ? processName : L"unknown", _TRUNCATE);
        entry->remoteIp[0] = '\0';
        entry->remotePort = 0;
        entry->totalSent = 0;
        LogDebugA("TrackSocketConnect pid=%lu socket=0x%p", (unsigned long)pid, s);
    }
    LeaveCriticalSection(&g_cs);
}

void Tracking_UpdateSend(SOCKET s, SIZE_T bytes) {
    if (!g_csReady || s == INVALID_SOCKET) {
        return;
    }

    EnterCriticalSection(&g_cs);
    SOCKET_TRACK *entry = find_socket_by_handle(s);
    if (entry) {
        entry->totalSent += bytes;
        LogDebugA("TrackSocketSend socket=0x%p bytes=%llu total=%llu", s, (unsigned long long)bytes, (unsigned long long)entry->totalSent);
    }
    LeaveCriticalSection(&g_cs);
}

void Tracking_RemoveSocket(SOCKET s) {
    if (!g_csReady || s == INVALID_SOCKET) {
        return;
    }

    EnterCriticalSection(&g_cs);
    for (int i = 0; i < g_socketCount; ++i) {
        if (g_sockets[i].socket == s) {
            for (int j = i; j + 1 < g_socketCount; ++j) {
                g_sockets[j] = g_sockets[j + 1];
            }
            ZeroMemory(&g_sockets[g_socketCount - 1], sizeof(g_sockets[g_socketCount - 1]));
            --g_socketCount;
            break;
        }
    }
    LeaveCriticalSection(&g_cs);
}

BOOL CorrelateUpload(DWORD pid, SOCKET s, SIZE_T bytesUploaded) {
    if (!g_csReady || s == INVALID_SOCKET) {
        return FALSE;
    }

    BOOL correlated = FALSE;
    EnterCriticalSection(&g_cs);
    SOCKET_TRACK *socketEntry = find_socket_by_handle(s);
    if (!socketEntry || socketEntry->pid != pid) {
        LeaveCriticalSection(&g_cs);
        return FALSE;
    }

    char remoteIp[INET6_ADDRSTRLEN];
    int remotePort = 0;
    if (!resolve_socket_endpoint(s, remoteIp, sizeof(remoteIp), &remotePort)) {
        if (socketEntry->remoteIp[0] != '\0') {
            strncpy_s(remoteIp, sizeof(remoteIp), socketEntry->remoteIp, _TRUNCATE);
            remotePort = socketEntry->remotePort;
        } else {
            LeaveCriticalSection(&g_cs);
            return FALSE;
        }
    } else {
        strncpy_s(socketEntry->remoteIp, sizeof(socketEntry->remoteIp), remoteIp, _TRUNCATE);
        socketEntry->remotePort = remotePort;
    }

    ULONGLONG now = GetTickCount64();
    FILE_TRACK *bestFile = NULL;
    for (int i = g_fileCount - 1; i >= 0; --i) {
        FILE_TRACK *candidate = &g_files[i];
        if (candidate->pid != pid) {
            continue;
        }
        if (now - candidate->lastReadTick > CORRELATION_WINDOW_MS) {
            continue;
        }
        if (candidate->lastCorrelatedTick >= candidate->lastReadTick) {
            continue;
        }
        bestFile = candidate;
        break;
    }

    if (bestFile) {
        char timestamp[64];
        char processUtf8[MAX_PATH * 4];
        char fileUtf8[MAX_PATH * 4];
        utf16_to_utf8(bestFile->processName, processUtf8, sizeof(processUtf8));
        utf16_to_utf8(bestFile->path, fileUtf8, sizeof(fileUtf8));
        format_timestamp(timestamp, sizeof(timestamp));

        bestFile->lastCorrelatedTick = now;
        correlated = TRUE;
        LogUploadA(processUtf8, pid, remoteIp, remotePort, fileUtf8, bytesUploaded, timestamp);
    }

    LeaveCriticalSection(&g_cs);
    return correlated;
}
