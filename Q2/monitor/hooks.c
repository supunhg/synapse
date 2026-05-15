#include <winsock2.h>
#include <ws2tcpip.h>

#include "hooks.h"
#include "logger.h"
#include "tracking.h"

#include <stdio.h>
#include <stdarg.h>

#include "../third_party/MinHook/include/MinHook.h"

typedef HANDLE (WINAPI *CreateFileW_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL (WINAPI *ReadFile_t)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef int (WSAAPI *connect_t)(SOCKET, const struct sockaddr*, int);
typedef int (WSAAPI *send_t)(SOCKET, const char*, int, int);
typedef int (WSAAPI *WSASend_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *closesocket_t)(SOCKET);

static CreateFileW_t g_realCreateFileW = NULL;
static ReadFile_t g_realReadFile = NULL;
static connect_t g_realConnect = NULL;
static send_t g_realSend = NULL;
static WSASend_t g_realWSASend = NULL;
static closesocket_t g_realCloseSocket = NULL;
static volatile LONG g_hooksReady = 0;

static void get_process_name_a(char *buffer, size_t bufferCount) {
    WCHAR path[MAX_PATH * 2];
    WCHAR *base = NULL;
    if (!buffer || bufferCount == 0) {
        return;
    }
    buffer[0] = '\0';
    if (!GetModuleFileNameW(NULL, path, _countof(path))) {
        return;
    }
    base = wcsrchr(path, L'\\');
    base = base ? base + 1 : path;
    WideCharToMultiByte(CP_UTF8, 0, base, -1, buffer, (int)bufferCount, NULL, NULL);
}

static void debug_u8(const char *fmt, ...) {
    char buffer[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, ap);
    va_end(ap);
    OutputDebugStringA(buffer);
    OutputDebugStringA("\n");
}

static BOOL resolve_socket_peer(SOCKET s, char *ipbuf, size_t ipbuflen, int *port) {
    struct sockaddr_storage addr;
    int addrlen = sizeof(addr);
    ipbuf[0] = '\0';
    *port = 0;

    if (getpeername(s, (struct sockaddr *)&addr, &addrlen) != 0) {
        return FALSE;
    }

    if (addr.ss_family == AF_INET) {
        struct sockaddr_in *a = (struct sockaddr_in *)&addr;
        if (!inet_ntop(AF_INET, &a->sin_addr, ipbuf, (socklen_t)ipbuflen)) {
            return FALSE;
        }
        *port = ntohs(a->sin_port);
        return TRUE;
    }

    if (addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&addr;
        if (!inet_ntop(AF_INET6, &a->sin6_addr, ipbuf, (socklen_t)ipbuflen)) {
            return FALSE;
        }
        *port = ntohs(a->sin6_port);
        return TRUE;
    }

    return FALSE;
}

static HANDLE WINAPI hk_CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    HANDLE result = g_realCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    if (result != INVALID_HANDLE_VALUE) {
        char pathUtf8[MAX_PATH * 4];
        char procUtf8[MAX_PATH];
        WideCharToMultiByte(CP_UTF8, 0, lpFileName ? lpFileName : L"", -1, pathUtf8, (int)sizeof(pathUtf8), NULL, NULL);
        get_process_name_a(procUtf8, sizeof(procUtf8));
        debug_u8("[hook] CreateFileW process=%s handle=0x%p file=%s access=0x%lx", procUtf8, result, pathUtf8, (unsigned long)dwDesiredAccess);
        TrackFileOpen(result, lpFileName);
    }
    return result;
}

static BOOL WINAPI hk_ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
    BOOL result = g_realReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    if (result && lpNumberOfBytesRead && *lpNumberOfBytesRead > 0) {
        char procUtf8[MAX_PATH];
        get_process_name_a(procUtf8, sizeof(procUtf8));
        debug_u8("[hook] ReadFile process=%s handle=0x%p bytes=%lu", procUtf8, hFile, (unsigned long)*lpNumberOfBytesRead);
        TrackFileRead(hFile, (SIZE_T)*lpNumberOfBytesRead);
    }
    return result;
}

static int WSAAPI hk_connect(SOCKET s, const struct sockaddr *name, int namelen) {
    (void)name;
    (void)namelen;
    int result = g_realConnect(s, name, namelen);
    if (result == 0) {
        char ip[INET6_ADDRSTRLEN];
        int port = 0;
        if (resolve_socket_peer(s, ip, sizeof(ip), &port)) {
            char procUtf8[MAX_PATH];
            get_process_name_a(procUtf8, sizeof(procUtf8));
            debug_u8("[hook] connect process=%s socket=0x%p remote=%s:%d", procUtf8, s, ip, port);
        } else {
            debug_u8("[hook] connect process socket=0x%p remote unresolved", s);
        }
        TrackSocketConnect(s);
    }
    return result;
}

static int WSAAPI hk_send(SOCKET s, const char *buf, int len, int flags) {
    (void)buf;
    (void)len;
    (void)flags;
    int result = g_realSend(s, buf, len, flags);
    if (result > 0) {
        char procUtf8[MAX_PATH];
        get_process_name_a(procUtf8, sizeof(procUtf8));
        debug_u8("[hook] send process=%s socket=0x%p bytes=%d", procUtf8, s, result);
        TrackSocketSend(s, (SIZE_T)result);
        CorrelateUpload(GetCurrentProcessId(), s, (SIZE_T)result);
    }
    return result;
}

static int WSAAPI hk_WSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    int result = g_realWSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
    if (result == 0 && lpNumberOfBytesSent && *lpNumberOfBytesSent > 0) {
        char procUtf8[MAX_PATH];
        get_process_name_a(procUtf8, sizeof(procUtf8));
        debug_u8("[hook] WSASend process=%s socket=0x%p bytes=%lu", procUtf8, s, (unsigned long)*lpNumberOfBytesSent);
        TrackSocketSend(s, (SIZE_T)*lpNumberOfBytesSent);
        CorrelateUpload(GetCurrentProcessId(), s, (SIZE_T)*lpNumberOfBytesSent);
    }
    return result;
}

static int WSAAPI hk_closesocket(SOCKET s) {
    char procUtf8[MAX_PATH];
    get_process_name_a(procUtf8, sizeof(procUtf8));
    debug_u8("[hook] closesocket process=%s socket=0x%p", procUtf8, s);
    Tracking_RemoveSocket(s);
    return g_realCloseSocket(s);
}

static BOOL install_one_hook(LPVOID target, LPVOID detour, LPVOID *original, const char *name) {
    MH_STATUS status = MH_CreateHook(target, detour, original);
    if (status != MH_OK) {
        LogDebugA("MH_CreateHook failed for %s status=%d", name, (int)status);
        return FALSE;
    }
    status = MH_EnableHook(target);
    if (status != MH_OK) {
        LogDebugA("MH_EnableHook failed for %s status=%d", name, (int)status);
        return FALSE;
    }
    LogDebugA("Installed hook for %s", name);
    return TRUE;
}

BOOL InitializeHooks(void) {
    if (InterlockedCompareExchange(&g_hooksReady, 1, 0) != 0) {
        return TRUE;
    }

    if (MH_Initialize() != MH_OK) {
        LogInfoA("MH_Initialize failed");
        InterlockedExchange(&g_hooksReady, 0);
        return FALSE;
    }

    if (!install_one_hook((LPVOID)CreateFileW, (LPVOID)hk_CreateFileW, (LPVOID *)&g_realCreateFileW, "CreateFileW")) goto fail;
    if (!install_one_hook((LPVOID)ReadFile, (LPVOID)hk_ReadFile, (LPVOID *)&g_realReadFile, "ReadFile")) goto fail;
    if (!install_one_hook((LPVOID)connect, (LPVOID)hk_connect, (LPVOID *)&g_realConnect, "connect")) goto fail;
    if (!install_one_hook((LPVOID)send, (LPVOID)hk_send, (LPVOID *)&g_realSend, "send")) goto fail;
    if (!install_one_hook((LPVOID)WSASend, (LPVOID)hk_WSASend, (LPVOID *)&g_realWSASend, "WSASend")) goto fail;
    if (!install_one_hook((LPVOID)closesocket, (LPVOID)hk_closesocket, (LPVOID *)&g_realCloseSocket, "closesocket")) goto fail;

    LogInfoA("InitializeHooks: all hooks installed");
    return TRUE;

fail:
    UninitializeHooks();
    InterlockedExchange(&g_hooksReady, 0);
    return FALSE;
}

VOID UninitializeHooks(void) {
    MH_DisableHook((LPVOID)CreateFileW);
    MH_DisableHook((LPVOID)ReadFile);
    MH_DisableHook((LPVOID)connect);
    MH_DisableHook((LPVOID)send);
    MH_DisableHook((LPVOID)WSASend);
    MH_DisableHook((LPVOID)closesocket);

    MH_RemoveHook((LPVOID)CreateFileW);
    MH_RemoveHook((LPVOID)ReadFile);
    MH_RemoveHook((LPVOID)connect);
    MH_RemoveHook((LPVOID)send);
    MH_RemoveHook((LPVOID)WSASend);
    MH_RemoveHook((LPVOID)closesocket);
    MH_Uninitialize();
    InterlockedExchange(&g_hooksReady, 0);
    LogInfoA("UninitializeHooks: hooks removed");
}

void TrackFileOpen(HANDLE hFile, const WCHAR *path) {
    WCHAR processPath[MAX_PATH * 2];
    WCHAR *base = NULL;

    if (!hFile || hFile == INVALID_HANDLE_VALUE) {
        return;
    }

    if (!GetModuleFileNameW(NULL, processPath, _countof(processPath))) {
        base = L"unknown";
    } else {
        base = wcsrchr(processPath, L'\\');
        base = base ? base + 1 : processPath;
    }

    Tracking_AddFile(hFile, path, GetCurrentProcessId(), base);
}

void TrackFileRead(HANDLE hFile, SIZE_T bytes) {
    if (!hFile || hFile == INVALID_HANDLE_VALUE) {
        return;
    }
    Tracking_UpdateRead(hFile, bytes);
}

void TrackSocketConnect(SOCKET s) {
    WCHAR processPath[MAX_PATH * 2];
    WCHAR *base = NULL;

    if (s == INVALID_SOCKET) {
        return;
    }

    if (!GetModuleFileNameW(NULL, processPath, _countof(processPath))) {
        base = L"unknown";
    } else {
        base = wcsrchr(processPath, L'\\');
        base = base ? base + 1 : processPath;
    }

    Tracking_AddSocket(s, GetCurrentProcessId(), base);
}

void TrackSocketSend(SOCKET s, SIZE_T bytesSent) {
    if (s == INVALID_SOCKET) {
        return;
    }
    Tracking_UpdateSend(s, bytesSent);
}

static DWORD WINAPI bootstrap_thread(LPVOID parameter) {
    Logger_Init((HMODULE)parameter);
    Tracking_Init();
    InitializeHooks();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    (void)lpReserved;
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            CreateThread(NULL, 0, bootstrap_thread, hModule, 0, NULL);
            break;
        case DLL_PROCESS_DETACH:
            if (InterlockedCompareExchange(&g_hooksReady, 0, 0) != 0) {
                UninitializeHooks();
            }
            Tracking_Shutdown();
            Logger_Shutdown();
            break;
    }
    return TRUE;
}