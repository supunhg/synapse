#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

typedef struct {
    HANDLE handle;
    WCHAR path[MAX_PATH * 2];
    DWORD pid;
    WCHAR processName[MAX_PATH];
    ULONGLONG lastReadTick;
    SIZE_T totalRead;
    ULONGLONG lastCorrelatedTick;
} FILE_TRACK;

typedef struct {
    SOCKET socket;
    DWORD pid;
    WCHAR processName[MAX_PATH];
    char remoteIp[INET6_ADDRSTRLEN];
    int remotePort;
    SIZE_T totalSent;
} SOCKET_TRACK;

void Tracking_Init(void);
void Tracking_Shutdown(void);

void Tracking_AddFile(HANDLE hFile, const WCHAR *path, DWORD pid, const WCHAR *processName);
void Tracking_UpdateRead(HANDLE hFile, SIZE_T bytes);
void Tracking_RemoveFile(HANDLE hFile);

void Tracking_AddSocket(SOCKET s, DWORD pid, const WCHAR *processName);
void Tracking_UpdateSend(SOCKET s, SIZE_T bytes);
void Tracking_RemoveSocket(SOCKET s);

BOOL CorrelateUpload(DWORD pid, SOCKET s, SIZE_T bytesUploaded);
