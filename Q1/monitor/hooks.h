#pragma once

#include <winsock2.h>
#include <windows.h>

BOOL InitializeHooks(void);
VOID UninitializeHooks(void);

void TrackFileOpen(HANDLE hFile, const WCHAR *path);
void TrackFileRead(HANDLE hFile, SIZE_T bytesRead);
void TrackSocketConnect(SOCKET s);
void TrackSocketSend(SOCKET s, SIZE_T bytesSent);
BOOL CorrelateUpload(DWORD pid, SOCKET s, SIZE_T bytesUploaded);
