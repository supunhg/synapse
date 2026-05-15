#pragma once

#include <windows.h>

void Logger_Init(HMODULE moduleHandle);
void Logger_Shutdown(void);

void LogInfoA(const char *fmt, ...);
void LogDebugA(const char *fmt, ...);
void LogUploadA(const char *processName, DWORD pid, const char *remoteIp, int remotePort, const char *filePath, SIZE_T bytesUploaded, const char *timestamp);
