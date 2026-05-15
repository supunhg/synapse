#include "logger.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static HANDLE g_logFile = NULL;

static void write_utf8_line(const char *line) {
    if (!line || !*line) {
        return;
    }

    DWORD written = 0;
    if (g_logFile) {
        WriteFile(g_logFile, line, (DWORD)strlen(line), &written, NULL);
        WriteFile(g_logFile, "\r\n", 2, &written, NULL);
        FlushFileBuffers(g_logFile);
    }
}

void Logger_Init(HMODULE moduleHandle) {
    WCHAR modulePath[MAX_PATH * 2];
    WCHAR logPath[MAX_PATH * 2];

    modulePath[0] = L'\0';
    logPath[0] = L'\0';

    if (!GetModuleFileNameW(moduleHandle, modulePath, _countof(modulePath))) {
        return;
    }

    WCHAR *slash = wcsrchr(modulePath, L'\\');
    if (slash) {
        *(slash + 1) = L'\0';
    }

    swprintf_s(logPath, _countof(logPath), L"%slogs\\uploads.log", modulePath);
    g_logFile = CreateFileW(logPath, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_logFile == INVALID_HANDLE_VALUE) {
        g_logFile = NULL;
    }
}

void Logger_Shutdown(void) {
    if (g_logFile) {
        CloseHandle(g_logFile);
        g_logFile = NULL;
    }
}

static void format_message(char *buffer, size_t bufferCount, const char *prefix, const char *fmt, va_list ap) {
    char body[1024];
    body[0] = '\0';
    vsnprintf(body, sizeof(body), fmt, ap);
    if (prefix && *prefix) {
        snprintf(buffer, bufferCount, "%s%s", prefix, body);
    } else {
        snprintf(buffer, bufferCount, "%s", body);
    }
}

void LogInfoA(const char *fmt, ...) {
    char buffer[2048];
    va_list ap;
    va_start(ap, fmt);
    format_message(buffer, sizeof(buffer), "[info] ", fmt, ap);
    va_end(ap);
    write_utf8_line(buffer);
}

void LogDebugA(const char *fmt, ...) {
    char buffer[2048];
    va_list ap;
    va_start(ap, fmt);
    format_message(buffer, sizeof(buffer), "[debug] ", fmt, ap);
    va_end(ap);
    write_utf8_line(buffer);
}

void LogUploadA(const char *processName, DWORD pid, const char *remoteIp, int remotePort, const char *filePath, SIZE_T bytesUploaded, const char *timestamp) {
    char buffer[4096];
    snprintf(buffer, sizeof(buffer), "[upload] timestamp=%s pid=%lu process=%s remote=%s:%d file=%s bytes=%llu",
             timestamp ? timestamp : "unknown",
             (unsigned long)pid,
             processName ? processName : "unknown",
             remoteIp ? remoteIp : "unknown",
             remotePort,
             filePath ? filePath : "unknown",
             (unsigned long long)bytesUploaded);
    OutputDebugStringA(buffer);
    OutputDebugStringA("\n");
    write_utf8_line(buffer);
}
