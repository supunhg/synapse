#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <wmistr.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <wchar.h>
#include <strsafe.h>
#include <time.h>
#include <process.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#define TRACE_SESSION_NAME L"SynapseUploadMonitorQ1"
#define MAX_RECENT_EVENTS 1024
#define MAX_PATH_WIDE 512

static const GUID FileIoGuid = {
    0x90cbdc39, 0x4a3e, 0x11d1,
    { 0xb1, 0x0d, 0x00, 0xa0, 0xc9, 0x06, 0x29, 0xe7 }
};

static const GUID TcpipGuid = {
    0x2f07e2ee, 0x15db, 0x40f1,
    { 0x90, 0xef, 0x1d, 0x66, 0xcb, 0x6d, 0x5a, 0xb8 }
};

#define FILE_IO_WRITE 36
#define FILE_IO_READ  35
#define TCPIP_SEND    10

typedef struct {
    ULONG pid;
    WCHAR process[260];
    WCHAR filepath[MAX_PATH_WIDE];
    ULONG bytes;
    FILETIME timestamp;
} RecentFileEvent;

static RecentFileEvent recent_events[MAX_RECENT_EVENTS];
static LONG recent_count = 0;
static FILE *log_file = NULL;
static TRACEHANDLE trace_handle = 0;
static volatile LONG stop_requested = 0;

static void format_timestamp(FILETIME ft, WCHAR *buf, size_t bufsize)
{
    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);
    StringCchPrintfW(buf, bufsize, L"%04d-%02d-%02d %02d:%02d:%02d",
                     st.wYear, st.wMonth, st.wDay,
                     st.wHour, st.wMinute, st.wSecond);
}

static void format_bytes(ULONG bytes, WCHAR *buf, size_t bufsize)
{
    if (bytes < 1024) {
        StringCchPrintfW(buf, bufsize, L"%luB", bytes);
    } else if (bytes < 1024 * 1024) {
        StringCchPrintfW(buf, bufsize, L"%.0fKB", (double)bytes / 1024.0);
    } else if (bytes < 1024 * 1024 * 1024) {
        StringCchPrintfW(buf, bufsize, L"%.0fMB", (double)bytes / (1024.0 * 1024.0));
    } else {
        StringCchPrintfW(buf, bufsize, L"%.2fGB", (double)bytes / (1024.0 * 1024.0 * 1024.0));
    }
}

static void get_process_name(ULONG pid, WCHAR *name, size_t namesize)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        wcscpy_s(name, namesize, L"unknown");
        return;
    }

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(entry);

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (entry.th32ProcessID == pid) {
                wcscpy_s(name, namesize, entry.szExeFile);
                CloseHandle(snapshot);
                return;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    wcscpy_s(name, namesize, L"unknown");
}

static void log_line(const WCHAR *line)
{
    wprintf(L"%ls", line);
    if (log_file) {
        fwprintf(log_file, L"%ls", line);
        fflush(log_file);
    }
}

static void log_debug_event(const WCHAR *provider, ULONG pid, USHORT event_id, UCHAR opcode, ULONG user_data_length)
{
    WCHAR line[512];
    StringCchPrintfW(line, 512,
                     L"DBG:\tProvider:%ls\tPID:%lu\tEventId:%u\tOpcode:%u\tUserData:%lu\n",
                     provider,
                     pid,
                     (unsigned)event_id,
                     (unsigned)opcode,
                     user_data_length);
    log_line(line);
}

static void log_upload_event(ULONG pid, const WCHAR *process, const WCHAR *filepath, ULONG bytes, const WCHAR *remote_ip, USHORT remote_port)
{
    WCHAR ts_str[64], bytes_str[64];
    FILETIME now_ft;
    GetSystemTimeAsFileTime(&now_ft);
    format_timestamp(now_ft, ts_str, 64);
    format_bytes(bytes, bytes_str, 64);

    WCHAR line[2048];
    StringCchPrintfW(line, 2048,
                     L"%s\tPID:%lu\tTCP\t%ls:%u\tProcess:%ls\tDetectedFile:%ls (%ls)\n",
                     ts_str,
                     pid,
                     remote_ip,
                     (unsigned)remote_port,
                     process,
                     filepath,
                     bytes_str);
    log_line(line);
}

static void store_recent_file_event(ULONG pid, const WCHAR *process, const WCHAR *filepath, ULONG bytes)
{
    LONG index = InterlockedIncrement(&recent_count) - 1;
    if (index < 0) {
        return;
    }

    if (index >= MAX_RECENT_EVENTS) {
        InterlockedExchange(&recent_count, MAX_RECENT_EVENTS);
        return;
    }

    RecentFileEvent *ev = &recent_events[index];
    ev->pid = pid;
    wcscpy_s(ev->process, 260, process);
    wcscpy_s(ev->filepath, MAX_PATH_WIDE, filepath);
    ev->bytes = bytes;
    GetSystemTimeAsFileTime(&ev->timestamp);
}

static void extract_filepath(PEVENT_RECORD pEvent, WCHAR *filepath, size_t fpsize)
{
    if (pEvent->UserData && pEvent->UserDataLength >= sizeof(WCHAR)) {
        size_t copy_len = pEvent->UserDataLength / sizeof(WCHAR);
        if (copy_len >= fpsize) {
            copy_len = fpsize - 1;
        }
        wmemcpy(filepath, (const WCHAR *)pEvent->UserData, copy_len);
        filepath[copy_len] = 0;
    } else {
        wcscpy_s(filepath, fpsize, L"<unknown>");
    }
}

static void extract_network_info(PEVENT_RECORD pEvent, WCHAR *remote_ip, size_t remote_ip_sz, USHORT *remote_port)
{
    if (pEvent->UserData && pEvent->UserDataLength >= 12) {
        const UCHAR *data = (const UCHAR *)pEvent->UserData;
        ULONG daddr = *(const ULONG *)&data[6];
        USHORT dport = *(const USHORT *)&data[10];
        const UCHAR *d = (const UCHAR *)&daddr;
        StringCchPrintfW(remote_ip, remote_ip_sz, L"%d.%d.%d.%d", d[0], d[1], d[2], d[3]);
        *remote_port = ntohs(dport);
    } else {
        wcscpy_s(remote_ip, remote_ip_sz, L"0.0.0.0");
        *remote_port = 0;
    }
}

static void WINAPI event_record_callback(PEVENT_RECORD pEvent)
{
    if (!pEvent) {
        return;
    }

    ULONG pid = pEvent->EventHeader.ProcessId;
    USHORT event_id = pEvent->EventHeader.EventDescriptor.Id;
    WCHAR process[260];
    get_process_name(pid, process, 260);

    if (IsEqualGUID(&pEvent->EventHeader.ProviderId, &FileIoGuid)) {
        log_debug_event(L"FileIo", pid, event_id, pEvent->EventHeader.EventDescriptor.Opcode, pEvent->UserDataLength);
        if (event_id == FILE_IO_WRITE || event_id == FILE_IO_READ) {
            WCHAR filepath[MAX_PATH_WIDE];
            extract_filepath(pEvent, filepath, MAX_PATH_WIDE);
            if (filepath[0] != 0 && wcscmp(filepath, L"<unknown>") != 0) {
                store_recent_file_event(pid, process, filepath, pEvent->UserDataLength);
            }
        }
        return;
    }

    if (IsEqualGUID(&pEvent->EventHeader.ProviderId, &TcpipGuid)) {
        log_debug_event(L"Tcpip", pid, event_id, pEvent->EventHeader.EventDescriptor.Opcode, pEvent->UserDataLength);
        if (event_id == TCPIP_SEND) {
            WCHAR remote_ip[64];
            USHORT remote_port = 0;
            extract_network_info(pEvent, remote_ip, 64, &remote_port);

            for (LONG i = recent_count - 1; i >= 0; i--) {
                if (recent_events[i].pid == pid && recent_events[i].filepath[0] != 0) {
                    log_upload_event(pid, process, recent_events[i].filepath, recent_events[i].bytes, remote_ip, remote_port);
                    break;
                }
            }
        }
    }
}

static BOOL start_etw_session(void)
{
    DWORD needed = sizeof(EVENT_TRACE_PROPERTIES) + 2 * MAX_PATH * sizeof(WCHAR);
    EVENT_TRACE_PROPERTIES *props = (EVENT_TRACE_PROPERTIES *)calloc(1, needed);
    if (!props) {
        return FALSE;
    }

    props->Wnode.BufferSize = needed;
    props->Wnode.ClientContext = 1;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->EnableFlags = 0;
    props->BufferSize = 64;
    props->MinimumBuffers = 20;
    props->MaximumBuffers = 200;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ULONG status = StartTraceW(&trace_handle, TRACE_SESSION_NAME, props);
    if (status == ERROR_ALREADY_EXISTS) {
        ControlTraceW(0, TRACE_SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
        status = StartTraceW(&trace_handle, TRACE_SESSION_NAME, props);
    }

    free(props);

    if (status != ERROR_SUCCESS) {
        wprintf(L"StartTraceW failed: %lu\n", status);
        return FALSE;
    }

    ENABLE_TRACE_PARAMETERS params;
    ZeroMemory(&params, sizeof(params));
    params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;

    EnableTraceEx2(trace_handle, &FileIoGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                   TRACE_LEVEL_VERBOSE, 0, 0, 0, &params);
    EnableTraceEx2(trace_handle, &TcpipGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                   TRACE_LEVEL_VERBOSE, 0, 0, 0, &params);

    return TRUE;
}

static void stop_etw_session(void)
{
    if (trace_handle != 0) {
        ControlTraceW(trace_handle, TRACE_SESSION_NAME, NULL, EVENT_TRACE_CONTROL_STOP);
        trace_handle = 0;
    }
}

static BOOL running_as_admin(void)
{
    BOOL is_admin = FALSE;
    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    PSID admin_group = NULL;

    if (AllocateAndInitializeSid(&nt_authority, 2,
                                 SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS,
                                 0, 0, 0, 0, 0, 0,
                                 &admin_group)) {
        CheckTokenMembership(NULL, admin_group, &is_admin);
        FreeSid(admin_group);
    }

    return is_admin;
}

int wmain(int argc, wchar_t *argv[])
{
    (void)argc;
    (void)argv;

    wprintf(L"ETW Upload Monitor - Starting real file I/O observation\n");
    if (!running_as_admin()) {
        wprintf(L"Administrator privileges are required for ETW file I/O tracing.\n");
        return 1;
    }
    log_file = _wfopen(L"upload_log.txt", L"a, ccs=UTF-8");
    if (log_file) {
        wprintf(L"Logging to upload_log.txt\n");
    }

    if (!start_etw_session()) {
        if (log_file) {
            fclose(log_file);
            log_file = NULL;
        }
        return 1;
    }

    EVENT_TRACE_LOGFILEW log_file_etw;
    ZeroMemory(&log_file_etw, sizeof(log_file_etw));
    log_file_etw.LoggerName = (LPWSTR)TRACE_SESSION_NAME;
    log_file_etw.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log_file_etw.EventRecordCallback = event_record_callback;

    TRACEHANDLE consume_handle = OpenTraceW(&log_file_etw);
    if (consume_handle == INVALID_PROCESSTRACE_HANDLE) {
        wprintf(L"OpenTraceW failed\n");
        stop_etw_session();
        if (log_file) {
            fclose(log_file);
            log_file = NULL;
        }
        return 1;
    }

    wprintf(L"ETW monitoring started successfully\n");
    ProcessTrace(&consume_handle, 1, NULL, NULL);

    CloseTrace(consume_handle);
    stop_etw_session();

    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }

    wprintf(L"ETW monitoring stopped\n");
    return 0;
}
