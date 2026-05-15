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

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

static const GUID FileIoGuid = {
    0x90cbdc39, 0x4a3e, 0x11d1,
    { 0xb1, 0x0d, 0x00, 0xa0, 0xc9, 0x06, 0x29, 0xe7 }
};

static const GUID TcpipGuid = {
    0x2f07e2ee, 0x15db, 0x40f1,
    { 0x90, 0xef, 0x1d, 0x66, 0xcb, 0x6d, 0x5a, 0xb8 }
};

#define FILE_IO_CREATE 32
#define FILE_IO_WRITE  36
#define FILE_IO_READ   35
#define TCPIP_SEND     10

typedef struct {
    ULONG pid;
    WCHAR process[256];
    WCHAR filepath[512];
    WCHAR local_ip[64];
    USHORT local_port;
    WCHAR remote_ip[64];
    USHORT remote_port;
    ULONG bytes;
    FILETIME timestamp;
} EventRecord;

#define MAX_EVENTS 1000
static EventRecord event_buffer[MAX_EVENTS];
static int event_count = 0;
static FILE *log_file = NULL;

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
    if (bytes < 1024)
        StringCchPrintfW(buf, bufsize, L"%luB", bytes);
    else if (bytes < 1024 * 1024)
        StringCchPrintfW(buf, bufsize, L"%.0fKB", (double)bytes / 1024.0);
    else if (bytes < 1024 * 1024 * 1024)
        StringCchPrintfW(buf, bufsize, L"%.0fMB", (double)bytes / (1024.0 * 1024.0));
    else
        StringCchPrintfW(buf, bufsize, L"%.2fGB", (double)bytes / (1024.0 * 1024.0 * 1024.0));
}

static void log_upload_event(EventRecord *ev)
{
    WCHAR ts_str[64], bytes_str[64];
    format_timestamp(ev->timestamp, ts_str, 64);
    format_bytes(ev->bytes, bytes_str, 64);

    WCHAR line[2048];
    StringCchPrintfW(line, 2048,
                     L"%s\tPID:%lu\tTCP\t%s:%u\t%s:%u\tProcess:%s\tDetectedFile:%s (%s)\n",
                     ts_str,
                     ev->pid,
                     ev->local_ip,
                     (unsigned)ev->local_port,
                     ev->remote_ip,
                     (unsigned)ev->remote_port,
                     ev->process,
                     ev->filepath,
                     bytes_str);

    if (log_file) {
        fwprintf(log_file, line);
        fflush(log_file);
    }
    wprintf(line);
    fflush(stdout);
}

static void get_process_name(ULONG pid, WCHAR *name, size_t namesize)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        wcscpy_s(name, namesize, L"unknown");
        return;
    }

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

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
static void extract_filepath(PEVENT_RECORD pEvent, WCHAR *filepath, size_t fpsize)
{
    if (pEvent->UserDataLength >= 256) {
        wmemcpy(filepath, (WCHAR *)pEvent->UserData, min(256, fpsize - 1));
        filepath[fpsize - 1] = 0;
    } else {
        wcscpy_s(filepath, fpsize, L"<unknown>");
    }
}

static void extract_network_info(PEVENT_RECORD pEvent, WCHAR *local_ip, size_t local_ip_sz,
                                  USHORT *local_port, WCHAR *remote_ip, size_t remote_ip_sz,
                                  USHORT *remote_port)
{
    if (pEvent->UserDataLength >= 12) {
        UCHAR *data = (UCHAR *)pEvent->UserData;
        ULONG saddr = *(ULONG *)&data[0];
        USHORT sport = *(USHORT *)&data[4];
        ULONG daddr = *(ULONG *)&data[6];
        USHORT dport = *(USHORT *)&data[10];

        UCHAR *s = (UCHAR *)&saddr;
        StringCchPrintfW(local_ip, local_ip_sz, L"%d.%d.%d.%d", s[0], s[1], s[2], s[3]);
        *local_port = ntohs(sport);

        UCHAR *d = (UCHAR *)&daddr;
        StringCchPrintfW(remote_ip, remote_ip_sz, L"%d.%d.%d.%d", d[0], d[1], d[2], d[3]);
        *remote_port = ntohs(dport);
    } else {
        wcscpy_s(local_ip, local_ip_sz, L"0.0.0.0");
        *local_port = 0;
        wcscpy_s(remote_ip, remote_ip_sz, L"0.0.0.0");
        *remote_port = 0;
    }
}

static void store_event(ULONG pid, const WCHAR *process, const WCHAR *filepath,
                       const WCHAR *local_ip, USHORT local_port,
                       const WCHAR *remote_ip, USHORT remote_port, ULONG bytes)
{
    if (event_count >= MAX_EVENTS)
        return;

    EventRecord *ev = &event_buffer[event_count++];
    ev->pid = pid;
    wcscpy_s(ev->process, 256, process);
    wcscpy_s(ev->filepath, 512, filepath);
    wcscpy_s(ev->local_ip, 64, local_ip);
    ev->local_port = local_port;
    wcscpy_s(ev->remote_ip, 64, remote_ip);
    ev->remote_port = remote_port;
    ev->bytes = bytes;
    GetSystemTimeAsFileTime(&ev->timestamp);
}

static void maybe_report_upload(ULONG pid, const WCHAR *filepath)
{
    for (int i = event_count - 1; i >= 0; i--) {
        if (event_buffer[i].pid == pid && event_buffer[i].remote_ip[0] != 0 &&
            event_buffer[i].local_ip[0] != 0) {
            log_upload_event(&event_buffer[i]);
            return;
        }
    }
}

static VOID WINAPI event_record_callback(PEVENT_RECORD pEvent)
{
    if (pEvent == NULL)
        return;

    ULONG pid = pEvent->EventHeader.ProcessId;
    USHORT event_id = pEvent->EventHeader.EventDescriptor.Id;
    WCHAR process[256], filepath[512];
    WCHAR local_ip[64], remote_ip[64];
    USHORT local_port, remote_port;
    ULONG bytes;

    get_process_name(pid, process, 256);

    if (IsEqualGUID(&pEvent->EventHeader.ProviderId, &FileIoGuid)) {
        if (event_id == FILE_IO_WRITE || event_id == FILE_IO_READ) {
            extract_filepath(pEvent, filepath, 512);
            bytes = pEvent->UserDataLength;
            store_event(pid, process, filepath, L"", 0, L"", 0, bytes);
        }
    }
    else if (IsEqualGUID(&pEvent->EventHeader.ProviderId, &TcpipGuid)) {
        if (event_id == TCPIP_SEND) {
            extract_network_info(pEvent, local_ip, 64, &local_port, remote_ip, 64, &remote_port);
            bytes = pEvent->UserDataLength;
            store_event(pid, process, L"", local_ip, local_port, remote_ip, remote_port, bytes);
            
            for (int i = event_count - 2; i >= 0; i--) {
                if (event_buffer[i].pid == pid && event_buffer[i].filepath[0] != 0) {
                    wcscpy_s(event_buffer[event_count - 1].filepath, 512, event_buffer[i].filepath);
                    log_upload_event(&event_buffer[event_count - 1]);
                    break;
                }
            }
        }
    }
}

static TRACEHANDLE start_trace(const WCHAR *session_name)
{
    EVENT_TRACE_PROPERTIES props = {0};
    props.Wnode.BufferSize = sizeof(EVENT_TRACE_PROPERTIES);
    props.Wnode.ClientContext = 1;
    props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props.EnableFlags = EVENT_TRACE_FLAG_FILE_IO | EVENT_TRACE_FLAG_NETWORK_TCPIP;
    props.BufferSize = 64;
    props.MinimumBuffers = 20;
    props.MaximumBuffers = 500;

    TRACEHANDLE trace_handle = 0;
    ULONG status = StartTraceW(&trace_handle, session_name, &props);
    
    if (status == ERROR_ALREADY_EXISTS) {
        ControlTraceW(trace_handle, session_name, &props, EVENT_TRACE_CONTROL_STOP);
        status = StartTraceW(&trace_handle, session_name, &props);
    }

    if (status != ERROR_SUCCESS) {
        wprintf(L"StartTraceW failed: 0x%08X\n", status);
        return 0;
    }

    return trace_handle;
}

static ULONG enable_providers(TRACEHANDLE trace_handle)
{
    ENABLE_TRACE_PARAMETERS params = {0};
    params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;

    ULONG status = EnableTraceEx2(trace_handle, &FileIoGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                  TRACE_LEVEL_VERBOSE, 0, 0, 0, &params);
    if (status != ERROR_SUCCESS)
        wprintf(L"EnableTraceEx2 (FileIO) failed: 0x%08X\n", status);

    status = EnableTraceEx2(trace_handle, &TcpipGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                           TRACE_LEVEL_VERBOSE, 0, 0, 0, &params);
    if (status != ERROR_SUCCESS)
        wprintf(L"EnableTraceEx2 (TCPIP) failed: 0x%08X\n", status);

    return status;
}

int wmain(int argc, WCHAR *argv[])
{
    wprintf(L"ETW Upload Monitor - Starting (requires Administrator)\n");

    errno_t err = _wfopen_s(&log_file, L"upload_log.txt", L"a");
    if (err != 0 || log_file == NULL) {
        wprintf(L"Failed to open log file. Continuing without file output.\n");
    } else {
        wprintf(L"Logging to upload_log.txt\n");
    }

    const WCHAR *session_name = L"SynapseMonitor";
    TRACEHANDLE trace_handle = start_trace(session_name);

    if (trace_handle == 0) {
        wprintf(L"Failed to start trace. Run as Administrator.\n");
        if (log_file) fclose(log_file);
        return 1;
    }

    if (enable_providers(trace_handle) != ERROR_SUCCESS) {
        wprintf(L"Failed to enable providers.\n");
        ControlTraceW(trace_handle, session_name, NULL, EVENT_TRACE_CONTROL_STOP);
        if (log_file) fclose(log_file);
        return 1;
    }

    wprintf(L"Monitoring file uploads... (Ctrl+C to stop)\n");

    EVENT_TRACE_LOGFILEW log_file_etw = {0};
    log_file_etw.LoggerName = (LPWSTR)session_name;
    log_file_etw.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log_file_etw.EventRecordCallback = event_record_callback;

    TRACEHANDLE consume_handle = OpenTraceW(&log_file_etw);
    if (consume_handle == INVALID_PROCESSTRACE_HANDLE) {
        wprintf(L"OpenTraceW failed: %ld\n", GetLastError());
        ControlTraceW(trace_handle, session_name, NULL, EVENT_TRACE_CONTROL_STOP);
        if (log_file) fclose(log_file);
        return 1;
    }

    ProcessTrace(&consume_handle, 1, 0, 0);

    CloseTrace(consume_handle);
    ControlTraceW(trace_handle, session_name, NULL, EVENT_TRACE_CONTROL_STOP);

    if (log_file) fclose(log_file);

    wprintf(L"Monitoring stopped.\n");
    return 0;
}
