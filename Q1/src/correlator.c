#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include "../include/correlator.h"

/* Simple in-memory correlator implementation for prototype/testing.
 * Not thread-safe; intended as a single-threaded test harness.
 */

static FileEvent file_events[512];
static size_t file_events_count = 0;

static const uint64_t MATCH_WINDOW_US = 5ULL * 1000ULL * 1000ULL; /* 5 seconds */

static void format_timestamp(uint64_t ts_us, char *out, size_t out_sz) {
    time_t secs = (time_t)(ts_us / 1000000ULL);
    struct tm tm;
    localtime_r(&secs, &tm);
    int usec = (int)(ts_us % 1000000ULL);
    snprintf(out, out_sz, "%04d-%02d-%02d %02d:%02d:%02d",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec);
}

static const char *human_bytes(uint64_t bytes, char *buf, size_t bufsz) {
    const char *units[] = {"B","KB","MB","GB","TB"};
    double v = (double)bytes;
    int i = 0;
    while (v >= 1024.0 && i < 4) { v /= 1024.0; i++; }
    snprintf(buf, bufsz, "%.2f%s", v, units[i]);
    return buf;
}

void correlator_init(void) {
    file_events_count = 0;
}

void correlator_feed_file_event(const FileEvent *ev) {
    if (file_events_count < sizeof(file_events)/sizeof(file_events[0])) {
        file_events[file_events_count++] = *ev;
    }
}

void correlator_feed_net_event(const NetEvent *nev) {
    /* Search recent file events for same pid within window. If found, report upload. */
    for (size_t i = 0; i < file_events_count; ++i) {
        FileEvent *fe = &file_events[i];
        if (fe->pid != nev->pid) continue;
        uint64_t diff = (nev->timestamp_us > fe->timestamp_us) ? (nev->timestamp_us - fe->timestamp_us) : (fe->timestamp_us - nev->timestamp_us);
        if (diff <= MATCH_WINDOW_US) {
            char ts_str[64];
            format_timestamp(nev->timestamp_us, ts_str, sizeof(ts_str));
            char hbytes[64];
            human_bytes(nev->bytes, hbytes, sizeof(hbytes));
            printf("%s PID:%u %s:%u Process:%s DetectedFile:%s (%s)\n",
                   ts_str,
                   nev->pid,
                   nev->remote_ip,
                   (unsigned)nev->remote_port,
                   (nev->process_name[0] ? nev->process_name : fe->process_name),
                   fe->filepath,
                   hbytes);
            fflush(stdout);
            return;
        }
    }
    /* If no matching file event, still optionally log connection */
    char ts_str[64];
    format_timestamp(nev->timestamp_us, ts_str, sizeof(ts_str));
    char hbytes[64];
    human_bytes(nev->bytes, hbytes, sizeof(hbytes));
    printf("%s PID:%u %s:%u Process:%s DetectedFile:%s (%s)\n",
           ts_str,
           nev->pid,
           nev->remote_ip,
           (unsigned)nev->remote_port,
           nev->process_name[0] ? nev->process_name : "unknown",
           "<unknown>",
           hbytes);
    fflush(stdout);
}

void correlator_shutdown(void) {
    /* no-op for prototype */
}
