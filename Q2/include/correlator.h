#ifndef CORRELATOR_H
#define CORRELATOR_H

#include <stdint.h>

typedef struct {
    uint32_t pid;
    char process_name[256];
    char filepath[512];
    uint64_t timestamp_us; /* microseconds since epoch */
    uint64_t bytes; /* bytes read/uploaded */
} FileEvent;

typedef struct {
    uint32_t pid;
    char process_name[256];
    char remote_ip[64];
    uint16_t remote_port;
    uint64_t timestamp_us; /* microseconds since epoch */
    uint64_t bytes; /* bytes transferred */
} NetEvent;

/* Initialize the correlator (call once) */
void correlator_init(void);

/* Feed events into the correlator */
void correlator_feed_file_event(const FileEvent *ev);
void correlator_feed_net_event(const NetEvent *ev);

/* Shutdown and free resources */
void correlator_shutdown(void);

#endif /* CORRELATOR_H */
