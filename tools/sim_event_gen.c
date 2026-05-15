#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include "../Q1/include/correlator.h"

static uint64_t now_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec;
}

int main(void) {
    correlator_init();

    FileEvent fe = {0};
    fe.pid = 18376;
    strncpy(fe.process_name, "firefox.exe", sizeof(fe.process_name)-1);
    strncpy(fe.filepath, "C:\\Users\\Lanka\\AppData\\Local\\Temp\\test.dat", sizeof(fe.filepath)-1);
    fe.timestamp_us = now_us();
    fe.bytes = 300ULL * 1024ULL * 1024ULL; /* 300 MB */
    correlator_feed_file_event(&fe);

    sleep(1);

    NetEvent ne = {0};
    ne.pid = 18376;
    strncpy(ne.process_name, "firefox.exe", sizeof(ne.process_name)-1);
    strncpy(ne.remote_ip, "165.22.221.132", sizeof(ne.remote_ip)-1);
    ne.remote_port = 443;
    ne.timestamp_us = now_us();
    ne.bytes = fe.bytes;
    correlator_feed_net_event(&ne);

    correlator_shutdown();
    return 0;
}
