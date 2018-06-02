#ifndef ARGS_H
#define ARGS_H

#include <stdbool.h>
#include <stdint.h>

#define MAX_ENDPOINT_LEN 32

typedef struct arguments {
    bool logfile_opt;
    bool syslog_tcp_opt;
    bool syslog_uds_opt;
    bool is_daemon;
    char *logfile_path, syslog_endpoint[MAX_ENDPOINT_LEN];
    uint16_t syslog_port;
} args_t;

args_t get_args(int argc, char *argv[]);

#endif /*ARGS_H*/
