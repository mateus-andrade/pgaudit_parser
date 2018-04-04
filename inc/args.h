#ifndef ARGS_H
#define ARGS_H

#include <stdbool.h>
#include <stdint.h>

typedef struct arguments {
    bool logfile_opt, syslog_opt, is_daemon;
    char *logfile_path, syslog_address[16];
    uint16_t syslog_port;
} args_t;

args_t get_args(int argc, char *argv[]);

#endif /*ARGS_H*/
