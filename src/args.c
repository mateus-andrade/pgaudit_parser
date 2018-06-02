#include "args.h"
#include "logger.h"

#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

args_t get_args(int argc, char *argv[]) {

    int opt;
    args_t args;
    memset(&args, 0, sizeof(args_t));

    while ((opt = getopt(argc, argv, "l:t:u:d")) != -1) {
        switch (opt) {
            case 'l':
                args.logfile_opt = true;
                args.logfile_path = optarg;
                break;
            case 't':
                args.syslog_tcp_opt = true;
                sscanf(optarg, "%[^:]:%" SCNd16, args.syslog_endpoint,
                       &args.syslog_port);
                break;
            case 'u':
                args.syslog_uds_opt = true;
                sscanf(optarg, "%32s", args.syslog_endpoint);
                break;
            case 'd':
                args.is_daemon = true;
                break;
            default:
                log_fatal("Usage: %s [-l | -t ip:port | -u socket_file_path] -d", argv[0]);
        }
    }

    return args;
}
