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

    while ((opt = getopt(argc, argv, "l:s:")) != -1) {
        switch (opt) {
            case 'l':
                args.logfile_opt = true;
                args.logfile_path = optarg;
                break;
            case 's':
                args.syslog_opt = true;
                sscanf(optarg, "%[^:]:%" SCNd16, args.syslog_address,
                       &args.syslog_port);
                break;
            default:
                log_fatal("Usage: %s [-l | -s]", argv[0]);
        }
    }

    return args;
}
