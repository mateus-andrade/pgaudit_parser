#include "pgaudit_parser.h"
#include "logger.h"

#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>

int main(int argc, char *argv[]) {

    int opt;
    uint16_t port;
    bool logfile_opt = false, syslog_opt = false;
    char *logfile_path, address[16];

    while ((opt = getopt(argc, argv, "l:s:")) != -1) {
        switch (opt) {
            case 'l':
                logfile_opt = true;
                logfile_path = optarg;
                break;
            case 's':
                syslog_opt = true;
                sscanf(optarg, "%[^:]:%" SCNd16, address, &port);
                break;
            default:
                log_fatal("Usage: %s [-l | -s]", argv[0]);
        }
    }

    setup_pgaudit_parser();

    if (syslog_opt == true)
        extract_log_from_syslog(address, port);
    else if (logfile_opt == true)
        extract_log_from_file(logfile_path);
    else
        log_error("Usage: %s [-l | -s]", argv[0]);

    tear_down_pgaudit_parser();

    return 0;
}
