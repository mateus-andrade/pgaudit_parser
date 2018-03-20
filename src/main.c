#include "pgaudit_parser.h"
#include "logger.h"

#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>

int main(int argc, char *argv[]) {

    int opt;
    bool logfile_opt = false;
    char *logfile_path;
    while ((opt = getopt(argc, argv, "l:s:")) != -1) {
        switch (opt) {
            case 'l':
                logfile_opt = true;
                logfile_path = optarg;
                break;
            case 's':
                break;
            default:
                log_fatal("Usage: %s [-l | -s]", argv[0]);
        }
    }

    setup_pgaudit_parser();

    if (logfile_opt == true)
        extract_log_from_file(logfile_path);

    tear_down_pgaudit_parser();

    return 0;
}
