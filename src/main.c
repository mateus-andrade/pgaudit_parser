#include "args.h"
#include "pgaudit_parser.h"
#include "logger.h"

#include <stdio.h>

int main(int argc, char *argv[]) {

    args_t args = get_args(argc, argv);

    setup_pgaudit_parser();

    if (args.syslog_opt)
        extract_log_from_syslog(args.syslog_address, args.syslog_port);
    else if (args.logfile_opt)
        extract_log_from_file(args.logfile_path);
    else
        log_error("Usage: %s [-l | -s]", argv[0]);

    tear_down_pgaudit_parser();

    return 0;
}
