#include "args.h"
#include "daemonize.h"
#include "pgaudit_parser.h"
#include "logger.h"

#include <stdio.h>

int main(int argc, char *argv[]) {

    args_t args = get_args(argc, argv);

    if (args.is_daemon)
        daemonize();

    setup_pgaudit_parser();

    if (args.syslog_tcp_opt)
        extract_log_from_syslog_tcp(args.syslog_endpoint, args.syslog_port);
    else if (args.syslog_uds_opt)
        extract_log_from_syslog_uds(args.syslog_endpoint);
    else if (args.logfile_opt)
        extract_log_from_file(args.logfile_path);
    else
        log_error("Usage: %s [-l log_file_path | -t address:port |"
                  "-u sock_file] -d", argv[0]);

    tear_down_pgaudit_parser();

    return 0;
}
