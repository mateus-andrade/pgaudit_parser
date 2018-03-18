#include "pgaudit_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

int main(int argc, char *argv[]) {

	int opt;
	bool logfile_opt = false, syslog_opt = false;
	char *logfile_path;
	while ((opt = getopt(argc, argv, "l:s:")) != -1) {
		switch (opt) {
			case 'l':
				printf("open file: %s\n", optarg);
				logfile_opt = true;
				logfile_path = optarg;
				break;
			case 's':
				syslog_opt = true;
				// not implemented
				break;
		}
	}

    setup_pgaudit_parser();

	if (logfile_opt == true)
		extract_log_from_file(logfile_path);

    tear_down_pgaudit_parser();

    return 0;
}
