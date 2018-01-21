#include "pgaudit_parser.h"

static regex_t re;

int setup_pgaudit_parser() {

    if (regcomp(&re, ",[a-zA-Z0-9_. ]+", REG_EXTENDED))
        return 0;

    return 1;
}

void tear_down_pgaudit_parser() {
    regfree(&re);
}

auditlog_t parse_audit_log(char *audit_log) {

}
