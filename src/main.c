#include "pgaudit_parser.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {

    setup_pgaudit_parser();

    //pgaudit = parse_auditlog(auditlog);

    tear_down_pgaudit_parser();

    return 0;
}
