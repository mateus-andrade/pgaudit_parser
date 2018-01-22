#include "pgaudit_parser.h"

static regex_t re;

int setup_pgaudit_parser() {

    if (regcomp(&re, ",[a-zA-Z0-9_. ]+", REG_EXTENDED))
        return 0;

    return 1;
}

int get_number(char *auditlog_offset, uint8_t match_len) {

    char *number_str = calloc(match_len, sizeof(char));
    int number_ret;

    strncpy(number_str, auditlog_offset, match_len);
    number_str[match_len - 1] = '\0';

    number_ret = atoi(number_str);

    free(number_str);

    return number_ret;
}

bool parse_auditlog(char *auditlog, auditlog_t pgaudit) {

    regmatch_t pmatch;
    enum parse_state parse_state = 0;
    char *reg_str = auditlog;

    while (regexec(&re, reg_str, 1, &pmatch, 0) == 0) {
        switch (parse_state) {
            case SESSION:
               pgaudit.session = get_number(reg_str + pmatch.rm_so + 1,
                                            pmatch.rm_eo - pmatch.rm_so);
               break;
            case SEQUENCE:
               pgaudit.sequence = get_number(reg_str + pmatch.rm_so + 1,
                                             pmatch.rm_eo - pmatch.rm_so);
               break;
            default:
                break;

        }
        reg_str += pmatch.rm_eo;
        parse_state++;
    }

    return true;
}

void tear_down_pgaudit_parser() {
    regfree(&re);
}
