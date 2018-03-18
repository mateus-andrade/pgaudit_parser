/**
 * @file pgaudit_parser.c
 * @author Mateus Andrade
 *
 * Implementation of a parse for pgaudit logs
 */

#include "pgaudit_parser.h"

static regex_t re;

int setup_pgaudit_parser() {

    if (regcomp(&re, ",[a-zA-Z0-9_. ]+", REG_EXTENDED))
        return 0;

    return 1;
}

static char *get_str(char *auditlog_offset, uint8_t match_len) {
    char *str = malloc(match_len * sizeof(char));
    strncpy(str, auditlog_offset, match_len);
    str[match_len - 1] = '\0';

    return str;
}

static uint32_t get_number(char *auditlog_offset, uint8_t match_len) {

    char *number_str = get_str(auditlog_offset, match_len);
    uint32_t number_ret = atoi(number_str);
    free(number_str);

    return number_ret;
}

auditlog_t parse_auditlog(char *auditlog) {

    regmatch_t pmatch;
    auditlog_t pgaudit;
    enum parse_state parse_state = 0;

    while (regexec(&re, auditlog, 1, &pmatch, 0) == 0) {
        switch (parse_state) {
            case SESSION:
                pgaudit.session = get_number(auditlog + pmatch.rm_so + 1,
                                           pmatch.rm_eo - pmatch.rm_so);
                break;
            case SEQUENCE:
                pgaudit.sequence = get_number(auditlog + pmatch.rm_so + 1,
                                            pmatch.rm_eo - pmatch.rm_so);
                break;
            case STATEMENT_TYPE:
                pgaudit.statement_type = get_str(auditlog + pmatch.rm_so + 1,
                                                 pmatch.rm_eo - pmatch.rm_so);
                break;
            case STATEMENT:
                pgaudit.statement = get_str(auditlog + pmatch.rm_so + 1,
                                            pmatch.rm_eo - pmatch.rm_so);
                break;
            case STATEMENT_OBJ:
                pgaudit.statement_object = get_str(auditlog + pmatch.rm_so + 1,
                                                   pmatch.rm_eo - pmatch.rm_so);
                break;
            case DB_OBJ:
                pgaudit.db_object = get_str(auditlog + pmatch.rm_so + 1,
                                            pmatch.rm_eo - pmatch.rm_so);
                break;
            case QUERY:
                pgaudit.query = get_str(auditlog + pmatch.rm_so + 1,
                                        pmatch.rm_eo - pmatch.rm_so);
                break;
            default:
                break;

        }
        auditlog += pmatch.rm_eo;
        parse_state++;
    }

    return pgaudit;
}

void tear_down_pgaudit_parser() {
    regfree(&re);
}
