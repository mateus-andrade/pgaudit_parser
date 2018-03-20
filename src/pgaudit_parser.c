/**
 * @file pgaudit_parser.c
 * @author Mateus Andrade
 *
 * Implementation of a parse for pgaudit logs
 */

#include "logger.h"
#include "pgaudit_parser.h"

#include <regex.h>
#include <stdlib.h>
#include <string.h>

static regex_t re;

int setup_pgaudit_parser(void) {

    if (regcomp(&re, ",[a-zA-Z0-9_. ]+", REG_EXTENDED))
        return 0;

    log_info("Setting up PGAudit log parser...");

    return 1;
}

static char *get_str(char *auditlog_offset, uint8_t match_len) {
    char *str = malloc(match_len * sizeof(char));

    if (str == NULL)
        log_fatal("Cannot alloc memory, aborting...");

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

void pgaudit_freer(auditlog_t *pgaudit) {
    free(pgaudit->statement_type);
    free(pgaudit->statement);
    free(pgaudit->query);
    memset(pgaudit, 0, sizeof(auditlog_t));
}

void extract_log_from_file(const char* log_file_path) {
    char auditlog[MAX_LOG_LENGTH], *auditlog_start = NULL;
    auditlog_t pgaudit;
    FILE *f = fopen(log_file_path, "r");

    if (f == NULL)
        log_fatal("Impossible to open file: %s", log_file_path);

    log_info("Opening log file: %s", log_file_path);

    while (fgets(auditlog, MAX_LOG_LENGTH, f)) {
        auditlog_start = strstr(auditlog, "AUDIT");
        if (auditlog_start != NULL) {
            pgaudit = parse_auditlog(auditlog_start);
            pgaudit_freer(&pgaudit);
        }
    }

    fclose(f);
}

void tear_down_pgaudit_parser(void) {
    log_info("Tear down PGAudit log parser...");
    regfree(&re);
}
