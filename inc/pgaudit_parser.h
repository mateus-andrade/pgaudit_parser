
#ifndef PGAUDIT_PARSER_H
#define PGAUDIT_PARSER_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <regex.h>

#define MAX_LOG_LENGTH 4096

enum parse_state {
    SESSION,
    SEQUENCE,
    STATEMENT_TYPE,
    STATEMENT,
    STATEMENT_OBJ,
    DB_OBJ,
    QUERY
};

typedef struct timestamp {
    char date[11];  /* aaaa-mm-dd */
    char hour[9];   /* hh:mm:ss */
} timestamp_t;

typedef struct auditlog {
    uint16_t session;
    uint16_t sequence;
    char *statement_type;
    char *statement;
    char *statement_object;
    char *db_object;
    char *query;
} auditlog_t;

int setup_pgaudit_parser();
void tear_down_pgaudit_parser();
auditlog_t parse_auditlog(char *audit_log);
void extract_log_from_file(const char* log_file_path);

#endif
