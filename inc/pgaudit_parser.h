
#ifndef PGAUDIT_PARSER_H
#define PGAUDIT_PARSER_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <regex.h>

enum parse_state {
    SESSION,
    SEQUENCE,
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
    char statement[33]; /* Max length pgsql statement */
    char statement_object [128];
    char *db_object;
    char *query;
} auditlog_t;

int setup_pgaudit_parser();
void tear_down_pgaudit_parser();
bool parse_auditlog(char *audit_log, auditlog_t pgaudit);
int get_number(char *auditlog_offset, uint8_t match_len);

#endif
