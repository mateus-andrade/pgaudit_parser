
#ifndef PGAUDIT_PARSER_H
#define PGAUDIT_PARSER_H

#include <stdint.h>
#include <regex.h>

enum type_method {
    DDL,
    DML
};

typedef struct timestamp {
    char date[11];  /* aaaa-mm-dd */
    char hour[9];   /* hh:mm:ss */
} timestamp_t;

typedef struct auditlog {
    uint16_t session;
    uint16_t sequence;
    enum type_method type_method;
    char statement[33]; /* Max length pgsql statement */
    char statement_object [128];
    char *db_object;
    char *query;
} auditlog_t;

int setup_pgaudit_parser();
void tear_down_pgaudit_parser();
auditlog_t parse_audit_log(char *audit_log);

#endif
