
#ifndef PGAUDIT_PARSER_H
#define PGAUDIT_PARSER_H

#include <stdint.h>

#define MAX_LOG_LENGTH 4096

enum parse_state {
    SEQUENCE,
    SESSION,
    STATEMENT_TYPE,
    STATEMENT,
    QUERY
};

typedef struct timestamp {
    char date[11];  /* aaaa-mm-dd */
    char hour[9];   /* hh:mm:ss */
} timestamp_t;

typedef struct auditlog {
    uint16_t sequence;
    uint16_t session;
    char *statement_type;
    char *statement;
    char *query;
} auditlog_t;

int setup_pgaudit_parser();
void tear_down_pgaudit_parser();
auditlog_t parse_auditlog(char *audit_log);
void extract_log_from_file(const char *log_file_path);
void extract_log_from_syslog(const char *address, uint16_t port);
#endif
