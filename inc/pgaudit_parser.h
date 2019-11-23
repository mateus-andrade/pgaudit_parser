
#ifndef PGAUDIT_PARSER_H
#define PGAUDIT_PARSER_H

#include <arpa/inet.h>
#include <stdint.h>
#include <sys/un.h>

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

typedef struct sock_data {
    auditlog_t pgaudit;
    int sockfd;
    char log_buffer[MAX_LOG_LENGTH];
    char *auditlog_start;
} sock_data;

typedef struct sock_inet {
    sock_data data;
    struct sockaddr_in addr;
} sock_inet;

typedef struct sock_uds {
    sock_data data;
    struct sockaddr_un addr;
} sock_uds;

int setup_pgaudit_parser();
void tear_down_pgaudit_parser();
auditlog_t parse_auditlog(char *audit_log);
void extract_log_from_file(const char *log_file_path);
void extract_log_from_syslog_tcp(const char *endpoint, uint16_t port);
void extract_log_from_syslog_uds(const char *endpoint);
void publish_audit(auditlog_t pgaudit);
#endif
