/**
 * @file pgaudit_parser.c
 * @author Mateus Andrade
 *
 * Implementation of a parse for pgaudit logs from syslog uds and tcp outputs
 */

#include "args.h"
#include "logger.h"
#include "pgaudit_parser.h"

#include <netinet/in.h>
#include <inttypes.h>
#include <jansson.h>
#include <regex.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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

void publish_audit(auditlog_t pgaudit) {
    char *audit_json = NULL;
    json_t *root = json_object();

    json_object_set_new(root, "session", json_integer(pgaudit.session));
    json_object_set_new(root, "sequence", json_integer(pgaudit.sequence));
    json_object_set_new(root, "statement_type",
                        json_string(pgaudit.statement_type));
    json_object_set_new(root, "statement", json_string(pgaudit.statement));
    json_object_set_new(root, "query", json_string(pgaudit.query));

    audit_json = json_dumps(root, 0);
    json_decref(root);
}

void extract_log_from_file(const char *log_file_path) {
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
            publish_audit(pgaudit);
            pgaudit_freer(&pgaudit);
            memset(auditlog, 0, MAX_LOG_LENGTH);
        }
    }

    fclose(f);
}

void extract_log_from_syslog_tcp(const char *address, uint16_t port) {
    sock_inet sock;
    int client, opt = 1, addrlen = sizeof(sock.addr);

    bzero(&sock.addr, sizeof(sock.addr));
    bzero(sock.data.log_buffer, MAX_LOG_LENGTH);

    if ((sock.data.sockfd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
        log_fatal("Socket openning to listen syslog port failed");

    if (setsockopt(sock.data.sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                   &opt, sizeof(opt)))
        log_fatal("Socket openning to listen syslog port failed");

    sock.addr.sin_family = AF_INET;
    sock.addr.sin_addr.s_addr = inet_addr(address);
    sock.addr.sin_port = htons(port);

    if (bind(sock.data.sockfd, (struct sockaddr *) &sock.addr,
             sizeof(sock.addr)) < 0) {
        tear_down_pgaudit_parser();
        log_fatal("Socket bind failed");
    }

    if (listen(sock.data.sockfd, 1) < 0) {
        tear_down_pgaudit_parser();
        log_fatal("Listen on port %" SCNd16 " failed", port);
    }

    log_info("Listening on port %" SCNd16"...", port);

    if ((client = accept(sock.data.sockfd,
                            (struct sockaddr *) &sock.addr,
                            (socklen_t *) &addrlen)) < 0) {
        tear_down_pgaudit_parser();
        log_fatal("Accept syslog client failed");
    }

    while (true) {
        read(client, sock.data.log_buffer, MAX_LOG_LENGTH);
        sock.data.auditlog_start = strstr(sock.data.log_buffer, "AUDIT");
        if (sock.data.auditlog_start != NULL) {
            sock.data.pgaudit = parse_auditlog(sock.data.auditlog_start);
            pgaudit_freer(&sock.data.pgaudit);
            memset(sock.data.log_buffer, 0, MAX_LOG_LENGTH);
        }
    }
}

void extract_log_from_syslog_uds(const char *endpoint) {
    sock_uds sock;

    bzero(&sock.addr, sizeof(sock.addr));

    if ((sock.data.sockfd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0)
        log_fatal("UDS Socket openning failed");

    sock.addr.sun_family = AF_UNIX;
    strncpy(sock.addr.sun_path, endpoint, sizeof(sock.addr.sun_path));
    sock.addr.sun_path[strlen(endpoint)-1] = '\0';

    if (bind(sock.data.sockfd, (const struct sockaddr *)&sock.addr,
        sizeof(sock.addr)) < 0) {
        log_fatal("Socket bind failed");
    }

    while (true) {
        recvfrom(sock.data.sockfd, sock.data.log_buffer, MAX_LOG_LENGTH, 0, 0,
                 0);
        sock.data.auditlog_start = strstr(sock.data.log_buffer, "AUDIT");
        if (sock.data.auditlog_start != NULL) {
           sock.data.pgaudit = parse_auditlog(sock.data.auditlog_start);
           pgaudit_freer(&sock.data.pgaudit);
           memset(sock.data.log_buffer, 0, MAX_LOG_LENGTH);
        }
    }
}

void tear_down_pgaudit_parser(void) {
    log_info("Tear down PGAudit log parser...");
    regfree(&re);
}
