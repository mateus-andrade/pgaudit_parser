#ifndef LOGGER_H
#define LOGGER_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_LOG_MSG_SIZE 100

#define log_warn(message, ...)                                                 \
    logger(stderr, "WARN", message, ##__VA_ARGS__);

#define log_error(message, ...)                                                 \
    logger(stderr, "ERROR", message, ##__VA_ARGS__);

#define log_fatal(message, ...)                                                \
    do {                                                                       \
        logger(stderr, "FATAL", message, ##__VA_ARGS__);                                 \
        exit(1);                                                               \
    } while (0);

#define log_info(message, ...)                                                 \
    logger(stdout, "INFO", message, ##__VA_ARGS__);

#define debug(message, ...)                                                    \
    logger(stdout, "DEBUG", message, ##__VA_ARGS__);

#define trace(message, ...)                                                    \
    logger(stdout, "TRACE", message, ##__VA_ARGS__);


void logger(FILE *f, const char *severity, const char *message, ...);

#endif /* LOGGER_H */
