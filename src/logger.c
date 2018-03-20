#include "logger.h"

#include <time.h>
#include <stdarg.h>

void logger(FILE *f, const char* severity, const char* message, ...) {
    time_t now;
    char buff_msg[MAX_LOG_MSG_SIZE];
    va_list vl;

    time(&now);
    va_start(vl, message);
    vsnprintf(buff_msg, sizeof(buff_msg), message, vl);
    va_end(vl);

    fprintf(f, "%.19s [%s]: %s\n", ctime(&now), severity, buff_msg);
}
