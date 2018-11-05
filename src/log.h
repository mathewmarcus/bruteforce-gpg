
#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <stdarg.h>

void log_debug(char *format, ...);

extern int debug;

#endif
