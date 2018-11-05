#include "log.h"

void log_debug(char *format, ...) {
  va_list args;
  va_start(args, format);

  if (debug)
    vprintf(format, args);

  va_end(args);
}
