#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "agent.h"


char *get_gpg_agent_cache_info(char **ttl) {
  FILE *output;
  char *line, *prev, *cur, *next;
  size_t line_len;

  line = NULL;
  if (!(output = popen("gpgconf --list-options gpg-agent", "r"))) {
    perror("Failed to list gpg-agent cache options");
    return NULL;
  }
  while (getline(&line, &line_len, output) !=-1) {
    if (!strncmp(line, "default-cache-ttl", 17)) {
      cur = strsep(&line, ":");

      while ((next = strsep(&line, ":"))) {
	prev = cur;
	cur = next;
      }

      /* prev will contain the value of flags
	 (https://www.gnupg.org/documentation/manuals/gnupg/Changing-options.html)
	 which we may end up using at a later date
      */
      
      if (!*ttl)
	*ttl = strdup(cur);
      else
	strcpy(*ttl, cur);
      (*ttl)[strlen(*ttl)- 1] = '\0';
      break;
    }
  }
  
  if (line)
    free(line);

  pclose(output);
  return *ttl;
}

int set_gpg_agent_cache_info(char *ttl) {
  FILE *output;
  char *cmd;
  int ttl_len;

  ttl_len = strlen(ttl);

  cmd = calloc(21 + ttl_len, sizeof(char));
  strcpy(cmd, "default-cache-ttl::");

  strncat(cmd, ttl, ttl_len);
  strcat(cmd, "\n");

  if (!(output = popen("gpgconf --change-options gpg-agent 2>&1 >/dev/null", "w"))) {
    perror("Failed to open gpg-agent cache options write buffer");
    return errno;
  }

  if (fwrite(cmd, 1, 20 + ttl_len, output) != (size_t) (20 + ttl_len)) {
    perror("Failed to modify gpg-agent cache options");
    return errno;
  }

  free(cmd);
  pclose(output);
  return 0;
}
