#ifndef AGENT_H
#define AGENT_H

char *get_gpg_agent_cache_info(char **ttl);
int set_gpg_agent_cache_info(char *ttl);

#endif
