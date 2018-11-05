#include <getopt.h>
#include "bruteforce_gpg.h"
#include "log.h"
#include "agent.h"

/*
  TODO:
    1. Disable password caching in gpg-agent
    2. Signal handling
*/

int debug;
int main(int argc, char *argv[argc])
{
  int option;
  long num_threads;
  char *password_filename = NULL, *secret_key_filename, *endptr, *ttl = NULL;
  pthread_t *workers;
  gpgme_error_t err;
  void *worker_err;
  struct thread_args gpg_data;
  time_t start_time;

  num_threads = 1;
  debug = opterr = 0;
  while ((option = getopt(argc, argv, "hvf:t:")) != -1) {
    switch (option) {
      case 'f': {
	password_filename = optarg;
	break;
      }
      case 't':
	num_threads = strtol(optarg, &endptr, 10);
	if (errno == EINVAL || errno == ERANGE) {
	  perror("Invalid argument to -t");
	  exit(errno);
	}

	if (num_threads <= 0) {
	  fprintf(stderr, "Argument to -t must be >= 1\n");
	  exit(1);
	}
	break;
      case 'h':
	fprintf(stderr, USAGE, argv[0]);
	exit(0);
      case 'v':
	debug = 1;
	break;
      case ':':
	fprintf(stderr, "Option %c requires an argument", optopt);
	exit(1);
      case '?':
	fprintf(stderr, "Unrecognized option %c\n", optopt);
	exit(1);
    }
  }

  if (!password_filename || argc-optind != 1) {
    fprintf(stderr, USAGE, argv[0]);
    exit(1);
  }
  secret_key_filename = argv[optind];

  log_debug("wordlist: %s\nkey file: %s\n",
	    password_filename,
	    secret_key_filename);

  if (!(gpg_data.wordlist = fopen(password_filename, "r"))) {
    fprintf(stderr,
	    "Failed to open wordlist %s: %s\n",
	    password_filename,
	    strerror(errno));
    exit(errno);
  }

  /* Initialize thread subsystem */
  gpgme_check_version(NULL);

  /* Check that PGP is supported by the gpg installation */
  err = gpgme_engine_check_version(GPGME_PROTOCOL_OPENPGP);
  if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
    fprintf(stderr, "%s gpg engine check failure: %s\n",
	    gpgme_get_protocol_name(GPGME_PROTOCOL_OPENPGP),
	    gpgme_strerror(err));
    exit(gpgme_err_code(err));
  }
  
  log_debug("%s engine supported!\n",
	    gpgme_get_protocol_name(GPGME_PROTOCOL_OPENPGP));

  gpg_data.fingerprint = NULL;
  if (!bruteforce_gpg_load_secret_key(secret_key_filename, &gpg_data.fingerprint))
    exit(1);

  gpg_data.attempt = 0;
  gpg_data.passphrase = NULL;
  gpg_data.num_workers = 0;
  workers = calloc(num_threads, sizeof(pthread_t));
  gpg_data.workers = workers;

  
  get_gpg_agent_cache_info(&ttl);
  log_debug("Got existing gpg-agent default-cache-ttl: %s\n", ttl);
  set_gpg_agent_cache_info("0");
  log_debug("Set gpg-agent default-cache-ttl to 0\n");

  start_time = time(NULL);
  for (int i = 0; i < num_threads; i++) {
    if (pthread_create(workers + i, NULL, bruteforce_gpg_crack_passphrase, &gpg_data)) {
      perror("Failed to create at least one of the worker threads");
      free(workers);
      exit(errno);
    }
    gpg_data.num_workers++;
  }

  for (int i = 0; i < num_threads; i++)
    if (pthread_join(workers[i], &worker_err))
      perror("Failed to join to worker thread");
  
  if (gpg_data.passphrase) {
    printf("\nFound passphrase: %s\n", gpg_data.passphrase);
  }
  else {
    gpg_data.end_time = time(NULL);
    printf("\nPassphrase not found\n");
  }
  printf("Duration: %lu seconds\n", gpg_data.end_time - start_time);

  set_gpg_agent_cache_info(ttl);
  log_debug("Reverted gpg-agent default-cache-ttl to %s\n", ttl);
  free(ttl);
  fclose(gpg_data.wordlist);
  free(gpg_data.fingerprint);
  free(workers);
  return gpg_data.passphrase != NULL;
}
