#include <getopt.h>
#include "bruteforce_gpg.h"

/*
  TODO:
    1. Disable password caching in gpg-agent
    2. Signal handling
    3. DEBUG level logging via -v option
*/

int main(int argc, char *argv[argc])
{
  int option;
  long num_threads;
  char *password_filename = NULL, *secret_key_filename, *endptr;
  pthread_t *workers;
  gpgme_error_t err;
  void *worker_err;
  struct thread_args gpg_data;
  time_t start_time;

  num_threads = 1;
  opterr =  0;
  while ((option = getopt(argc, argv, "f:t:")) != -1) {
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
      case ':':
	fprintf(stderr, "Option %c requires an argument", optopt);
	exit(1);
      case '?':
	fprintf(stderr, "Unrecognized option %c\n", optopt);
	exit(1);
    }
  }
  printf("%i %i\n", argc, optind);
  if (!password_filename || argc-optind != 1) {
    fprintf(stderr, USAGE, argv[0]);
    exit(1);
  }
  secret_key_filename = argv[optind];
  printf("wordlist: %s\n, key file: %s\n", password_filename, secret_key_filename);

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
  
  printf("%s engine supported!\n", gpgme_get_protocol_name(GPGME_PROTOCOL_OPENPGP));

  gpg_data.fingerprint = NULL;
  if (!bruteforce_gpg_load_secret_key(secret_key_filename, &gpg_data.fingerprint))
    exit(1);

  gpg_data.attempt = 0;
  gpg_data.passphrase = NULL;
  gpg_data.num_workers = 0;
  workers = calloc(num_threads, sizeof(pthread_t));
  gpg_data.workers = workers;

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
    printf("Duration: %lu seconds\n", gpg_data.end_time - start_time);
  }
  else
    fprintf(stderr, "Passphrase not found\n");

  fclose(gpg_data.wordlist);
  free(gpg_data.fingerprint);
  free(workers);
  return gpg_data.passphrase != NULL;
}
