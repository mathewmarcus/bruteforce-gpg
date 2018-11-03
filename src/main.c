#include <gpgme.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#define USAGE "%s -f password_file secret_key_file\n"

struct callback_data {
  FILE *password_file;
  unsigned int attempt;
  char *line;
  size_t line_length;
};



gpgme_error_t bruteforce_gpg_read_passphrases_from_file(void *hook, const char *uid_hint, const char *passphrase_info, int prev_was_bad, int fd);
int main(int argc, char *argv[argc])
{
  int option;
  long num_threads;
  char *password_filename = NULL, *secret_key_filename, *fingerprint, *endptr;
  gpgme_error_t err;
  gpgme_ctx_t context;
  gpgme_key_t secret_key;
  gpgme_data_t signing_data;
  gpgme_data_t signature;
  gpgme_data_t secret_key_data;
  struct callback_data *data;

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
  printf("Password file: %s, key file: %s\n", password_filename, secret_key_filename);

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

  /* Create context */
  err = gpgme_new(&context);
  if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
    fprintf(stderr, "Context creation failed: %s\n",
	    gpgme_strerror(err));
    exit(gpgme_err_code(err));
  }

  printf("Context created!\n");

  /* Ensure protocol is set to pgp */
  err = gpgme_set_protocol(context, GPGME_PROTOCOL_OPENPGP);
  if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
    gpgme_release(context);
    fprintf(stderr, "Setting context to use %s protocol failed: %s\n",
	    gpgme_get_protocol_name(GPGME_PROTOCOL_OPENPGP),
	    gpgme_strerror(err));
    exit(gpgme_err_code(err));
  }

  printf("Context set to %s\n", gpgme_get_protocol_name(GPGME_PROTOCOL_OPENPGP));

  /* Set pinentry mode to allow non-interactive reading of passphrase(s) */
  err = gpgme_set_pinentry_mode(context, GPGME_PINENTRY_MODE_LOOPBACK);
  if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
    gpgme_release(context);
    fprintf(stderr, "Failed to set pinentry mode to loopback: %s\n",
  	    gpgme_strerror(err));
    exit(gpgme_err_code(err));
  }

  printf("Pinentry mode set to loopback\n");

  /*
     Set keylist mode to use local keyring(default) and include secret keys in the first iteration
     It is not strictly necessary to set this option
  */
  err = gpgme_set_keylist_mode(context, GPGME_KEYLIST_MODE_LOCAL | GPGME_KEYLIST_MODE_WITH_SECRET);
  if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
    gpgme_release(context);
    fprintf(stderr, "Failed to set keylist mode to local with secret: %s\n",
  	    gpgme_strerror(err));
    exit(gpgme_err_code(err));
  }

  printf("Keylist mode set to local with secret\n");

  /* Set passphrase callback */
  data = malloc(sizeof(struct callback_data));
  if (!data) {
    gpgme_release(context);
    perror("Failed to allocate space for passphrase callback hook data");
    exit(errno);
  }
  gpgme_set_passphrase_cb(context, bruteforce_gpg_read_passphrases_from_file, data);

  /* Read secret key into data buffer */
  err = gpgme_data_new_from_file(&secret_key_data, secret_key_filename, 1);
  if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
    gpgme_release(context);
    free(data);
    fprintf(stderr, "Failed to load secret key from %s: %s\n",
	    secret_key_filename,
	    gpgme_strerror(err));
    exit(gpgme_err_code(err));
  }

  printf("Loaded secret key data from file %s\n", secret_key_filename);

  /* Load secret key from gpg data buffer */
  err = gpgme_op_import(context, secret_key_data);
  if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
    gpgme_data_release(secret_key_data);
    gpgme_release(context);
    free(data);
    fprintf(stderr, "Failed to import secret key from gpg data buffer: %s\n",
	    gpgme_strerror(err));
    exit(gpgme_err_code(err));
  }

  printf("Imported secret key from gpg data buffer\n");
  gpgme_import_result_t result = gpgme_op_import_result(context);

  if (result->imported != 1) {
    gpgme_data_release(secret_key_data);
    gpgme_release(context);
    free(data);
    fprintf(stderr, "Secret key file must contain exactly one key, found %i in %s\n",
	    result->imported,
	    secret_key_filename);
    exit(gpgme_err_code(err));
  }

  if (result->secret_imported != 1) {
    gpgme_data_release(secret_key_data);
    gpgme_release(context);
    free(data);
    fprintf(stderr, "Secret key file %s only contains public key \n",
	    secret_key_filename);
    exit(gpgme_err_code(err));
  }

  printf("Considered: %i\n", result->considered);
  printf("No user id: %i\n", result->no_user_id);
  printf("Imported: %i\n", result->imported);
  printf("RSA %i\n", result->imported_rsa);
  printf("Unchanged: %i\n", result->unchanged);
  printf("New user IDs: %i\n", result->new_user_ids);
  printf("New sub keys: %i\n", result->new_sub_keys);
  printf("New signatures: %i\n", result->new_signatures);
  printf("New revocations: %i\n", result->new_revocations);
  printf("Secret keys read: %i\n", result->secret_read);
  printf("Secret keys imported: %i\n", result->secret_imported);
  printf("Secret keys unchanged: %i\n", result->secret_unchanged);
  printf("Not imported: %i\n", result->not_imported);
  printf("Fingerprint: %s\n", result->imports->fpr);

  fingerprint = strndup(result->imports->fpr, 40);
  if (!fingerprint) {
    gpgme_data_release(secret_key_data);
    gpgme_release(context);
    free(data);
    perror("Failed to allocate space for key fingerprint\n");
    exit(errno);
  }
  /* Get secret key */
  err = gpgme_get_key(context, fingerprint, &secret_key, 1);
  if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
    free(fingerprint);
    gpgme_data_release(secret_key_data);
    gpgme_release(context);
    free(data);
    fprintf(stderr, "Failed to get secret key: %s\n", gpgme_strerror(err));
    exit(gpgme_err_code(err));
  }

  printf("Got secret key\n");

  /* Set key as signing key */
  err = gpgme_signers_add(context, secret_key);
  if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
    free(fingerprint);
    gpgme_data_release(secret_key_data);
    gpgme_release(context);
    free(data);
    fprintf(stderr, "Failed to add signing key to context: %s\n", gpgme_strerror(err));
    exit(gpgme_err_code(err));
  }

  printf("Added secret key as signing key in context\n");

  /* Create buffer of data to sign */
  err = gpgme_data_new_from_mem(&signing_data, "test", 4, 0);
  if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
    free(fingerprint);
    gpgme_signers_clear(context);
    gpgme_data_release(secret_key_data);
    free(data);
    gpgme_release(context);
    fprintf(stderr, "Failed to create signing buffer: %s\n", gpgme_strerror(err));
    exit(gpgme_err_code(err));
  }

  printf("Created signing buffer\n");

  err = gpgme_data_new(&signature);
  if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
    free(fingerprint);
    gpgme_data_release(signing_data);
    gpgme_signers_clear(context);
    gpgme_data_release(secret_key_data);
    free(data);
    gpgme_release(context);
    fprintf(stderr, "Failed to create signature buffer: %s\n", gpgme_strerror(err));
    exit(gpgme_err_code(err));
  }

  printf("Created signature buffer\n");

  /* Open password_file */
  data->attempt = 0;
  data->line = NULL;
  data->line_length = 0;
  data->password_file = fopen(password_filename, "r");
  if (!data->password_file) {
    free(fingerprint);
    gpgme_data_release(signature);
    gpgme_data_release(signing_data);
    gpgme_signers_clear(context);
    gpgme_data_release(secret_key_data);
    free(data);
    gpgme_release(context);
    fprintf(stderr, "Failed to open password file %s: %s\n", password_filename,
	    strerror(errno));
    exit(gpgme_err_code(errno));
  }

  printf("Opened password file %s\n", password_filename);

  /* Sign any data

     The loop logic is necessary because the user-supplied passphrase callback function is
     not re-invoked for failed passphrase attempts (like the default pinentry callback)
  */
  do
    {
      err = gpgme_op_sign(context, signing_data, signature, GPGME_SIG_MODE_DETACH);
    } while (gpgme_err_code(err) == GPG_ERR_BAD_PASSPHRASE);

  if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
    free(fingerprint);
    fclose(data->password_file);
    gpgme_data_release(signature);
    gpgme_data_release(signing_data);
    gpgme_signers_clear(context);
    gpgme_data_release(secret_key_data);
    free(data);
    gpgme_release(context);
    fprintf(stderr, "Secret key decryption failed: %s\n", gpgme_strerror(err));
    exit(gpgme_err_code(err));
  }

  if (data->line)
    printf("\nFound passphrase: %s\n", data->line);
  else {
    printf("Secret key passphrase for key %s is already cached in gpg-agent\n", fingerprint);
    printf("Restart the agent with \"gpgconf --reload --gpg-agent\"\n\n");
  }

  err = gpgme_op_delete_ext(context, secret_key, GPGME_DELETE_ALLOW_SECRET | GPGME_DELETE_FORCE);
  if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
    free(fingerprint);
    fclose(data->password_file);
    gpgme_data_release(signature);
    gpgme_data_release(signing_data);
    gpgme_signers_clear(context);
    gpgme_data_release(secret_key_data);
    free(data->line);
    fclose(data->password_file);
    free(data);
    gpgme_release(context);
    fprintf(stderr, "Key deletion failed: %s\n", gpgme_strerror(err));
    exit(gpgme_err_code(err));
  }

  printf("Key deleted from keyring\n");

  free(fingerprint);
  fclose(data->password_file);
  gpgme_data_release(signature);
  gpgme_data_release(signing_data);
  gpgme_signers_clear(context);
  gpgme_data_release(secret_key_data);
  free(data->line);
  fclose(data->password_file);
  free(data);
  gpgme_release(context);
  return 0;
}

gpgme_error_t bruteforce_gpg_read_passphrases_from_file(void *hook, const char *uid_hint, const char *passphrase_info, int prev_was_bad, int fd) {
  struct callback_data *data = (struct callback_data *) hook;

  if (getline(&(data->line), &(data->line_length), data->password_file) == -1) {
    free(data->line);
    fclose(data->password_file);
    perror("Failed to read password file");
    return GPG_ERR_CANCELED;
  }

  printf("%u passwords attmpted\r", ++data->attempt);
  fflush(stdout);

  if (gpgme_io_writen(fd, data->line, data->line_length) == -1) {
    free(data->line);
    fclose(data->password_file);
    fprintf(stderr, "Failed to write password %s: %s\n",
  	    data->line,
  	    strerror(errno));
    return GPG_ERR_CANCELED;
  }

  return GPG_ERR_NO_ERROR;
}
