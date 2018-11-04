#include "bruteforce_gpg.h"

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

char *bruteforce_gpg_load_secret_key(char *secret_key_filename, char **fingerprint) {
  gpgme_ctx_t context;
  gpgme_error_t err;
  gpgme_data_t secret_key_data;

  err = gpgme_new(&context);
  if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
    fprintf(stderr, "Context creation failed: %s\n", gpgme_strerror(err));
    return NULL;
  }

  
  /* Read secret key into data buffer */
  err = gpgme_data_new_from_file(&secret_key_data, secret_key_filename, 1);
  if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
    gpgme_release(context);
    fprintf(stderr, "Failed to load secret key from %s: %s\n",
	    secret_key_filename,
	    gpgme_strerror(err));
    return NULL;
  }

  printf("Loaded secret key data from file %s\n", secret_key_filename);

  /* Load secret key from gpg data buffer */
  err = gpgme_op_import(context, secret_key_data);
  if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
    gpgme_data_release(secret_key_data);
    gpgme_release(context);
    fprintf(stderr, "Failed to import secret key from gpg data buffer: %s\n",
  	    gpgme_strerror(err));
    return NULL;
  }

  printf("Imported secret key from gpg data buffer\n");
  gpgme_import_result_t result = gpgme_op_import_result(context);

  if (result->imported != 1) {
    gpgme_data_release(secret_key_data);
    gpgme_release(context);
    fprintf(stderr, "Secret key file must contain exactly one key, found %i in %s\n",
  	    result->imported,
  	    secret_key_filename);
    return NULL;
  }

  if (result->secret_imported != 1) {
    gpgme_data_release(secret_key_data);
    gpgme_release(context);
    fprintf(stderr, "Secret key file %s only contains public key \n",
  	    secret_key_filename);
    return NULL;
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

  if (!*fingerprint)
    *fingerprint = strndup(result->imports->fpr, 40);
  else
    strncpy(*fingerprint, result->imports->fpr, 40);
    
  gpgme_data_release(secret_key_data);
  gpgme_release(context);
  return *fingerprint;
}

gpgme_error_t bruteforce_gpg_read_passphrases_from_file(void *hook, const char *uid_hint, const char *passphrase_info, int prev_was_bad, int fd) {
  struct callback_data *data = (struct callback_data *) hook;

  pthread_mutex_lock(&mutex);
  if (getline(&(data->line), &(data->line_length), data->password_file) == -1) {
    free(data->line);
    perror("Failed to read password file");
    return GPG_ERR_CANCELED;
  }

  printf("%u passwords attmpted\r", ++(*data->attempt));
  fflush(stdout);
  
  pthread_mutex_unlock(&mutex);
  if (gpgme_io_writen(fd, data->line, data->line_length) == -1) {
    free(data->line);
    fprintf(stderr, "Failed to write password %s: %s\n",
  	    data->line,
  	    strerror(errno));
    return GPG_ERR_CANCELED;
  }
  /* printf("%i %lu %s", fd, pthread_self(), data->line); */
  return GPG_ERR_NO_ERROR;
}

void *bruteforce_gpg_crack_passphrase(void *args) {
  gpgme_error_t err;
  gpgme_ctx_t context;
  gpgme_key_t secret_key;
  gpgme_data_t signing_data;
  gpgme_data_t signature;
  struct callback_data *data;
  char *err_buf;

  struct thread_args *gpg_data = (struct thread_args *) args;

  if(!(err_buf = calloc(ERR_BUF_LEN, sizeof(char))))
    return NULL;

  err = gpgme_new(&context);
  if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
    gpgme_strerror_r(err, err_buf, ERR_BUF_LEN);
    fprintf(stderr, "Context creation failed: %s\n", err_buf);
    return NULL;
  }

  printf("Context created!\n");

  /* Ensure protocol is set to pgp */
  err = gpgme_set_protocol(context, GPGME_PROTOCOL_OPENPGP);
  if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
    gpgme_release(context);
    gpgme_strerror_r(err, err_buf, ERR_BUF_LEN);
    fprintf(stderr, "Setting context to use %s protocol failed: %s\n",
	    gpgme_get_protocol_name(GPGME_PROTOCOL_OPENPGP),
	    err_buf);
    free(err_buf);
    return NULL;
  }

  printf("Context set to %s\n", gpgme_get_protocol_name(GPGME_PROTOCOL_OPENPGP));

  /* Set pinentry mode to allow non-interactive reading of passphrase(s) */
  err = gpgme_set_pinentry_mode(context, GPGME_PINENTRY_MODE_LOOPBACK);
  if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
    gpgme_release(context);
    gpgme_strerror_r(err, err_buf, ERR_BUF_LEN);
    fprintf(stderr, "Failed to set pinentry mode to loopback: %s\n",
  	    err_buf);
    free(err_buf);
    return NULL;
  }

  printf("Pinentry mode set to loopback\n");

  /*
     Set keylist mode to use local keyring(default) and include secret keys in the first iteration
  */
  err = gpgme_set_keylist_mode(context, GPGME_KEYLIST_MODE_LOCAL | GPGME_KEYLIST_MODE_WITH_SECRET);
  if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
    gpgme_release(context);
    gpgme_strerror_r(err, err_buf, ERR_BUF_LEN);
    fprintf(stderr, "Failed to set keylist mode to local with secret: %s\n",
  	    err_buf);
    free(err_buf);
    return NULL;
  }

  printf("Keylist mode set to local with secret\n");

  /* Set passphrase callback */
  data = malloc(sizeof(struct callback_data));
  if (!data) {
    gpgme_release(context);
    perror("Failed to allocate space for passphrase callback hook data");
    free(err_buf);
    return NULL;
  }
  gpgme_set_passphrase_cb(context, bruteforce_gpg_read_passphrases_from_file, data);

  /* Get secret key */
  err = gpgme_get_key(context, gpg_data->fingerprint, &secret_key, 1);
  if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
    gpgme_release(context);
    free(data);
    gpgme_strerror_r(err, err_buf, ERR_BUF_LEN);
    fprintf(stderr, "Failed to get secret key: %s\n", err_buf);
    free(err_buf);
    return NULL;
  }

  printf("Got secret key\n");

  /* Set key as signing key */
  err = gpgme_signers_add(context, secret_key);
  if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
    gpgme_op_delete_ext(context, secret_key, GPGME_DELETE_ALLOW_SECRET | GPGME_DELETE_FORCE);
    gpgme_release(context);
    free(data);
    gpgme_strerror_r(err, err_buf, ERR_BUF_LEN);
    fprintf(stderr, "Failed to add signing key to context: %s\n", err_buf);
    free(err_buf);
    return NULL;
  }

  printf("Added secret key as signing key in context\n");

  /* Create buffer of data to sign */
  err = gpgme_data_new_from_mem(&signing_data, "test", 4, 0);
  if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
    gpgme_signers_clear(context);
    gpgme_op_delete_ext(context, secret_key, GPGME_DELETE_ALLOW_SECRET | GPGME_DELETE_FORCE);
    free(data);
    gpgme_release(context);
    gpgme_strerror_r(err, err_buf, ERR_BUF_LEN);
    fprintf(stderr, "Failed to create signing buffer: %s\n", err_buf);
    free(err_buf);
    return NULL;
  }

  printf("Created signing buffer\n");

  err = gpgme_data_new(&signature);
  if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
    gpgme_data_release(signing_data);
    gpgme_signers_clear(context);
    gpgme_op_delete_ext(context, secret_key, GPGME_DELETE_ALLOW_SECRET | GPGME_DELETE_FORCE);
    free(data);
    gpgme_release(context);
    gpgme_strerror_r(err, err_buf, ERR_BUF_LEN);
    fprintf(stderr, "Failed to create signature buffer: %s\n", err_buf);
    free(err_buf);
    return NULL;
  }

  printf("Created signature buffer\n");

  data->attempt = &(gpg_data->attempt);
  data->line = NULL;
  data->line_length = 0;
  data->password_file = gpg_data->wordlist;

  /* Sign any data

     The loop logic is necessary because the user-supplied passphrase callback function is
     not re-invoked for failed passphrase attempts (like the default pinentry callback)
  */
  do
    {
      err = gpgme_op_sign(context, signing_data, signature, GPGME_SIG_MODE_DETACH);
    } while (gpgme_err_code(err) == GPG_ERR_BAD_PASSPHRASE && !gpg_data->passphrase);
  
  if (gpgme_err_code(err) != GPG_ERR_NO_ERROR && !gpg_data->passphrase) {
    gpgme_strerror_r(err, err_buf, ERR_BUF_LEN);
    fprintf(stderr, "Secret key decryption failed: %s\n", err_buf);
  }

  pthread_mutex_lock(&mutex);
  if (data->line && !gpg_data->passphrase) {
    gpg_data->end_time = time(NULL);
    gpg_data->passphrase = data->line;
  }
  else if (data->line)
    free(data->line);
  pthread_mutex_unlock(&mutex);

  gpgme_data_release(signature);
  gpgme_data_release(signing_data);
  gpgme_op_delete_ext(context, secret_key, GPGME_DELETE_ALLOW_SECRET | GPGME_DELETE_FORCE);
  gpgme_signers_clear(context);
  free(data);
  gpgme_release(context);
  free(err_buf);


  return &gpg_data->passphrase;
}

