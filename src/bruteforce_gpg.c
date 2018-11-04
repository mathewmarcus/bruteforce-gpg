#include <gpgme.h>
#include <string.h>
#include <stdlib.h>
#include "bruteforce_gpg.h"


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
