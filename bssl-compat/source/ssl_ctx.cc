#include <openssl/ssl.h>
#include <ossl/openssl/ssl.h>
#include <string>


/*
 * https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/ssl.h#L1508
 *
 * https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set_cipher_list.html
 * https://www.openssl.org/docs/man3.0/man3/SSL_CTX_get_ciphers.html
 * https://www.openssl.org/docs/man3.0/man3/SSL_CIPHER_get_name.html
 */
int SSL_CTX_set_strict_cipher_list(SSL_CTX *ctx, const char *str) {
  // OpenSSL's SSL_CTX_set_cipher_list() performs virtually no checking on str.
  // It only returns 0 (fail) if no cipher could be selected from the list at
  // all. Otherwise it returns 1 (pass) even if there is only one cipher in the
  // string that makes sense, and the rest are unsupported or even just rubbish.
  if (ossl_SSL_CTX_set_cipher_list(ctx, str) == 0) {
    ERR_print_errors_fp(stderr);
    return 0;
  }

  STACK_OF(SSL_CIPHER)* ciphers = reinterpret_cast<STACK_OF(SSL_CIPHER)*>(ossl_SSL_CTX_get_ciphers(ctx));
  char* dup = strdup(str);
  char* token = strtok(dup, ":+![|]");
  while (token != NULL) {
    std::string str1(token);
    bool found = false;
    for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
      const SSL_CIPHER* cipher = sk_SSL_CIPHER_value(ciphers, i);
      std::string str2(SSL_CIPHER_get_name(cipher));
      if (str1.compare(str2) == 0) {
        found = true;
      }
    }

    if (!found && str1.compare("-ALL") && str1.compare("ALL")) {
      free(dup);
      return 0;
    }

    token = strtok(NULL, ":[]|");
  }

  free(dup);
  return 1;
}
