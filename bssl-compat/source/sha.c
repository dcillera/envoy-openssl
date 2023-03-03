#include <openssl/sha.h>
#include <ossl.h>


uint8_t *SHA1(const uint8_t *data, size_t len, uint8_t out[SHA_DIGEST_LENGTH]) {
  return ossl_SHA1(data,len,out);
}

uint8_t *SHA224(const uint8_t *data, size_t len,
                uint8_t out[SHA224_DIGEST_LENGTH]) {
  return ossl_SHA224(data,len,out);
}

uint8_t *SHA256(const uint8_t *data, size_t len,
                uint8_t out[SHA256_DIGEST_LENGTH]) {
  return ossl_SHA256(data,len,out);
}

uint8_t *SHA384(const uint8_t *data, size_t len,
                uint8_t out[SHA384_DIGEST_LENGTH]) {
  return ossl_SHA384(data,len,out);
}

uint8_t *SHA512(const uint8_t *data, size_t len,
                uint8_t out[SHA512_DIGEST_LENGTH]) {
  return ossl_SHA512(data,len,out);
}


