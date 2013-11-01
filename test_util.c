#include <openssl/bn.h>

#include "util.h"
#include "test_common.h"

void mu_test_Util() 
{
  BN_CTX *ctx = BN_CTX_new();
  for(int i=0; i<100; i++) {
    BIGNUM* start = BN_new();
    CHECK_CALL(BN_rand(start, 1024, 0, 1));
    BIGNUM* b = BN_new();

    mu_ensure(RsaPrime(b, start, ctx));
    CHECK_CALL(BN_add(b, b, start));
    mu_ensure(BN_is_prime(b, BN_prime_checks, NULL, ctx, NULL));

    BN_free(start);
    BN_free(b);
  }
  BN_CTX_free(ctx);
}

