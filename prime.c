#include <openssl/bn.h>
#include "bn_prime.h"
#include "prime.h"
#include "util.h"

static const int bound_bits = 48;
static const int max_iterations = 4096*8;
static const double epsilon = 0.33;

BIGNUM* GeneratePrime(int n_bits, 
    const BIGNUM* min, const BIGNUM* max, BN_CTX* ctx)
{
  BIGNUM* ret = BN_new();
  CHECK_CALL(ret);
  if(n_bits < bound_bits) {
    CHECK_CALL(BN_generate_prime(ret, n_bits, false, NULL, NULL, NULL, NULL)); 
    return ret;
  } 

  if(min != NULL) {
    n_bits = BN_num_bits(min);
  }

  const double b_min = (epsilon * (double)n_bits);
  BIGNUM* factor = GeneratePrime((int)b_min, NULL, NULL, ctx);

  BIGNUM* N0 = BN_new();
  BIGNUM* a = BN_new();
  BIGNUM* ia = BN_new();
  CHECK_CALL(N0);
  CHECK_CALL(a);
  CHECK_CALL(ia);

  const int sn = n_bits * max_iterations;
  BIGNUM* t = BN_new();
  BIGNUM* lower = BN_new();
  BIGNUM* range = BN_new();
  // Pick random t in 2^{n-2}/F, ..., ((2^{n-1}/F) - sn)

  CHECK_CALL(BN_one(lower));
  CHECK_CALL(BN_lshift(lower, lower, n_bits-2));
  CHECK_CALL(BN_div(lower, NULL, lower, factor, ctx));

  CHECK_CALL(BN_copy(range, lower));
  CHECK_CALL(BN_sub_word(range, sn));

 
  printf("$%d\n", n_bits);
  puts("---");
  BN_print_fp(stderr, range);
  puts("<>");
  BN_print_fp(stderr, lower);
  puts("---");
  

  CHECK_CALL(BN_rand_range(t, range));
  CHECK_CALL(BN_add(t, t, lower));

  BN_clear_free(lower);
  BN_clear_free(range);

  //a = 2F
  CHECK_CALL(BN_lshift1(a, factor));

  //N0 = ta+1
  CHECK_CALL(BN_mul(N0, t, a, ctx));
  CHECK_CALL(BN_add_word(N0, 1));

  BN_clear_free(t);
  bool success = false;
  //N = N0 + ia;
  //i = 0, ..., s
  BIGNUM* i = BN_new();
  CHECK_CALL(i);
  int ntest = 0;

  if(min == NULL) {
    BN_zero(i);
  } else {
    // i = ceil((min - ta - 1)/a)

    // N0 = ta+1
    CHECK_CALL(BN_copy(i, min));
    CHECK_CALL(BN_sub(i, i, N0));
    CHECK_CALL(BN_sub_word(i, 2));
    CHECK_CALL(BN_div(i, NULL, i, a, ctx));
  }

  // iterate until N0 is too big
  while(!max || BN_cmp(max, N0) < 1) {
    CHECK_CALL(BN_copy(ia, a));
    CHECK_CALL(BN_mul(ia, ia, i, ctx));

    CHECK_CALL(BN_add(ret, N0, ia));

    bool is_comp = false;
    for(int j=0; j<NUMPRIMES; j++) {
      if(BN_mod_word(ret, primes[j]) == 0) {
        is_comp = true;
        break;
      }
    }

    if(is_comp) continue;
    
    printf("%d\n",ntest++);
    // Check is prime and break if so
    if(BN_is_prime_fasttest(ret, BN_prime_checks, NULL, ctx, NULL, 1)) {
      success = true;
      break;
    }

    BN_add_word(i, 1);
  }
  BN_clear_free(i);
  BN_clear_free(N0);
  BN_clear_free(a);
  BN_clear_free(ia);
  CHECK_CALL(success);

  BN_clear_free(factor);

  return ret;
}

int main(void) {
  BN_CTX* ctx = BN_CTX_new();
  GeneratePrime(512, NULL, NULL, ctx);
  BN_CTX_free(ctx);
  return 0;
}
