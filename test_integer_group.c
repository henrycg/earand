#include <stdbool.h>
#include <stdio.h>

#include <openssl/bn.h>

#include "integer_group.h"
#include "test_common.h"

void mu_test_IntegerGroup_New()
{
  const int bits = 100;
  IntegerGroup g = IntegerGroup_Generate(bits);
  mu_check(IntegerGroup_GetP(g));
  mu_check(IntegerGroup_GetQ(g));
  mu_check(IntegerGroup_GetG(g));
  mu_check(IntegerGroup_GetH(g));
  IntegerGroup_Free(g);
}

void mu_test_IntegerGroup_Generators() 
{
  const int bits = 100;

  IntegerGroup group = IntegerGroup_Generate(bits);
  const BIGNUM *p = IntegerGroup_GetP(group);
  const BIGNUM *q = IntegerGroup_GetQ(group);
  const BIGNUM *g = IntegerGroup_GetG(group);
  const BIGNUM *h = IntegerGroup_GetH(group);

  mu_ensure(p);
  mu_ensure(q);
  mu_ensure(g);
  mu_ensure(h);
  mu_check(BN_cmp(g, h));

  BN_CTX* ctx = BN_CTX_new();
  BIGNUM* tmp = BN_new();
  mu_ensure(tmp);

  // Check that (g^q == 1  mod p)
  mu_ensure(BN_mod_exp(tmp, g, q, p, ctx));
  mu_check(BN_is_one(tmp));

  // Check that (h^q == 1  mod p)
  mu_ensure(BN_mod_exp(tmp, h, q, p, ctx));
  mu_check(BN_is_one(tmp));

  // Check that (g^2 != 1 mod p)
  mu_ensure(BN_mod_sqr(tmp, g, p, ctx));
  mu_check(!BN_is_one(tmp));

  // Check that (h^2 != 1 mod p)
  mu_ensure(BN_mod_sqr(tmp, h, p, ctx));
  mu_check(!BN_is_one(tmp));

  // Check that p is prime
  mu_check(BN_is_prime(p, BN_prime_checks, NULL, ctx, NULL));

  // Check that q is prime
  mu_check(BN_is_prime(q, BN_prime_checks, NULL, ctx, NULL));

  // Check that 2q+1 = p
  mu_ensure(BN_copy(tmp, q));
  mu_ensure(BN_mul_word(tmp, 2));
  mu_ensure(BN_add_word(tmp, 1));
  mu_check(!BN_cmp(tmp, p));

  BN_free(tmp);

  IntegerGroup_Free(group);
  BN_CTX_free(ctx); 
}


void mu_test_IntegerGroup_Serialize() 
{
  const int bits = 115;
  IntegerGroup group = IntegerGroup_Generate(bits);

  // Save params
  const BIGNUM *p = IntegerGroup_GetP(group);
  const BIGNUM *q = IntegerGroup_GetQ(group);
  const BIGNUM *g = IntegerGroup_GetG(group);
  const BIGNUM *h = IntegerGroup_GetH(group);

  // Write params to temp file
  FILE *file = tmpfile();
  mu_ensure(file);
  mu_ensure(IntegerGroup_Serialize(group, file));

  // Read params from file
  rewind(file);

  IntegerGroup group2 = IntegerGroup_Unserialize(file);
  mu_ensure(group2);

  fclose(file);

  // Make sure params match saved ones
  mu_check(!BN_cmp(p, IntegerGroup_GetP(group2)));
  mu_check(!BN_cmp(q, IntegerGroup_GetQ(group2)));
  mu_check(!BN_cmp(g, IntegerGroup_GetG(group2)));
  mu_check(!BN_cmp(h, IntegerGroup_GetH(group2)));

  // Delete params
  IntegerGroup_Free(group);
  IntegerGroup_Free(group2);
}

void mu_test_IntegerGroup_RandomExponent() 
{
  const int bits = 120;
  IntegerGroup group = IntegerGroup_Generate(bits);

  for(int i=0; i<50; i++) {
    BIGNUM* rnd = IntegerGroup_RandomExponent(group);
    mu_check(BN_cmp(rnd, IntegerGroup_GetQ(group)));
    mu_check(!BN_is_negative(rnd));
    BN_free(rnd);
  }

  IntegerGroup_Free(group);
}

void mu_test_IntegerGroup_Commit() 
{
  const int bits = 120;
  IntegerGroup group = IntegerGroup_Generate(bits);
  const BIGNUM *p = IntegerGroup_GetP(group);
  const BIGNUM *g = IntegerGroup_GetG(group);
  const BIGNUM *h = IntegerGroup_GetH(group);
  BN_CTX *ctx = BN_CTX_new();

  for(int i=0; i<50; i++) {
    BIGNUM* v = IntegerGroup_RandomExponent(group);
    mu_ensure(v);

    BIGNUM* r = IntegerGroup_RandomExponent(group);
    mu_ensure(r);

    BIGNUM* c = IntegerGroup_Commit(group, v, r);
    mu_ensure(c);

    mu_ensure(BN_mod_exp(v, g, v, p, ctx));
    mu_ensure(BN_mod_exp(r, h, r, p, ctx));
    mu_ensure(BN_mod_mul(v, v, r, p, ctx));

    mu_check(!BN_cmp(v, c));

    BN_free(v);
    BN_free(r);
    BN_free(c);
  }

  IntegerGroup_Free(group);
  BN_CTX_free(ctx);
}

void mu_test_IntegerGroup_Inverse() 
{
  const int bits = 250;
  IntegerGroup group = IntegerGroup_Generate(bits);
  const BIGNUM *p = IntegerGroup_GetP(group);
  BN_CTX *ctx = BN_CTX_new();

  for(int i=0; i<50; i++) {
    BIGNUM* a = IntegerGroup_RandomElement(group);
    mu_ensure(a);
    mu_ensure(IntegerGroup_IsElement(group, a));

    BIGNUM* a_inv = IntegerGroup_Inverse(group, a);
    mu_ensure(a_inv);
    mu_ensure(IntegerGroup_IsElement(group, a_inv));

    mu_ensure(BN_mod_mul(a, a, a_inv, p, ctx));
    mu_ensure(BN_is_one(a));

    BN_free(a);
    BN_free(a_inv);
  }

  IntegerGroup_Free(group);
  BN_CTX_free(ctx);
}

void mu_test_IntegerGroup_Exponentiate() 
{
  const int bits = 120;
  IntegerGroup group = IntegerGroup_Generate(bits);
  const BIGNUM *p = IntegerGroup_GetP(group);
  BN_CTX *ctx = BN_CTX_new();

  for(int i=0; i<50; i++) {
    BIGNUM* g = IntegerGroup_RandomElement(group);
    mu_ensure(g);
    mu_ensure(IntegerGroup_IsElement(group, g));

    BIGNUM* x = IntegerGroup_RandomExponent(group);
    mu_ensure(x);

    BIGNUM* y = IntegerGroup_Exponentiate(group, g, x);
    mu_ensure(y);
    mu_ensure(IntegerGroup_IsElement(group, y));


    mu_ensure(BN_mod_exp(g, g, x, p, ctx));

    mu_check(!BN_cmp(g, y));

    BN_free(g);
    BN_free(x);
    BN_free(y);
  }

  IntegerGroup_Free(group);
  BN_CTX_free(ctx);
}

void mu_test_IntegerGroup_CascadeExponentiate() 
{
  const int bits = 120;
  IntegerGroup group = IntegerGroup_Generate(bits);
  const BIGNUM *p = IntegerGroup_GetP(group);
  BN_CTX *ctx = BN_CTX_new();

  for(int i=0; i<50; i++) {
    BIGNUM* g1 = IntegerGroup_RandomElement(group);
    BIGNUM* g2 = IntegerGroup_RandomElement(group);
    mu_ensure(g1);
    mu_ensure(g2);
    mu_ensure(IntegerGroup_IsElement(group, g1));
    mu_ensure(IntegerGroup_IsElement(group, g2));

    BIGNUM* x1 = IntegerGroup_RandomExponent(group);
    BIGNUM* x2 = IntegerGroup_RandomExponent(group);
    mu_ensure(x1);
    mu_ensure(x2);

    BIGNUM* y = IntegerGroup_CascadeExponentiate(group, g1, x1, g2, x2);
    BIGNUM* r1 = BN_new();
    BIGNUM* r2 = BN_new();
    mu_ensure(y);
    mu_ensure(r1);
    mu_ensure(r2);

    mu_ensure(BN_mod_exp(r1, g1, x1, p, ctx));
    mu_ensure(BN_mod_exp(r2, g2, x2, p, ctx));
    mu_ensure(BN_mod_mul(r1, r1, r2, p, ctx));

    mu_check(!BN_cmp(r1, y));
    mu_ensure(IntegerGroup_IsElement(group, y));

    BN_free(r1);
    BN_free(r2);
    BN_free(g1);
    BN_free(g2);
    BN_free(x1);
    BN_free(x2);
    BN_free(y);
  }

  IntegerGroup_Free(group);
  BN_CTX_free(ctx);
}

