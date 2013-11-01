#include <stdbool.h>

#include "integer_group.h"
#include "util.h"

static BIGNUM* FindGenerator(const BIGNUM* p, const BIGNUM* q, BN_CTX *ctx);

static const char str_p[] = "p";
static const char str_q[] = "q";
static const char str_g[] = "g";
static const char str_h[] = "h";

struct integer_group {
  BIGNUM* p;
  BIGNUM* q;
  BIGNUM* g;
  BIGNUM* h;
  BN_CTX* ctx;
};

IntegerGroup IntegerGroup_New(BIGNUM* p, BIGNUM* q, 
    BIGNUM* g, BIGNUM* h)
{
  IntegerGroup group = safe_malloc(sizeof(*group));
 
  group->p = p;
  group->q = q;
  group->g = g;
  group->h = h;
  CHECK_CALL(group->ctx = BN_CTX_new());

  return group;
}

void IntegerGroup_Free(IntegerGroup group) 
{
  BN_clear_free(group->p);
  BN_clear_free(group->q);
  BN_clear_free(group->g);
  BN_clear_free(group->h);
  BN_CTX_free(group->ctx);

  free(group);
}

IntegerGroup IntegerGroup_Generate(int p_bits)
{
  BIGNUM* p = BN_new();
  BIGNUM* q = BN_new();

  CHECK_CALL(p);
  CHECK_CALL(q);

  // Generate big p
  CHECK_CALL(BN_generate_prime(p, p_bits, true, 
        NULL, NULL, NULL, NULL));

  // q = (p-1)/2
  CHECK_CALL(BN_copy(q, p));
  CHECK_CALL(BN_sub_word(q, 1));
  CHECK_CALL(BN_rshift1(q, q));
  // Generate big q

  BN_CTX *ctx = BN_CTX_new();

  ASSERT(BN_is_prime(q, BN_prime_checks, NULL, ctx, NULL));

  // Get generators g,h
  BIGNUM *g = FindGenerator(p, q, ctx);
  BIGNUM *h = FindGenerator(p, q, ctx);

  BN_CTX_free(ctx);

  return IntegerGroup_New(p, q, g, h);
}

int IntegerGroup_Serialize(const_IntegerGroup group, FILE* file)
{
  if(!WriteOneBignum(str_p, sizeof(str_p), 
        file, group->p)) return false;

  if(!WriteOneBignum(str_q, sizeof(str_q), 
        file, group->q)) return false;

  if(!WriteOneBignum(str_g, sizeof(str_g), 
        file, group->g)) return false;

  if(!WriteOneBignum(str_h, sizeof(str_h), 
        file, group->h)) return false;

  return true;
}

bool IntegerGroup_IsElement(const_IntegerGroup group, const BIGNUM *a)
{
  bool is_elm = true;
  BIGNUM *result = BN_new();
  BIGNUM *one = BN_new();
  BN_one(one);

  // a should be greater than or equal to 1
  is_elm &= (BN_cmp(one, a) < 1);

  // a^2 mod p should not equal 1
  CHECK_CALL(BN_mod_sqr(result, a, group->p, group->ctx));
  
  is_elm &= !BN_is_one(result);

  BN_clear_free(result);
  BN_free(one);

  return is_elm;
}

IntegerGroup IntegerGroup_Unserialize(FILE* file)
{
  BIGNUM *p = BN_new();
  BIGNUM *q = BN_new();
  BIGNUM *g = BN_new();
  BIGNUM *h = BN_new();

  CHECK_CALL(p);
  CHECK_CALL(q);
  CHECK_CALL(g);
  CHECK_CALL(h);

  if(ReadOneBignum(&p, file, str_p) &&
    ReadOneBignum(&q, file, str_q) &&
    ReadOneBignum(&g, file, str_g) &&
    ReadOneBignum(&h, file, str_h)) {
    return IntegerGroup_New(p, q, g, h);
  } else {
    return NULL;
  }
}


BIGNUM* IntegerGroup_Inverse(const_IntegerGroup group, const BIGNUM *a)
{
  BIGNUM* result = BN_new();
  CHECK_CALL(result);
  CHECK_CALL(BN_mod_inverse(result, a, group->p, group->ctx));
 
  return result;
}

BIGNUM* IntegerGroup_Exponentiate(const_IntegerGroup group,
    const BIGNUM* g, const BIGNUM* x)
{
  BIGNUM* result = BN_new();
  CHECK_CALL(result);

  CHECK_CALL(BN_mod_exp(result, g, x, group->p, group->ctx));

  return result;
}

BIGNUM* IntegerGroup_CascadeExponentiate(const_IntegerGroup group,
    const BIGNUM* g1, const BIGNUM* x1,
    const BIGNUM* g2, const BIGNUM* x2)
{
  BIGNUM* result1 = IntegerGroup_Exponentiate(group, g1, x1);
  BIGNUM* result2 = IntegerGroup_Exponentiate(group, g2, x2);
  CHECK_CALL(result1);
  CHECK_CALL(result2);

  CHECK_CALL(BN_mod_mul(result1, result1, result2, group->p, group->ctx));

  BN_clear_free(result2);

  return result1;
}

const BIGNUM* IntegerGroup_GetP(const_IntegerGroup group)
{
  return group->p;
}

const BIGNUM* IntegerGroup_GetQ(const_IntegerGroup group)
{
  return group->q;
}

const BIGNUM* IntegerGroup_GetG(const_IntegerGroup group) 
{
  return group->g;
}

const BIGNUM* IntegerGroup_GetH(const_IntegerGroup group)
{
  return group->h;
}

BN_CTX* IntegerGroup_GetCtx(const_IntegerGroup group)
{
  return group->ctx;
}

BIGNUM* FindGenerator(const BIGNUM* p, const BIGNUM* q, BN_CTX *ctx)
{
  BIGNUM *result = BN_new();
  CHECK_CALL(result);

  // e = (p-1)/q
  BIGNUM *e = BN_dup(p);
  CHECK_CALL(e);
  CHECK_CALL(BN_sub_word(e, 1));
  CHECK_CALL(BN_div(e, NULL, e, q, ctx));

  do {
    CHECK_CALL(BN_rand_range(result, p));
    CHECK_CALL(BN_mod_exp(result, result, e, p, ctx));
  } while(BN_is_one(result));

  BN_clear_free(e);

  return result;
}

BIGNUM* IntegerGroup_RandomElement(const_IntegerGroup group) 
{
  BIGNUM *result = BN_new();
  CHECK_CALL(result);

  do {
    CHECK_CALL(BN_rand_range(result, group->p));
  } while(!IntegerGroup_IsElement(group, result));

  return result;
}


BIGNUM* IntegerGroup_RandomExponent(const_IntegerGroup group) 
{
  BIGNUM *result = BN_new();

  CHECK_CALL(result);
  CHECK_CALL(BN_rand_range(result, group->q));

  return result;
}

BIGNUM* IntegerGroup_Commit(const_IntegerGroup group, const BIGNUM* v, const BIGNUM *r)
{
  BIGNUM* result = BN_new();
  BIGNUM* tmp = BN_new();
  CHECK_CALL(result);
  CHECK_CALL(tmp);

  // result = g^v mod p
  CHECK_CALL(BN_mod_exp(result, group->g, 
        v, group->p, group->ctx));

  // tmp = h^r mod p
  CHECK_CALL(BN_mod_exp(tmp, group->h, 
        r, group->p, group->ctx));

  // result = g^v h^r mod p
  CHECK_CALL(BN_mod_mul(result, result, tmp,
        group->p, group->ctx));

  BN_clear_free(tmp);
  return result;
}

