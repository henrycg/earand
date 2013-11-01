#include <openssl/bn.h>
#include <openssl/sha.h>

#include <string.h>

#include "product_proof.h"

static const char str_c[] = "c";
static const char str_z[] = "z";
static const char str_w1[] = "w1";
static const char str_w2[] = "w2";

struct product_statement {
  const_IntegerGroup group;

  /* Statement */
  BIGNUM* commit_a;
  BIGNUM* commit_b;
  BIGNUM* commit_c;
};

struct product_evidence {
  /* Challenge */
  BIGNUM* c;

  /* Response */
  BIGNUM* z;
  BIGNUM* w1;
  BIGNUM* w2;
};

/**
 * Compute:
 *    c = Hash(p, q, g, h, A, B, C, m1, m2)
 * where c is in [0, q).
 */
static BIGNUM* Commit(const_ProductStatement st, 
    const BIGNUM *m1, const BIGNUM *m2);

static void AddBignumToHash(SHA_CTX* sha, const BIGNUM* bn);

/**
 * Multiplication protocol from:
 *   "Zero-Knowledge Proofs for Finite Field Arithmetic or:
 *      Can Zero-Knowledge be for Free?"
 *   Cramer and Damgard - BRICS Report RS-97-27
 *   November 1997
 *
 * ftp://ftp.cs.au.dk/pub/BRICS/pub/RS/97/27/BRICS-RS-97-27.pdf
 */
ProductStatement ProductStatement_New(const_IntegerGroup group, 
    const BIGNUM* commit_a, const BIGNUM* commit_b, const BIGNUM* commit_c)
{
  ProductStatement st = safe_malloc(sizeof(*st));

  st->group = group;
  CHECK_CALL(st->commit_a = BN_dup(commit_a));
  CHECK_CALL(st->commit_b = BN_dup(commit_b));
  CHECK_CALL(st->commit_c = BN_dup(commit_c));

  return st;
}

void ProductStatement_Free(ProductStatement st)
{
  BN_clear_free(st->commit_a);
  BN_clear_free(st->commit_b);
  BN_clear_free(st->commit_c);
  free(st);
}

ProductEvidence ProductEvidence_New(ProductStatement st, 
    const BIGNUM *a, const BIGNUM *r_a, const BIGNUM *r_b, const BIGNUM *r_c)
{
  ProductEvidence ev = safe_malloc(sizeof(*ev));

  const BIGNUM* g = IntegerGroup_GetG(st->group);
  const BIGNUM* h = IntegerGroup_GetH(st->group);
  const BIGNUM* q = IntegerGroup_GetQ(st->group);
  BN_CTX* ctx = IntegerGroup_GetCtx(st->group);

  // A = g^a h^{r_a}
  // B = g^b h^{r_b}
  // C = g^{ab} h^{r_c}

  // r_prod = r_c - a*r_b 
  BIGNUM* r_prod;
  CHECK_CALL(r_prod = BN_dup(a));
  CHECK_CALL(BN_mod_mul(r_prod, r_prod, r_b, q, ctx));
  CHECK_CALL(BN_mod_sub(r_prod, r_c, r_prod, q, ctx));
  
  // == Commitment == 
  // x, s1, s2 in [0, q)

  BIGNUM *x = IntegerGroup_RandomExponent(st->group);
  BIGNUM *s1 = IntegerGroup_RandomExponent(st->group);
  BIGNUM *s2 = IntegerGroup_RandomExponent(st->group);

  CHECK_CALL(x);
  CHECK_CALL(s1);
  CHECK_CALL(s2);

  // m1 = g^x h^s1
  BIGNUM* m1 = IntegerGroup_CascadeExponentiate(st->group, g, x, h, s1);
  CHECK_CALL(m1);
    
  // m2 = B^x h^s2
  BIGNUM* m2 = IntegerGroup_CascadeExponentiate(st->group, st->commit_b, x, h, s2);
  CHECK_CALL(m2);

  // == Challenge == 
  // c = H(g, h, q, p, A, B, C, m1, m2)
  ev->c = Commit(st, m1, m2);

  // == Response ==
  // z = x + ca mod q
  ev->z = BN_dup(ev->c);
  CHECK_CALL(ev->z);
  CHECK_CALL(BN_mod_mul(ev->z, ev->z, a, q, ctx));
  CHECK_CALL(BN_mod_add(ev->z, ev->z, x, q, ctx));

  // w1 = s1 + (c r_a) mod q
  ev->w1 = BN_dup(r_a);
  CHECK_CALL(ev->w1);
  CHECK_CALL(BN_mod_mul(ev->w1, ev->w1, ev->c, q, ctx));
  CHECK_CALL(BN_mod_add(ev->w1, ev->w1, s1, q, ctx));

  // w2 = s2 + (c r_prod) mod q
  ev->w2 = BN_dup(r_prod);
  CHECK_CALL(ev->w2);
  CHECK_CALL(BN_mod_mul(ev->w2, ev->w2, ev->c, q, ctx));
  CHECK_CALL(BN_mod_add(ev->w2, ev->w2, s2, q, ctx));

  // proof is (c, z, w1, w2)

  BN_free(m1);
  BN_free(m2);
  BN_clear_free(x);
  BN_clear_free(s1);
  BN_clear_free(s2);
  BN_clear_free(r_prod);

  return ev;
}

void ProductEvidence_Free(ProductEvidence ev)
{
  BN_clear_free(ev->c);
  BN_clear_free(ev->z);
  BN_clear_free(ev->w1);
  BN_clear_free(ev->w2);
  free(ev);
}

ProductEvidence ProductEvidence_Unserialize(FILE* fp)
{
  ProductEvidence ev = safe_malloc(sizeof(*ev));
  ev->c = BN_new();
  ev->z = BN_new();
  ev->w1 = BN_new();
  ev->w2 = BN_new();

  CHECK_CALL(ev->c);
  CHECK_CALL(ev->z);
  CHECK_CALL(ev->w1);
  CHECK_CALL(ev->w2);

  if(!(ReadOneBignum(&(ev->c), fp, str_c) &&
    ReadOneBignum(&(ev->z), fp, str_z) &&
    ReadOneBignum(&(ev->w1), fp, str_w1) &&
    ReadOneBignum(&(ev->w2), fp, str_w2))) {

    BN_clear_free(ev->c);
    BN_clear_free(ev->z);
    BN_clear_free(ev->w1);
    BN_clear_free(ev->w2);
    free(ev);

    return NULL;
  } 

  return ev;
}

bool ProductEvidence_Serialize(const_ProductEvidence ev, FILE* fp)
{
  if(!WriteOneBignum(str_c, sizeof(str_c), fp, ev->c)) return false;
  if(!WriteOneBignum(str_z, sizeof(str_z), fp, ev->z)) return false;
  if(!WriteOneBignum(str_w1, sizeof(str_w1), fp, ev->w1)) return false;
  if(!WriteOneBignum(str_w2, sizeof(str_w2), fp, ev->w2)) return false;

  return true;
}

bool ProductEvidence_Verify(const_ProductEvidence ev, const_ProductStatement st)
{
  const BIGNUM* g = IntegerGroup_GetG(st->group);
  const BIGNUM* h = IntegerGroup_GetH(st->group);
  const BIGNUM* p = IntegerGroup_GetP(st->group);
  BN_CTX* ctx = IntegerGroup_GetCtx(st->group);
  BIGNUM *tmp = BN_new();

  // Recompute commitments
  // m1' = (g^z h^w1) / A^c
  BIGNUM* m1 = IntegerGroup_CascadeExponentiate(st->group, g, ev->z, h, ev->w1);
  CHECK_CALL(m1);
  CHECK_CALL(BN_copy(tmp, st->commit_a));
  CHECK_CALL(BN_mod_exp(tmp, tmp, ev->c, p, ctx));
  CHECK_CALL(BN_mod_inverse(tmp, tmp, p, ctx));
  CHECK_CALL(BN_mod_mul(m1, m1, tmp, p, ctx));

  // m2' = (B^z h^w2) / C^c
  BIGNUM* m2 = IntegerGroup_CascadeExponentiate(st->group, st->commit_b, ev->z, h, ev->w2);
  CHECK_CALL(m2);
  CHECK_CALL(BN_copy(tmp, st->commit_c));
  CHECK_CALL(BN_mod_exp(tmp, tmp, ev->c, p, ctx));
  CHECK_CALL(BN_mod_inverse(tmp, tmp, p, ctx));
  CHECK_CALL(BN_mod_mul(m2, m2, tmp, p, ctx));

  BN_clear_free(tmp);

  // Check challenge 
  // c =? H(g, h, q, p, A, B, C, m1', m2')
  BIGNUM *c_prime = Commit(st, m1, m2);

  BN_free(m1);
  BN_free(m2);

  bool retval = !BN_cmp(ev->c, c_prime);

  BN_clear_free(c_prime);

  return retval;
}

BIGNUM* Commit(const_ProductStatement st, const BIGNUM* m1, const BIGNUM* m2) 
{
  unsigned char digest[SHA_DIGEST_LENGTH];

  SHA_CTX sha;
  CHECK_CALL(SHA1_Init(&sha));

  AddBignumToHash(&sha, IntegerGroup_GetP(st->group));
  AddBignumToHash(&sha, IntegerGroup_GetQ(st->group));
  AddBignumToHash(&sha, IntegerGroup_GetG(st->group));
  AddBignumToHash(&sha, IntegerGroup_GetH(st->group));

  AddBignumToHash(&sha, st->commit_a);
  AddBignumToHash(&sha, st->commit_b);
  AddBignumToHash(&sha, st->commit_c);

  AddBignumToHash(&sha, m1);
  AddBignumToHash(&sha, m2);

  CHECK_CALL(SHA1_Final(digest, &sha));

  BIGNUM* result = BN_bin2bn(digest, SHA_DIGEST_LENGTH, NULL);
  CHECK_CALL(result);

  CHECK_CALL(BN_mod(result, result, IntegerGroup_GetQ(st->group),
        IntegerGroup_GetCtx(st->group)));

  return result;
}

void AddBignumToHash(SHA_CTX* sha, const BIGNUM* bn)
{
  const int n_bytes = BN_num_bytes(bn);
  unsigned char* bytes = safe_malloc(sizeof(unsigned char) * n_bytes);

  CHECK_CALL(BN_bn2bin(bn, bytes));
  CHECK_CALL(SHA1_Update(sha, (void*)bytes, n_bytes));

  free(bytes);
}

