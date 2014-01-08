#include <openssl/sha.h>
#include <string.h>

#include "pedersen_proof.h"
#include "util.h"

static const char str_c[] = "c";
static const char str_s1[] = "s1";
static const char str_s2[] = "s2";

struct pedersen_statement {
    const EC_GROUP* group;
    EC_POINT* g; 
    EC_POINT* h; 
    EC_POINT* commit_x;
    EC_POINT* g_to_the_x;
};

struct pedersen_evidence {
  /* Challenge */
  BIGNUM* c;

  /* Response */
  BIGNUM* s1;
  BIGNUM* s2;
};

static BIGNUM* Commit(const_PedersenStatement st, const EC_POINT* T1, 
    const EC_POINT* T2, const BIGNUM* q, BN_CTX* ctx);
static void AddPointToHash(SHA_CTX* sha, const EC_GROUP* ec, 
    const EC_POINT* p, BN_CTX* ctx);

PedersenStatement PedersenStatement_New(const EC_GROUP* group, 
    const EC_POINT* g, 
    const EC_POINT* h, 
    const EC_POINT* commit_x,
    const EC_POINT* g_to_the_x)
{
  PedersenStatement st = safe_malloc(sizeof(*st));

  st->group = group;
  CHECK_CALL(st->g = EC_POINT_dup(g, group));
  CHECK_CALL(st->h = EC_POINT_dup(h, group));
  CHECK_CALL(st->commit_x = EC_POINT_dup(commit_x, group));
  CHECK_CALL(st->g_to_the_x = EC_POINT_dup(g_to_the_x, group));

  return st;
}

void PedersenStatement_Free(PedersenStatement st)
{
  EC_POINT_clear_free(st->g);
  EC_POINT_clear_free(st->h);
  EC_POINT_clear_free(st->commit_x);
  EC_POINT_clear_free(st->g_to_the_x);
  free(st);
}

PedersenEvidence PedersenEvidence_New(PedersenStatement st, 
    const BIGNUM *witness_x, const BIGNUM *witness_r)
{
  PedersenEvidence ev = safe_malloc(sizeof(*ev));
  CHECK_CALL(ev);

  BN_CTX* ctx = BN_CTX_new();
  CHECK_CALL(ctx);

  BIGNUM* q = BN_new();
  BIGNUM* t1 = BN_new();
  BIGNUM* t2 = BN_new();
  CHECK_CALL(q);
  CHECK_CALL(t1);
  CHECK_CALL(t2);
  CHECK_CALL(EC_GROUP_get_order(st->group, q, ctx));

  EC_POINT* commit_1 = EC_POINT_new(st->group);
  EC_POINT* commit_2 = EC_POINT_new(st->group);

  // t1 = random in [1,Q]
  // t2 = random in [1,Q]
  CHECK_CALL(BN_rand_range(t1, q));
  CHECK_CALL(BN_rand_range(t2, q));

  // T2 = g^t1
  CHECK_CALL(EC_POINT_mul(st->group, commit_2, NULL, st->g, t1, ctx));

  // T1 = g^t1 h^t2 == T2 * (h^t2)
  CHECK_CALL(EC_POINT_mul(st->group, commit_1, NULL, st->h, t2, ctx));
  CHECK_CALL(EC_POINT_add(st->group, commit_1, commit_1, commit_2, ctx));

  EC_DEBUG("T1", st->group, commit_1, ctx);
  EC_DEBUG("T2", st->group, commit_2, ctx);

  // == Challenge == 
  // c = Hash(g, h, commit_x, g_to_the_x, T1, T2)
  ev->c = Commit(st, commit_1, commit_2, q, ctx);
  CHECK_CALL(ev->c);

  // == Response ==
  // s1 = c*x + t1  (mod Q)
  ev->s1 = BN_dup(ev->c);
  CHECK_CALL(ev->s1);
  CHECK_CALL(BN_mod_mul(ev->s1, ev->s1, witness_x, q, ctx));
  CHECK_CALL(BN_mod_add(ev->s1, ev->s1, t1, q, ctx));

  // s2 = c*r + t2  (mod Q)
  ev->s2 = BN_dup(ev->c);
  CHECK_CALL(ev->s2);
  CHECK_CALL(BN_mod_mul(ev->s2, ev->s2, witness_r, q, ctx));
  CHECK_CALL(BN_mod_add(ev->s2, ev->s2, t2, q, ctx));

  // proof is (c, s1, s2)

  BN_free(q);
  BN_clear_free(t1);
  BN_clear_free(t2);
  BN_CTX_free(ctx);

  EC_POINT_free(commit_1);
  EC_POINT_free(commit_2);

  return ev;
}

void PedersenEvidence_Free(PedersenEvidence ev)
{
  BN_clear_free(ev->c);
  BN_clear_free(ev->s1);
  BN_clear_free(ev->s2);
  free(ev);
}

BIGNUM* Commit(const_PedersenStatement st, const EC_POINT* T1, const EC_POINT* T2,
    const BIGNUM* q, BN_CTX* ctx) 
{
  unsigned char digest[SHA_DIGEST_LENGTH];

  SHA_CTX sha;
  CHECK_CALL(SHA1_Init(&sha));

  AddPointToHash(&sha, st->group, st->g, ctx);
  AddPointToHash(&sha, st->group, st->h, ctx);
  AddPointToHash(&sha, st->group, st->commit_x, ctx);
  AddPointToHash(&sha, st->group, st->g_to_the_x, ctx);
  AddPointToHash(&sha, st->group, T1, ctx);
  AddPointToHash(&sha, st->group, T2, ctx);

  CHECK_CALL(SHA1_Final(digest, &sha));

  BIGNUM* result = BN_bin2bn(digest, SHA_DIGEST_LENGTH, NULL);
  CHECK_CALL(result);

  CHECK_CALL(BN_mod(result, result, q, ctx));

  return result;
}

void AddPointToHash(SHA_CTX* sha, const EC_GROUP* group, 
    const EC_POINT* p, BN_CTX* ctx)
{
  char* hex = EC_POINT_point2hex(group, p, POINT_CONVERSION_UNCOMPRESSED, ctx);
  CHECK_CALL(SHA1_Update(sha, (void*)hex, strlen(hex)));
  OPENSSL_free(hex);
}

bool PedersenEvidence_Verify(const_PedersenEvidence ev, const_PedersenStatement st)
{
  BN_CTX* ctx = BN_CTX_new();
  EC_POINT* commit_1 = EC_POINT_new(st->group);
  EC_POINT* commit_2 = EC_POINT_new(st->group); 
  EC_POINT* g_to_the_s1 = EC_POINT_new(st->group);
  EC_POINT* commit_x_inv = EC_POINT_new(st->group); 

  // T2 = (g^s1) / (g_to_the_x^c)

  CHECK_CALL(st->g);
  CHECK_CALL(ev->s1);

  // g_to_the_s1 = g^s1
  CHECK_CALL(EC_POINT_mul(st->group, g_to_the_s1, NULL, st->g, ev->s1, ctx));

  // commit_2 = (g_to_the_x)^c
  CHECK_CALL(EC_POINT_mul(st->group, commit_2, NULL, st->g_to_the_x, ev->c, ctx));
  CHECK_CALL(EC_POINT_invert(st->group, commit_2, ctx));

  // T2 = (g^s1) / (g_to_the_x^c)
  CHECK_CALL(EC_POINT_add(st->group, commit_2, g_to_the_s1, commit_2, ctx));

  // T1 = (g^s1 h^s2) / (commit_x^c)
  // commit_1 = g^s1 h^s2
  CHECK_CALL(EC_POINT_mul(st->group, commit_1, NULL, st->h, ev->s2, ctx));
  CHECK_CALL(EC_POINT_add(st->group, commit_1, commit_1, g_to_the_s1, ctx));

  // commit_x_inv = (commit_x^-c)
  CHECK_CALL(EC_POINT_mul(st->group, commit_x_inv, NULL, st->commit_x, ev->c, ctx));
  CHECK_CALL(EC_POINT_invert(st->group, commit_x_inv, ctx));

  // T1 = (g^s1 h^s2) / (commit_x^c)
  CHECK_CALL(EC_POINT_add(st->group, commit_1, commit_1, commit_x_inv, ctx));

  //EC_DEBUG("commit_x", st->group, st->commit_x, ctx);
  EC_DEBUG("T1", st->group, commit_1, ctx);
  EC_DEBUG("T2", st->group, commit_2, ctx);

  BIGNUM* q = BN_new();
  CHECK_CALL(EC_GROUP_get_order(st->group, q, ctx));
  BIGNUM* c_actual = Commit(st, commit_1, commit_2, q, ctx);

  //BN_DEBUG("c_actual", c_actual);
  //BN_DEBUG("       c", ev->c);

  bool retval = !BN_cmp(c_actual, ev->c);

  BN_free(q);
  BN_free(c_actual);
  EC_POINT_free(commit_1);
  EC_POINT_free(commit_2);
  EC_POINT_free(g_to_the_s1);
  EC_POINT_free(commit_x_inv);
  BN_CTX_free(ctx);
  
  return retval;
}

bool PedersenEvidence_Serialize(const_PedersenEvidence ev, FILE* fp)
{
  if(!WriteOneBignum(str_c, sizeof(str_c), fp, ev->c)) return false;
  if(!WriteOneBignum(str_s1, sizeof(str_s1), fp, ev->s1)) return false;
  if(!WriteOneBignum(str_s2, sizeof(str_s2), fp, ev->s2)) return false;

  return true;
}

PedersenEvidence PedersenEvidence_Unserialize(FILE* fp)
{
  PedersenEvidence ev = safe_malloc(sizeof(*ev));
  ev->c = BN_new();
  ev->s1 = BN_new();
  ev->s2 = BN_new();

  CHECK_CALL(ev->c);
  CHECK_CALL(ev->s1);
  CHECK_CALL(ev->s2);

  if(!(ReadOneBignum(&(ev->c), fp, str_c) &&
    ReadOneBignum(&(ev->s1), fp, str_s1) &&
    ReadOneBignum(&(ev->s2), fp, str_s2))) {

    BN_clear_free(ev->c);
    BN_clear_free(ev->s1);
    BN_clear_free(ev->s2);
    free(ev);

    return NULL;
  } 

  return ev;
}

