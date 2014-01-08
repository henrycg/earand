#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "dsa_params.h"
#include "pedersen_proof.h"
#include "test_common.h"

void mu_test_PedersenStatement_New()
{
  DsaParams params = DsaParams_New("secp256k1");
  const EC_GROUP* group = DsaParams_GetCurve(params);
  const EC_POINT* g = DsaParams_GetG(params);
  const EC_POINT* h = DsaParams_GetH(params);

  BIGNUM *a1 = DsaParams_RandomExponent(params);
  BIGNUM *a2 = DsaParams_RandomExponent(params);

  BN_CTX* ctx = BN_CTX_new();

  mu_ensure(a1);
  mu_ensure(a2);

  EC_POINT* commit_x = EC_POINT_new(group);
  EC_POINT* g_to_the_x = EC_POINT_new(group);

  mu_ensure(commit_x);
  mu_ensure(g_to_the_x);

  CHECK_CALL(EC_POINT_mul(group, commit_x, a1, NULL, NULL, ctx));
  CHECK_CALL(EC_POINT_mul(group, g_to_the_x, a2, NULL, NULL, ctx));

  PedersenStatement st = PedersenStatement_New(group, g, h, commit_x, g_to_the_x);

  BN_free(a1);
  BN_free(a2);

  BN_CTX_free(ctx);

  EC_POINT_free(commit_x);
  EC_POINT_free(g_to_the_x);

  PedersenStatement_Free(st);
  DsaParams_Free(params);
}

void mu_test_PedersenStatement_Correct()
{
  DsaParams params = DsaParams_New("secp256k1");
  const EC_GROUP* group = DsaParams_GetCurve(params);
  const EC_POINT* g = DsaParams_GetG(params);
  const EC_POINT* h = DsaParams_GetH(params);

  BN_CTX* ctx = BN_CTX_new();

  EC_POINT* commit_x = EC_POINT_new(group);
  EC_POINT* g_to_the_x = EC_POINT_new(group);

  mu_ensure(commit_x);
  mu_ensure(g_to_the_x);

  for(int i=0; i<20; i++) {

    BIGNUM *x = DsaParams_RandomExponent(params);
    BIGNUM *r = DsaParams_RandomExponent(params);

    CHECK_CALL(EC_POINT_mul(group, g_to_the_x, NULL, g, x, ctx));
    CHECK_CALL(EC_POINT_mul(group, commit_x, NULL, h, r, ctx));
    CHECK_CALL(EC_POINT_add(group, commit_x, g_to_the_x, commit_x, ctx));

    PedersenStatement st = PedersenStatement_New(group, g, h, commit_x, g_to_the_x);
    PedersenEvidence ev = PedersenEvidence_New(st, x, r);

    mu_ensure(PedersenEvidence_Verify(ev, st));

    // Write params to temp file
    FILE *file = tmpfile();
    mu_ensure(file);

    mu_ensure(PedersenEvidence_Serialize(ev, file));
    rewind(file);

    PedersenEvidence ev2 = PedersenEvidence_Unserialize(file);
    mu_ensure(ev2);
    mu_ensure(PedersenEvidence_Verify(ev2, st));

    fclose(file);

    PedersenStatement_Free(st);
    PedersenEvidence_Free(ev);
    PedersenEvidence_Free(ev2);

    BN_free(x);
    BN_free(r);
  }


  BN_CTX_free(ctx);

  EC_POINT_free(commit_x);
  EC_POINT_free(g_to_the_x);

  DsaParams_Free(params);
}

void mu_test_PedersenStatement_Incorrect()
{
  DsaParams params = DsaParams_New("secp256k1");
  const EC_GROUP* group = DsaParams_GetCurve(params);
  const EC_POINT* g = DsaParams_GetG(params);
  const EC_POINT* h = DsaParams_GetH(params);

  BN_CTX* ctx = BN_CTX_new();

  EC_POINT* commit_x = EC_POINT_new(group);
  EC_POINT* g_to_the_x = EC_POINT_new(group);

  mu_ensure(commit_x);
  mu_ensure(g_to_the_x);

  for(int i=0; i<20; i++) {

    BIGNUM *x = DsaParams_RandomExponent(params);
    BIGNUM *r = DsaParams_RandomExponent(params);

    CHECK_CALL(EC_POINT_mul(group, g_to_the_x, NULL, g, x, ctx));
    CHECK_CALL(EC_POINT_mul(group, commit_x, NULL, h, r, ctx));
    CHECK_CALL(EC_POINT_add(group, commit_x, g_to_the_x, commit_x, ctx));

    PedersenStatement st = PedersenStatement_New(group, g, h, commit_x, g_to_the_x);

    BN_add_word(r, 1);
    PedersenEvidence ev = PedersenEvidence_New(st, x, r);

    mu_ensure(!PedersenEvidence_Verify(ev, st));

    // Write params to temp file
    FILE *file = tmpfile();
    mu_ensure(file);

    mu_ensure(PedersenEvidence_Serialize(ev, file));
    rewind(file);

    PedersenEvidence ev2 = PedersenEvidence_Unserialize(file);
    mu_ensure(ev2);
    mu_ensure(!PedersenEvidence_Verify(ev2, st));

    fclose(file);

    PedersenStatement_Free(st);
    PedersenEvidence_Free(ev);
    PedersenEvidence_Free(ev2);

    BN_free(x);
    BN_free(r);
  }


  BN_CTX_free(ctx);

  EC_POINT_free(commit_x);
  EC_POINT_free(g_to_the_x);

  DsaParams_Free(params);
}
