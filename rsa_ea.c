#include <stdio.h>
#include "rsa_ea.h"

struct rsa_ea {
  RsaParams params;
  BIGNUM* commit_x;
  BIGNUM* commit_y;
  BIGNUM* x_prime;
  BIGNUM* y_prime;
  BIGNUM* delta_x;
  BIGNUM* delta_y;
  BIGNUM* n;
  X509_REQ* req;
};

static BIGNUM* RecreateCommit(const_RsaParams params, 
    const BIGNUM* commit, const BIGNUM* prime, const BIGNUM* delta);

RsaEa RsaEa_New(RsaParams params, 
    const BIGNUM* commit_x, const BIGNUM* commit_y)
{
  RsaEa ea = safe_malloc(sizeof(*ea));
  ea->params = params;
  CHECK_CALL(ea->commit_x = BN_dup(commit_x));
  CHECK_CALL(ea->commit_y = BN_dup(commit_y));

  ea->x_prime = NULL;
  ea->y_prime = NULL;
  ea->delta_x = NULL;
  ea->delta_y = NULL;
  ea->n = NULL;

  return ea;
}

void RsaEa_Free(RsaEa ea)
{
  BN_free(ea->commit_x);
  BN_free(ea->commit_y);
  if(ea->x_prime) BN_clear_free(ea->x_prime);
  if(ea->y_prime) BN_clear_free(ea->y_prime);
  if(ea->delta_x) BN_clear_free(ea->delta_x);
  if(ea->delta_y) BN_clear_free(ea->delta_y);
  if(ea->n) BN_clear_free(ea->n);
  if(ea->req) X509_REQ_free(ea->req);
  
  free(ea);
}

void RsaEa_GenEntropyResponse(RsaEa ea, BIGNUM* x_prime, BIGNUM* y_prime)
{
  CHECK_CALL(ea->x_prime = RsaParams_RandomLargeValue(ea->params));
  CHECK_CALL(ea->y_prime = RsaParams_RandomLargeValue(ea->params));

  CHECK_CALL(BN_copy(x_prime, ea->x_prime));
  CHECK_CALL(BN_copy(y_prime, ea->y_prime));
}

bool RsaEa_SetCertRequest(RsaEa ea, X509_REQ* req, const BIGNUM* delta_x, 
    const BIGNUM* delta_y, const BIGNUM* rand_n, 
    const ProductEvidence ev)
{
  CHECK_CALL(ea->delta_x = BN_dup(delta_x));
  CHECK_CALL(ea->delta_y = BN_dup(delta_y));

  // Check that deltas are small
  BIGNUM *max = BN_new();
  CHECK_CALL(BN_set_word(max, RsaParams_GetDeltaMax(ea->params)));
  CHECK_CALL(BN_cmp(delta_x, max) == -1);
  CHECK_CALL(BN_cmp(delta_y, max) == -1);
  BN_free(max);

  // C(p, r_p) = C(x, r_p) g^{x'+dx}
  BIGNUM* commit_p = RecreateCommit(ea->params, ea->commit_x, ea->x_prime, ea->delta_x);
  BIGNUM* commit_q = RecreateCommit(ea->params, ea->commit_y, ea->y_prime, ea->delta_y);

  CHECK_CALL(commit_p);
  CHECK_CALL(commit_q);

  BIGNUM* n = BN_new();
  CHECK_CALL(n);
  EVP_PKEY* pkey = X509_REQ_get_pubkey(req);
  CHECK_CALL(pkey);

  RSA* rsa = EVP_PKEY_get1_RSA(pkey);

  CHECK_CALL(BN_copy(n, rsa->n));

  EVP_PKEY_free(pkey);
  RSA_free(rsa);

  CHECK_CALL(ea->req = X509_REQ_dup(req));

  // Client has commits to p and q
  BIGNUM* commit_n = IntegerGroup_Commit(RsaParams_GetGroup(ea->params),
      n, rand_n);

  /*
  printf("C(p) = "); BN_print_fp(stdout, commit_p); puts("");
  printf("C(q) = "); BN_print_fp(stdout, commit_q); puts("");
  printf("C(n) = "); BN_print_fp(stdout, commit_n); puts("");
  */

  ProductStatement st = ProductStatement_New(RsaParams_GetGroup(ea->params),
      commit_p, commit_q, commit_n);

  bool retval = ProductEvidence_Verify(ev, st);

  CHECK_CALL(ea->n = BN_dup(n));

  ProductStatement_Free(st);

  BN_clear_free(commit_p);
  BN_clear_free(commit_q);
  BN_clear_free(commit_n);
  BN_clear_free(n);

  return retval;
}

bool RsaEa_GetCertResponse(RsaEa ea, X509** cert)
{
  CHECK_CALL(ea->req);
  *cert = RequestToCertificate(ea->req, RsaParams_GetEaPrivateKey(ea->params));
  return (*cert != NULL);
}

BIGNUM* RecreateCommit(const_RsaParams params, 
    const BIGNUM* commit, const BIGNUM* prime, const BIGNUM* delta)
{
  BIGNUM* out = BN_new();
  CHECK_CALL(out);

  // We use "big" Q and P for the group order and modulus
  // and "little" q and p for the RSA factors.

  const BIGNUM *g = IntegerGroup_GetG(RsaParams_GetGroup(params));
  const BIGNUM *Q = IntegerGroup_GetQ(RsaParams_GetGroup(params));
  const BIGNUM *P = IntegerGroup_GetP(RsaParams_GetGroup(params));
  BN_CTX *ctx = IntegerGroup_GetCtx(RsaParams_GetGroup(params));

  CHECK_CALL(out = BN_dup(prime));

  // commit_p = x' + dx mod q
  CHECK_CALL(BN_mod_add(out, out, delta, Q, ctx));
  // commit_p = g^{x' + dx} mod p
  CHECK_CALL(BN_mod_exp(out, g, out, P, ctx));
  // commit_p = C(x) g^{x' + dx} mod p
  CHECK_CALL(BN_mod_mul(out, out, commit, P, ctx));

  return out;
}
