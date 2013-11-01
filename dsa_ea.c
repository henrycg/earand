#include <stdio.h>
#include "dsa_ea.h"

struct dsa_ea {
  DsaParams params;
  EC_POINT* commit_a;
  X509* cert;
};

DsaEa DsaEa_New(DsaParams params)
{
  DsaEa ea = safe_malloc(sizeof(*ea));
  ea->params = params;

  return ea;
}

void DsaEa_Free(DsaEa ea)
{
  if(ea->commit_a) EC_POINT_clear_free(ea->commit_a);
  if(ea->cert) X509_free(ea->cert);

  free(ea);
}

bool DsaEa_GetEntropyResponse(DsaEa ea, const EC_POINT* commit_x, 
    BIGNUM* x_prime, BIGNUM* rand_x_prime)
{
  // Commit to x'
  if(x_prime) BN_clear_free(x_prime);
  x_prime = DsaParams_RandomExponent(ea->params);
  CHECK_CALL(x_prime);

  if(rand_x_prime) BN_clear_free(rand_x_prime);
  rand_x_prime = DsaParams_RandomExponent(ea->params);
  CHECK_CALL(rand_x_prime);

  EC_POINT* commit_x_prime = DsaParams_Commit(ea->params, x_prime, rand_x_prime);
  CHECK_CALL(commit_x_prime);

  // Get commit to a = x+x'
  ea->commit_a = DsaParams_Add(ea->params, commit_x, commit_x_prime);
  CHECK_CALL(ea->commit_a);

  EC_POINT_clear_free(commit_x_prime);

  return true;
}

bool DsaEa_SetCertRequest(DsaEa ea, const BIGNUM* rand_a, X509_REQ* req)
{
  // check that:
  //    pub_key * (h^rand_a) == commit_a

  EVP_PKEY* pkey = X509_REQ_get_pubkey(req);
  CHECK_CALL(pkey);

  EC_KEY* eckey = EVP_PKEY_get1_EC_KEY(pkey);
  CHECK_CALL(eckey);

  const EC_POINT* pub_point = EC_KEY_get0_public_key(eckey);
  CHECK_CALL(pub_point);

  // Recreate commitment to a = (pk)(h^{rand_a})
  EC_POINT* h_to_ra = DsaParams_MultiplyH(ea->params, rand_a);
  EC_POINT* commit_a = DsaParams_Add(ea->params, pub_point, h_to_ra);

  CHECK_CALL(!EC_POINT_cmp(DsaParams_GetCurve(ea->params), commit_a, 
        ea->commit_a, DsaParams_GetCtx(ea->params)));

  EC_POINT_clear_free(commit_a);
  EC_POINT_clear_free(h_to_ra);
  EVP_PKEY_free(pkey);
  EC_KEY_free(eckey);

  ea->cert = RequestToCertificate(req, DsaParams_GetEaPrivateKey(ea->params));
  CHECK_CALL(ea->cert);

  return true;
}

bool DsaEa_GetCertResponse(DsaEa ea, X509** cert)
{
  //X509_print_fp(stderr, ea->cert);
  *cert = X509_dup(ea->cert);
  return (*cert != NULL);
}

