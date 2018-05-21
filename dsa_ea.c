#include <stdio.h>
#include "dsa_ea.h"

struct dsa_ea {
  DsaParams params;

  EC_POINT* commit_x;
  BIGNUM* x_prime;
  X509* cert;
};

DsaEa DsaEa_New(DsaParams params)
{
  DsaEa ea = safe_malloc(sizeof(*ea));
  ea->params = params;
  ea->commit_x = NULL;
  ea->x_prime = NULL;
  ea->cert = NULL;

  return ea;
}

void DsaEa_Free(DsaEa ea)
{
  if(ea->commit_x) EC_POINT_clear_free(ea->commit_x);
  if(ea->x_prime) BN_clear_free(ea->x_prime);
  if(ea->cert) X509_free(ea->cert);

  free(ea);
}

bool DsaEa_SetEntropyRequest(DsaEa ea, const EC_POINT* commit_x)
{
  // Store commitment to x
  return (ea->commit_x = EC_POINT_dup(commit_x, DsaParams_GetCurve(ea->params)));
}

bool DsaEa_GetEntropyResponse(DsaEa ea, BIGNUM** x_prime)
{
  // Pick random x'
  if(ea->x_prime) BN_clear_free(ea->x_prime);
  ea->x_prime = DsaParams_RandomExponent(ea->params);

  // Return x'
  CHECK_CALL(BN_copy(*x_prime, ea->x_prime));

  return true;
}

bool DsaEa_SetCertRequest(DsaEa ea, const_PedersenEvidence ev, X509_REQ* req)
{
  const EC_GROUP* curve = DsaParams_GetCurve(ea->params);
  BN_CTX* ctx = DsaParams_GetCtx(ea->params);

  EVP_PKEY* pkey = X509_REQ_get_pubkey(req);
  CHECK_CALL(pkey);

  EC_KEY* eckey = EVP_PKEY_get1_EC_KEY(pkey);
  CHECK_CALL(eckey);

  const EC_POINT* old_point = EC_KEY_get0_public_key(eckey);
  CHECK_CALL(old_point);

  //EC_DEBUG("pub", EC_KEY_get0_group(eckey), old_point, ctx);

  // Covert to point on our curve
  // Get x, y 
  BIGNUM* x = BN_new();
  BIGNUM* y = BN_new();
  CHECK_CALL(EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(eckey),
        old_point, x, y, ctx));

  // Create new point
  EC_POINT* new_point = EC_POINT_new(curve);
  CHECK_CALL(EC_POINT_set_affine_coordinates_GFp(curve, new_point, x, y, ctx));

  BN_free(x);
  BN_free(y);

  // Get g^x'
  CHECK_CALL(ea->x_prime);
  EC_POINT* tmp = DsaParams_MultiplyG(ea->params, ea->x_prime);
  CHECK_CALL(EC_POINT_invert(DsaParams_GetCurve(ea->params), tmp, ctx));
  CHECK_CALL(tmp);

  // g^x = A / g^x'
  EC_POINT* g_to_the_x = DsaParams_Add(ea->params, tmp, new_point);
  CHECK_CALL(g_to_the_x);

  PedersenStatement st = PedersenStatement_New(curve,
      DsaParams_GetG(ea->params), DsaParams_GetH(ea->params), 
      ea->commit_x, g_to_the_x);
  EC_DEBUG("g_to_the_x", curve, g_to_the_x, ctx);
  EC_DEBUG("pk", curve, new_point, ctx);
  EC_DEBUG("commit_x", curve, ea->commit_x, ctx);

  if(!PedersenEvidence_Verify(ev, st))
    fatal("Evidence failed to verify!");

  ea->cert = RequestToCertificate(req, DsaParams_GetEaPrivateKey(ea->params));
  CHECK_CALL(ea->cert);

  PedersenStatement_Free(st);
  EC_POINT_free(g_to_the_x);
  EC_POINT_free(tmp);
  EC_POINT_free(new_point);
  EC_KEY_free(eckey);
  EVP_PKEY_free(pkey);
  return true;
}

bool DsaEa_GetCertResponse(DsaEa ea, X509** cert)
{
  //X509_print_fp(stderr, ea->cert);
  *cert = X509_dup(ea->cert);
  return (*cert != NULL);
}

