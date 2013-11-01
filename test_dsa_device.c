#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "dsa_ca.h"
#include "dsa_device.h"
#include "dsa_ea.h"
#include "test_common.h"

void mu_test_DsaDevice_New() 
{
  DsaParams params = DsaParams_New("secp224r1");
  DsaDevice dsa = DsaDevice_New(params);

  DsaDevice_Free(dsa);
  DsaParams_Free(params);
}

void mu_test_DsaDevice_Protocol() 
{
  DsaParams params = DsaParams_New("secp224r1");
  DsaDevice dsa = DsaDevice_New(params);
  EC_GROUP* group = DsaParams_GetCurve(params);

  // Device makes entropy request
  EC_POINT* commit_x = EC_POINT_new(group);
  mu_ensure(commit_x);

  mu_check(DsaDevice_GenEntropyRequest(dsa, commit_x));

  // EA sends back entropy response
  DsaEa ea = DsaEa_New(params);
  mu_ensure(ea);

  BIGNUM* x_prime = BN_new();
  BIGNUM* rand_x_prime = BN_new();
  mu_ensure(x_prime);
  mu_ensure(rand_x_prime);

  mu_ensure(DsaEa_GetEntropyResponse(ea, commit_x, x_prime, rand_x_prime));

  // Device gets EA's response
  mu_ensure(DsaDevice_SetEntropyResponse(dsa, x_prime, rand_x_prime));

  // Device generates a cert request for EA
  X509_REQ* req = X509_REQ_new();
  BIGNUM* a_prime = BN_new();
  mu_ensure(DsaDevice_GenEaCertRequest(dsa, req, a_prime));

  // EA signs certificate
  mu_ensure(DsaEa_SetCertRequest(ea, a_prime, req));
  X509* cert;
  mu_ensure(DsaEa_GetCertResponse(ea, &cert));

  BN_free(a_prime);

  // CA signs certificate
  DsaCa ca = DsaCa_New(params);

  mu_check((cert = DsaCa_SignCertificate(ca, cert)));
  mu_check(DsaDevice_SetCaCertResponse(dsa, cert));
  X509_free(cert);

  DsaCa_Free(ca);

  X509_REQ_free(req);
  BN_free(x_prime);
  BN_free(rand_x_prime);
  EC_POINT_free(commit_x);

  DsaEa_Free(ea);
  DsaDevice_Free(dsa);
  DsaParams_Free(params);
}

