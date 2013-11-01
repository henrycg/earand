#include <string.h>
#include "dsa_ca.h"

struct dsa_ca {
  DsaParams params;
};

DsaCa DsaCa_New(DsaParams params)
{
  DsaCa ca = safe_malloc(sizeof(*ca));
  ca->params = params;

  return ca;
}

void DsaCa_Free(DsaCa ca)
{
  free(ca);
}

X509* DsaCa_SignCertificate(DsaCa ca, X509* cert_in)
{
  CHECK_CALL(X509_verify(cert_in, DsaParams_GetEaPublicKey(ca->params)));
  CHECK_CALL(cert_in);
  X509* cert_out = X509_dup(cert_in);
  CHECK_CALL(cert_out);

  CHECK_CALL(X509_sign(cert_in, DsaParams_GetCaPrivateKey(ca->params), EVP_sha1()));
  
  return cert_out;
}

