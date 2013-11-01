#include <string.h>
#include "rsa_ca.h"

struct rsa_ca {
  RsaParams params;
};

RsaCa RsaCa_New(RsaParams params)
{
  RsaCa ea = safe_malloc(sizeof(*ea));
  ea->params = params;

  return ea;
}

void RsaCa_Free(RsaCa ca)
{
  
  free(ca);
}

X509* RsaCa_SignCertificate(RsaCa ca, X509* cert)
{
  CHECK_CALL(X509_verify(cert, RsaParams_GetEaPublicKey(ca->params)));

  X509* cert_out = X509_dup(cert);
  CHECK_CALL(cert_out);
  CHECK_CALL(X509_sign(cert_out, RsaParams_GetCaPrivateKey(ca->params), EVP_sha1()));
  return cert_out;
}


