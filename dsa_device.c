#include <string.h>

#include "dsa_device.h"
#include "ssl_client.h"
#include "util.h"

struct dsa_device {
  DsaParams params;
  BIGNUM* x;
  BIGNUM* x_prime;
  BIGNUM* a;

  // pub = g^a
  EC_POINT* public_key;

  BIGNUM* rand_x;
  BIGNUM* rand_x_prime;
  BIGNUM* rand_a;

  X509* cert;
};

static EVP_PKEY* CreateDsaKey(const_DsaDevice d);

DsaDevice DsaDevice_New(DsaParams params)
{
  DsaDevice d = safe_malloc(sizeof(*d));
  d->params = params;

  d->x = NULL;
  d->x_prime = NULL;
  d->a = NULL;

  d->rand_x = NULL;
  d->rand_x_prime = NULL;
  d->rand_a = NULL;

  d->cert = NULL;

  return d;
}

void DsaDevice_Free(DsaDevice d)
{
  if(d->x) BN_clear_free(d->x);
  if(d->x_prime) BN_clear_free(d->x_prime);
  if(d->a) BN_clear_free(d->a);

  if(d->rand_x) BN_clear_free(d->rand_x);
  if(d->rand_x_prime) BN_clear_free(d->rand_x_prime);
  if(d->rand_a) BN_clear_free(d->rand_a);
  if(d->cert) X509_free(d->cert);
  
  free(d);
}

void DsaRunEaSession(SSL* ssl, void* data) 
{
  int rfd, wfd;
  FILE* rfp;
  FILE* wfp;
  SetupFileDescriptors(ssl, &rfd, &rfp, &wfd, &wfp);

  DsaDevice device = (DsaDevice)data;
  EC_GROUP* group = DsaParams_GetCurve(device->params);
  BN_CTX* ctx = DsaParams_GetCtx(device->params);

  BIGNUM* v1 = BN_new();
  BIGNUM* v2 = BN_new();
  CHECK_CALL(v1);
  CHECK_CALL(v2);

  // Device makes entropy request
  EC_POINT* commit_x = EC_POINT_new(group);
  CHECK_CALL(commit_x);

  CHECK_CALL(DsaDevice_GenEntropyRequest(device, commit_x));

  // Send mode flag
  CHECK_CALL(fprintf(wfp, "%d\n", DSA_CLIENT));
  CHECK_CALL(!fflush(wfp));

  CHECK_CALL(WriteOnePoint(STRING_COMMIT_X, sizeof(STRING_COMMIT_X), wfp, group, commit_x, ctx));
  CHECK_CALL(!fflush(wfp));

  fprintf(stderr, "Sent commit\n");

  // Read x', rx from EA
  CHECK_CALL(ReadOneBignum(&v1, rfp, STRING_X_PRIME));
  CHECK_CALL(ReadOneBignum(&v2, rfp, STRING_RAND_X_PRIME));

  CHECK_CALL(DsaDevice_SetEntropyResponse(device, v1, v2));

  X509_REQ* req = X509_REQ_new();
  CHECK_CALL(DsaDevice_GenEaCertRequest(device, req, v1))

  // Write rand_a, X509 request
  CHECK_CALL(WriteOneBignum(STRING_RAND_A, 3, wfp, v1));
  CHECK_CALL(i2d_X509_REQ_fp(wfp, req));
  CHECK_CALL(!fflush(wfp));

  X509_REQ_free(req);
  // Read signature from EA
  if(!(device->cert = d2i_X509_fp(rfp, NULL))) {
    fatal("Could not read X509 response");
  }

  return;
}


X509* DsaDevice_RunProtocol(DsaDevice d, bool ca_sign,
    const char* ea_hostname, int ea_port,
    const char* ca_hostname, int ca_port)
{
  CHECK_CALL(MakeSSLRequest(ea_hostname, ea_port, &DsaRunEaSession, (void*)d));

  struct ca_request_data rr;
  rr.client_type = DSA_CLIENT;
  
  //rr.cert = NULL;
  CHECK_CALL(DsaDevice_GenCaCertRequest(d, &(rr.cert)));

  if(ca_sign) {
    CHECK_CALL(MakeSSLRequest(ca_hostname, ca_port, &RequestCaSignatureClient, (void*)&rr));
  }

  return rr.cert;
}

bool DsaDevice_GenEntropyRequest(DsaDevice d, EC_POINT* commit_x)
{
  CHECK_CALL(d->x = DsaParams_RandomExponent(d->params));
  CHECK_CALL(d->rand_x = DsaParams_RandomExponent(d->params));

  if(commit_x) EC_POINT_clear_free(commit_x);
  CHECK_CALL(commit_x = DsaParams_Commit(d->params, d->x, d->rand_x));

  return true;
}

bool DsaDevice_SetEntropyResponse(DsaDevice d, const BIGNUM* x_prime,
    const BIGNUM* rand_x_prime)
{
  CHECK_CALL(d->x_prime = BN_dup(x_prime));
  CHECK_CALL(d->rand_x_prime = BN_dup(rand_x_prime));

  d->a = BN_new();
  d->rand_a = BN_new();
  CHECK_CALL(d->a);
  CHECK_CALL(d->rand_a);

  // a = x + x' mod q
  CHECK_CALL(BN_mod_add(d->a, d->x, d->x_prime, 
        DsaParams_GetQ(d->params), DsaParams_GetCtx(d->params)));

  // rand_a = rand_x + rand_x' mod q
  CHECK_CALL(BN_mod_add(d->rand_a, d->rand_x, d->rand_x_prime, 
        DsaParams_GetQ(d->params), DsaParams_GetCtx(d->params)));

  d->public_key = DsaParams_MultiplyG(d->params, d->a);

  return true;
}

bool DsaDevice_GenEaCertRequest(DsaDevice d, X509_REQ* req, BIGNUM* a_prime)
{
  // Create key in EVP format
  EVP_PKEY* key = CreateDsaKey(d);
  CHECK_CALL(key);
  
  // Create x509 cert signing request (CSR)
  CHECK_CALL(X509_REQ_set_pubkey(req, key));

  // Add subject name to the CSR
  X509_NAME* subj = X509_REQ_get_subject_name(req);
  CHECK_CALL(X509_NAME_add_entry_by_txt(
      subj, "O", MBSTRING_ASC, 
      (const unsigned char *)"RSA Device", -1, -1, 0)); 
  CHECK_CALL(X509_REQ_set_subject_name(req, subj));

  CHECK_CALL(BN_copy(a_prime, d->rand_a));

  // Sign the CSR with our own RSA private key
  CHECK_CALL(X509_REQ_sign(req, key, EVP_ecdsa()));

  EVP_PKEY_free(key);
  return true;
}

bool DsaDevice_SetEaCertResponse(DsaDevice d, X509* cert)
{
  CHECK_CALL(d->cert = X509_dup(cert));
  return X509_verify(cert, DsaParams_GetEaPublicKey(d->params));
}

bool DsaDevice_GenCaCertRequest(DsaDevice d, X509** cert)
{
  return (*cert = X509_dup(d->cert));
}

bool DsaDevice_SetCaCertResponse(DsaDevice d, X509* cert)
{
  CHECK_CALL(d->cert = X509_dup(cert));
  return X509_verify(cert, DsaParams_GetCaPublicKey(d->params));
}

EVP_PKEY* CreateDsaKey(const_DsaDevice d)
{
  EVP_PKEY *evp = EVP_PKEY_new();
  EC_KEY *ec = EC_KEY_new();

  CHECK_CALL(EC_KEY_set_group(ec, DsaParams_GetCurve(d->params)));
  CHECK_CALL(EC_KEY_set_public_key(ec, d->public_key));
  CHECK_CALL(EC_KEY_set_private_key(ec, d->a));
  CHECK_CALL(EVP_PKEY_set1_EC_KEY(evp, ec));
  ASSERT(EC_KEY_check_key(ec));

  return evp;

}
