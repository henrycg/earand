#include <string.h>

#include "dsa_device.h"
#include "pedersen_proof.h"
#include "ssl_client.h"
#include "util.h"

struct dsa_device {
  DsaParams params;
  BIGNUM* x;
  BIGNUM* x_prime;
  BIGNUM* a;

  PedersenStatement st;

  EC_POINT* g_to_the_x;
  EC_POINT* commit_x;

  // pub = g^a
  EC_POINT* public_key;

  BIGNUM* rand_x;

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
  d->commit_x = NULL;
  d->g_to_the_x = NULL;
  d->public_key = NULL;

  d->st = NULL;

  d->cert = NULL;

  return d;
}

void DsaDevice_Free(DsaDevice d)
{
  if(d->x) BN_clear_free(d->x);
  if(d->x_prime) BN_clear_free(d->x_prime);
  if(d->a) BN_clear_free(d->a);

  if(d->rand_x) BN_clear_free(d->rand_x);
  if(d->commit_x) EC_POINT_clear_free(d->commit_x);
  if(d->g_to_the_x) EC_POINT_clear_free(d->g_to_the_x);
  if(d->public_key) EC_POINT_clear_free(d->public_key);
  if(d->st) PedersenStatement_Free(d->st);
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
  ASSERT(v1);

  // Device makes entropy request
  EC_POINT* commit_x = EC_POINT_new(group);
  ASSERT(commit_x);

  CHECK_CALL(DsaDevice_GenEntropyRequest(device, &commit_x));

  EC_POINT_free(commit_x);

  // Send mode flag
  CHECK_CALL(fprintf(wfp, "%d\n", DSA_CLIENT));
  CHECK_CALL(!fflush(wfp));

  CHECK_CALL(WriteOnePoint(STRING_COMMIT_X, sizeof(STRING_COMMIT_X), wfp, group, device->commit_x, ctx));
  CHECK_CALL(!fflush(wfp));

  fprintf(stderr, "Sent commit\n");

  // Read x' from EA
  CHECK_CALL(ReadOneBignum(&v1, rfp, STRING_X_PRIME));

  CHECK_CALL(DsaDevice_SetEntropyResponse(device, v1));

  X509_REQ* req = X509_REQ_new();
  PedersenEvidence ev = NULL;
  CHECK_CALL(DsaDevice_GenEaCertRequest(device, &ev, &req))

  // Write proof, X509 request
  CHECK_CALL(PedersenEvidence_Serialize(ev, wfp));
  CHECK_CALL(i2d_X509_REQ_fp(wfp, req));
  CHECK_CALL(!fflush(wfp));

  PedersenEvidence_Free(ev);

  X509_REQ_free(req);
  // Read signature from EA
  if(!(device->cert = d2i_X509_fp(rfp, NULL))) {
    fatal("Could not read X509 response");
  }

  printf("Got cert from EA\n");

  BN_clear_free(v1);

  fclose(rfp);
  fclose(wfp);

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

bool DsaDevice_GenEntropyRequest(DsaDevice d, EC_POINT** commit_x)
{
  CHECK_CALL(d->x = DsaParams_RandomExponent(d->params));
  CHECK_CALL(d->rand_x = DsaParams_RandomExponent(d->params));
  CHECK_CALL(d->g_to_the_x = DsaParams_MultiplyG(d->params, d->x));
  if(d->commit_x) EC_POINT_clear_free(d->commit_x);

  EC_POINT* r_to_the_h;
  CHECK_CALL(r_to_the_h = DsaParams_MultiplyH(d->params, d->rand_x));

  CHECK_CALL(d->commit_x = DsaParams_Add(d->params, d->g_to_the_x, r_to_the_h));
  CHECK_CALL(EC_POINT_copy(*commit_x, d->commit_x));
  EC_POINT_clear_free(r_to_the_h);

  return true;
}

bool DsaDevice_SetEntropyResponse(DsaDevice d, const BIGNUM* x_prime)
{
  if(d->x_prime != NULL) BN_clear_free(d->x_prime);
  if(d->a != NULL) BN_clear_free(d->a);
  if(d->public_key != NULL) EC_POINT_free(d->public_key);

  CHECK_CALL(d->x_prime = BN_dup(x_prime));

  d->a = BN_new();
  CHECK_CALL(d->a);

  // a = x + x' mod q
  CHECK_CALL(BN_mod_add(d->a, d->x, d->x_prime, 
        DsaParams_GetQ(d->params), DsaParams_GetCtx(d->params)));

  d->public_key = DsaParams_MultiplyG(d->params, d->a);

  d->st = PedersenStatement_New(DsaParams_GetCurve(d->params),
      DsaParams_GetG(d->params), DsaParams_GetH(d->params),
      d->commit_x, d->g_to_the_x);
  BN_DEBUG("x_prime", d->x_prime);
  EC_DEBUG("pk", DsaParams_GetCurve(d->params), 
      d->public_key, DsaParams_GetCtx(d->params));
  EC_DEBUG("g_to_the_x", DsaParams_GetCurve(d->params), 
      d->g_to_the_x, DsaParams_GetCtx(d->params));
  EC_DEBUG("commit_x", DsaParams_GetCurve(d->params), 
      d->commit_x, DsaParams_GetCtx(d->params));

  return true;
}

bool DsaDevice_GenEaCertRequest(DsaDevice d, PedersenEvidence* ev, X509_REQ** req)
{
  // Create key in EVP format
  EVP_PKEY* key = CreateDsaKey(d);
  CHECK_CALL(key);
  
  // Create x509 cert signing request (CSR)
  CHECK_CALL(X509_REQ_set_pubkey(*req, key));

  // Add subject name to the CSR
  X509_NAME* subj = X509_REQ_get_subject_name(*req);
  CHECK_CALL(X509_NAME_add_entry_by_txt(
      subj, "O", MBSTRING_ASC, 
      (const unsigned char *)"DSA Device", -1, -1, 0)); 
  CHECK_CALL(X509_REQ_set_subject_name(*req, subj));

  // Sign the CSR with our own RSA private key
  CHECK_CALL(X509_REQ_sign(*req, key, EVP_ecdsa()));

  EVP_PKEY_free(key);
  *ev = PedersenEvidence_New(d->st, d->x, d->rand_x);
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

  EC_KEY_free(ec);

  return evp;

}
