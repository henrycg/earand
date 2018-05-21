#include <string.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "product_proof.h"
#include "rsa_device.h"
#include "rsa_ea.h"
#include "rsa_params.h"
#include "ssl_client.h"
#include "util.h"

static bool MakePrime(RsaParams params, const BIGNUM* value, 
    BIGNUM** delta, BN_CTX* ctx);
static EVP_PKEY* CreateRsaKey(const_RsaDevice d);
static bool GenerateCertRequest(RsaDevice d, X509_REQ* req);

struct rsa_device {
  RsaParams params;
  BIGNUM* x;
  BIGNUM* y;
  BIGNUM* x_prime;
  BIGNUM* y_prime;
  BIGNUM* rand_p;
  BIGNUM* rand_q;
  BIGNUM* p; // First RSA factor   p = x + x' + delta_x
  BIGNUM* q; // Second RSA factor  q = y + y' + delta_y
  BIGNUM* n; // n = p*q

  X509* cert; // certificate (EA or CA signed)

  unsigned char* ea_sig;
  int ea_sig_len;
};

void RunEaSession(SSL* ssl, void* data) 
{
  int rfd, wfd;
  FILE* rfp;
  FILE* wfp;
  SetupFileDescriptors(ssl, &rfd, &rfp, &wfd, &wfp);

  RsaDevice device = (RsaDevice)data;

  // Device makes entropy request
  BIGNUM* v1 = BN_new();
  BIGNUM* v2 = BN_new(); 
  BIGNUM* v3 = BN_new(); 
  BIGNUM* v4 = BN_new(); 

  CHECK_CALL(v1);
  CHECK_CALL(v2);
  CHECK_CALL(RsaDevice_GenEntropyRequest(device, v1, v2));

  PrintTime("Sending commits to EA");
  // Send mode flag
  CHECK_CALL(fprintf(wfp, "%d\n", RSA_CLIENT));
  CHECK_CALL(!fflush(wfp));

  CHECK_CALL(WriteOneBignum(STRING_COMMIT_X, sizeof(STRING_COMMIT_X), wfp, v1));
  CHECK_CALL(WriteOneBignum(STRING_COMMIT_Y, sizeof(STRING_COMMIT_Y), wfp, v2));
  CHECK_CALL(!fflush(wfp));

  PrintTime("...done");

  // Read x', y' from EA
  PrintTime("Reading entropy from EA");
  CHECK_CALL(ReadOneBignum(&v1, rfp, STRING_X_PRIME));
  CHECK_CALL(ReadOneBignum(&v2, rfp, STRING_Y_PRIME));
  PrintTime("...done");

  CHECK_CALL(RsaDevice_SetEntropyResponse(device, v1, v2));

  // Send proof to EA 
  ProductEvidence ev = NULL;
  X509_REQ* req = X509_REQ_new();
  CHECK_CALL(req);
  CHECK_CALL(RsaDevice_GenEaSigningRequest(device, req, v1, v2, v3, &ev));
  CHECK_CALL(ev);

  PrintTime("Sending cert to EA");
  CHECK_CALL(i2d_X509_REQ_fp(wfp, req));
  //fprintf(wfp, "\n");
  CHECK_CALL(!fflush(wfp));

  CHECK_CALL(WriteOneBignum(STRING_DELTA_X, sizeof(STRING_DELTA_X), wfp, v1));
  CHECK_CALL(WriteOneBignum(STRING_DELTA_Y, sizeof(STRING_DELTA_Y), wfp, v2));
  CHECK_CALL(WriteOneBignum(STRING_MODULUS_RAND, sizeof(STRING_MODULUS_RAND), wfp, v3));
  CHECK_CALL(ProductEvidence_Serialize(ev, wfp));
  CHECK_CALL(!fflush(wfp));
  PrintTime("...done");

  X509_REQ_free(req);

  ProductEvidence_Free(ev);

  X509* cert = NULL;
  PrintTime("Reading cert from EA");
  if(!(cert = d2i_X509_fp(rfp, NULL))) {
    fatal("Could not read X509 response");
  }
  PrintTime("...done");

  fclose(rfp);
  fclose(wfp);

  BN_clear_free(v1);
  BN_clear_free(v2);
  BN_clear_free(v3);
  BN_clear_free(v4);

  // Give EA signature back to device
  CHECK_CALL(RsaDevice_SetEaCertResponse(device, cert));

  X509_free(cert);
  return;
}

RsaDevice RsaDevice_New(RsaParams params)
{
  RsaDevice d = safe_malloc(sizeof(*d));
  d->params = params;
  d->x = NULL;
  d->y = NULL;
  d->x_prime = NULL;
  d->y_prime = NULL;
  d->rand_p = NULL;
  d->rand_q = NULL;
  d->p = NULL;
  d->q = NULL;
  d->n = NULL;
  //d->proof_st = NULL;
  //d->proof_ev = NULL;
  d->ea_sig = NULL;
  d->cert = NULL;

  return d;
}

void RsaDevice_Free(RsaDevice d)
{
  //if(d->proof_st) ProductStatement_Free(d->proof_st);
  //if(d->proof_ev) ProductEvidence_Free(d->proof_ev);
  if(d->x) BN_clear_free(d->x);
  if(d->y) BN_clear_free(d->y);
  if(d->x_prime) BN_clear_free(d->x_prime);
  if(d->y_prime) BN_clear_free(d->y_prime);
  if(d->rand_p) BN_clear_free(d->rand_p);
  if(d->rand_q) BN_clear_free(d->rand_q);
  if(d->p) BN_clear_free(d->p);
  if(d->q) BN_clear_free(d->q);
  if(d->n) BN_free(d->n);

  if(d->ea_sig) free(d->ea_sig);
  if(d->cert) X509_free(d->cert);
  
  free(d);
}

X509* RsaDevice_RunProtocol(RsaDevice d, bool ca_sign,
    const char* ea_hostname, int ea_port,
    const char* ca_hostname, int ca_port)
{
  PrintTime("Connecting to EA");
  CHECK_CALL(MakeSSLRequest(ea_hostname, ea_port, &RunEaSession, (void*)d));
  PrintTime("Closed connection to EA");

  struct ca_request_data rr;
  rr.client_type = RSA_CLIENT;
  rr.cert = X509_new();

  CHECK_CALL(rr.cert);
  PrintTime("Generating CA request");
  CHECK_CALL(RsaDevice_GenCaCertRequest(d, &(rr.cert)));
  PrintTime("Done generating CA request");

  if(ca_sign) {
    PrintTime("Beginning CA session");
    CHECK_CALL(MakeSSLRequest(ca_hostname, ca_port, &RequestCaSignatureClient, (void*)&rr));
  }

  return rr.cert;
}

bool RsaDevice_GenEntropyRequest(RsaDevice d,
    BIGNUM* commit_x, BIGNUM* commit_y)
{
  if(d->x || d->y) return false;

  PrintTime("Getting x, y, r_p, r_q");
  CHECK_CALL(d->x = RsaParams_RandomLargeValue(d->params));
  CHECK_CALL(d->y = RsaParams_RandomLargeValue(d->params));
  CHECK_CALL(d->rand_p = IntegerGroup_RandomExponent(RsaParams_GetGroup(d->params)));
  CHECK_CALL(d->rand_q = IntegerGroup_RandomExponent(RsaParams_GetGroup(d->params)));
  PrintTime("...done");

  bool retval = (d->x && d->y && d->rand_p && d->rand_q);

  PrintTime("Generating C(x), C(y)");
  BIGNUM* cx = IntegerGroup_Commit(RsaParams_GetGroup(d->params), d->x, d->rand_p);
  BIGNUM* cy = IntegerGroup_Commit(RsaParams_GetGroup(d->params), d->y, d->rand_q);
  PrintTime("...done");


  CHECK_CALL(cx);
  CHECK_CALL(cy);

  CHECK_CALL(BN_copy(commit_x, cx));
  CHECK_CALL(BN_copy(commit_y, cy));

  BN_clear_free(cx);
  BN_clear_free(cy);

  return retval;
}

bool RsaDevice_SetEntropyResponse(RsaDevice d, 
    const BIGNUM* x_prime, const BIGNUM* y_prime)
{
  if(!RsaParams_InRange(d->params, x_prime)) return false;
  if(!RsaParams_InRange(d->params, y_prime)) return false;

  CHECK_CALL(d->x_prime = BN_dup(x_prime));
  CHECK_CALL(d->y_prime = BN_dup(y_prime));

  return true;
}

bool RsaDevice_GenEaSigningRequest(RsaDevice d,
    X509_REQ* req, BIGNUM* delta_x, BIGNUM* delta_y,
    BIGNUM* rand_n, ProductEvidence* ev)
{
  BN_zero(delta_x);
  BN_zero(delta_y);

  PrintTime("Calculating x+x' and y+y'");
  // p = x + x'
  CHECK_CALL(d->p = BN_dup(d->x));
  CHECK_CALL(BN_add(d->p, d->p, d->x_prime));

  // q = y + y'
  CHECK_CALL(d->q = BN_dup(d->y));
  CHECK_CALL(BN_add(d->q, d->q, d->y_prime));
  PrintTime("...done");

  PrintTime("Making finding deltas to make p and q prime");
  if(!MakePrime(d->params, d->p, &delta_x, RsaParams_GetCtx(d->params)))
    return false;

  if(!MakePrime(d->params, d->q, &delta_y, RsaParams_GetCtx(d->params)))
    return false;
  PrintTime("...done");

  PrintTime("Adding deltas to p and q");
  // p = x + x' + delta_x
  CHECK_CALL(BN_add(d->p, d->p, delta_x));

  // q = y + y' + delta_y
  CHECK_CALL(BN_add(d->q, d->q, delta_y));
  PrintTime("...done");

  PrintTime("Calculating n");
  // n = p*q
  CHECK_CALL(d->n = BN_new());
  CHECK_CALL(BN_mul(d->n, d->p, d->q, RsaParams_GetCtx(d->params)));
  ASSERT(BN_cmp(d->n, IntegerGroup_GetQ(RsaParams_GetGroup(d->params))) == -1);
  PrintTime("...done");

  const_IntegerGroup group = RsaParams_GetGroup(d->params);

  // Get randomness for commitment to n
  PrintTime("Picking r_n");
  BIGNUM* r_n = IntegerGroup_RandomExponent(group);
  CHECK_CALL(r_n);
  CHECK_CALL(BN_copy(rand_n, r_n));
  BN_clear_free(r_n);
  PrintTime("...done");

  PrintTime("Generating commits to p,q,n");
  // Commit to p
  BIGNUM* commit_p = IntegerGroup_Commit(group, d->p, d->rand_p);
  CHECK_CALL(commit_p);

  // Commit to q
  BIGNUM* commit_q = IntegerGroup_Commit(group, d->q, d->rand_q);

  // Commit to n
  BIGNUM* commit_n = IntegerGroup_Commit(group, d->n, rand_n);
  PrintTime("...done");

  /*
  printf("C(p) = "); BN_print_fp(stdout, commit_p); puts("");
  printf("C(q) = "); BN_print_fp(stdout, commit_q); puts("");
  printf("C(n) = "); BN_print_fp(stdout, commit_n); puts("");
  */
 
  PrintTime("Generating prodproof");
  ProductStatement st = ProductStatement_New(RsaParams_GetGroup(d->params),
      commit_p, commit_q, commit_n);
  PrintTime("...done");

  // Generate proof that n = p*q
  PrintTime("Generating prodevidence");
  *ev = ProductEvidence_New(st, d->p, d->rand_p, d->rand_q, rand_n);
  PrintTime("...done");

  ProductStatement_Free(st);

  BN_clear_free(commit_p);
  BN_clear_free(commit_q);
  BN_clear_free(commit_n);

  CHECK_CALL(req);
  PrintTime("Generating certificate");
  CHECK_CALL(GenerateCertRequest(d, req));
  PrintTime("...done");

  return true;
}

bool RsaDevice_SetEaCertResponse(RsaDevice d, X509* cert)
{
  d->cert = X509_dup(cert);
  CHECK_CALL(d->cert);
  return X509_verify(d->cert, RsaParams_GetEaPublicKey(d->params));
}

bool RsaDevice_GenCaCertRequest(RsaDevice d, X509** cert)
{
  //X509_print_fp(stderr, d->cert);
  CHECK_CALL(*cert = X509_dup(d->cert));
  return true;
}

bool RsaDevice_SetCaCertResponse(RsaDevice d, X509* cert)
{
  if(d->cert) X509_free(d->cert);
  CHECK_CALL(d->cert = X509_dup(cert));
  return X509_verify(cert, RsaParams_GetCaPublicKey(d->params));
}

const BIGNUM* RsaDevice_GetX(const_RsaDevice rsa)
{
  return rsa->x;
}

const BIGNUM* RsaDevice_GetY(const_RsaDevice rsa)
{
  return rsa->y;
}

const BIGNUM* RsaDevice_GetXPrime(const_RsaDevice rsa)
{
  return rsa->x_prime;
}

const BIGNUM* RsaDevice_GetYPrime(const_RsaDevice rsa)
{
  return rsa->y_prime;
}

const BIGNUM* RsaDevice_GetP(const_RsaDevice rsa)
{
  return rsa->p;
}

const BIGNUM* RsaDevice_GetQ(const_RsaDevice rsa)
{
  return rsa->q;
}

const BIGNUM* RsaDevice_GetN(const_RsaDevice rsa)
{
  return rsa->n;
}

bool MakePrime(RsaParams params, const BIGNUM* value, BIGNUM** delta_ret, 
    BN_CTX* ctx)
{
  BIGNUM* tmp = BN_dup(value);
  CHECK_CALL(tmp);

  // Find a delta such that 
  //    p = value + delta
  // is prime
  const int delta_max = RsaParams_GetDeltaMax(params);

  bool is_even = !BN_is_odd(tmp);
  if(is_even) {
    CHECK_CALL(BN_add_word(tmp, 1));
  }

  if(!RsaPrime(*delta_ret, tmp, ctx)) return false;
 
  if(is_even) {
    CHECK_CALL(BN_add_word(*delta_ret, 1));
  }

//  printf("%llu %d\n", BN_get_word(*delta_ret), delta_max);
  if(BN_get_word(*delta_ret) > delta_max) return false;

  BN_clear_free(tmp);

  return true;
}

EVP_PKEY* CreateRsaKey(const_RsaDevice d)
{
  BN_CTX* ctx = IntegerGroup_GetCtx(RsaParams_GetGroup(d->params));
  // phi(n) = (p-1)(q-1)
  BIGNUM *phi_n, *pm, *qm;
  phi_n = BN_new();
  CHECK_CALL(phi_n);
  CHECK_CALL(pm = BN_dup(d->p));
  CHECK_CALL(qm = BN_dup(d->q));
  CHECK_CALL(BN_sub_word(pm, 1));
  CHECK_CALL(BN_sub_word(qm, 1));
  CHECK_CALL(BN_mul(phi_n, pm, qm, ctx));

  EVP_PKEY *evp = EVP_PKEY_new();
  RSA *rsa = RSA_new();
  CHECK_CALL(evp);
  CHECK_CALL(rsa);

  CHECK_CALL(rsa->n = BN_dup(d->n)); // public modulus
  CHECK_CALL(rsa->e = BN_new()); // public exponent
  BN_set_word(rsa->e, RsaEncryptionExponent);

  rsa->d = BN_new();              // private exponent
  CHECK_CALL(rsa->d);
  CHECK_CALL(BN_mod_inverse(rsa->d, rsa->e, phi_n, ctx));

  CHECK_CALL(rsa->p = BN_dup(d->p)); // secret prime factor
  CHECK_CALL(rsa->q = BN_dup(d->q)); // secret prime factor
  rsa->dmp1 = BN_new();           // d mod (p-1)
  CHECK_CALL(rsa->dmp1);
  CHECK_CALL(BN_mod(rsa->dmp1, rsa->d, pm, ctx));

  rsa->dmq1 = BN_new();           // d mod (q-1)
  CHECK_CALL(rsa->dmq1);
  CHECK_CALL(BN_mod(rsa->dmq1, rsa->d, qm, ctx));

  rsa->iqmp = BN_new();           // q^-1 mod p
  CHECK_CALL(rsa->iqmp);
  CHECK_CALL(BN_mod_inverse(rsa->iqmp, rsa->q, rsa->p, ctx));

  CHECK_CALL(EVP_PKEY_set1_RSA(evp, rsa));
  ASSERT(RSA_check_key(rsa));

  BN_clear_free(phi_n);
  BN_clear_free(pm);
  BN_clear_free(qm);

  return evp;
}

static bool GenerateCertRequest(RsaDevice d, X509_REQ* req)
{
  // Create key in EVP format
  EVP_PKEY* key = CreateRsaKey(d);
  CHECK_CALL(key);
  
  // Create x509 cert signing request (CSR)
  CHECK_CALL(X509_REQ_set_pubkey(req, key));

  // Add subject name to the CSR
  X509_NAME* subj = X509_REQ_get_subject_name(req);
  CHECK_CALL(X509_NAME_add_entry_by_txt(
      subj, "O", MBSTRING_ASC, 
      (const unsigned char *)"RSA Device", -1, -1, 0)); 
  CHECK_CALL(X509_REQ_set_subject_name(req, subj));

  //X509_REQ_print_fp(stderr, req);
  CHECK_CALL(X509_REQ_sign(req, key, EVP_sha1()));

  EVP_PKEY_free(key);
  return true;
}
