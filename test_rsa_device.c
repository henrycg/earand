#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "rsa_ca.h"
#include "rsa_device.h"
#include "rsa_ea.h"
#include "test_common.h"

void mu_test_RsaDevice_New() 
{
  const int n_bits = 134;
  RsaParams params = RsaParams_New(n_bits);
  RsaDevice rsa = RsaDevice_New(params);

  RsaDevice_Free(rsa);
  RsaParams_Free(params);
}

void mu_test_RsaDevice_Primes() 
{
  FILE* fp = fopen(TEST_PARAMS_FILE, "r");
  mu_ensure(fp);
  RsaParams params = RsaParams_Unserialize(fp);
  mu_ensure(params);
  fclose(fp);
  RsaDevice rsa = RsaDevice_New(params);

  BIGNUM* xp = RsaParams_RandomLargeValue(params);
  BIGNUM* yp = RsaParams_RandomLargeValue(params);

  BIGNUM* commit_x = BN_new();
  BIGNUM* commit_y = BN_new(); 

  mu_check(RsaDevice_GenEntropyRequest(rsa, commit_x, commit_y));
  mu_check(RsaDevice_SetEntropyResponse(rsa, xp, yp));

  BIGNUM *dx = BN_new();
  BIGNUM *dy = BN_new();
  BIGNUM *n = BN_new();
  BIGNUM *rand_n = BN_new();

  mu_ensure(dx);
  mu_ensure(dy);
  mu_ensure(n);
  mu_ensure(rand_n);

  ProductEvidence ev;

  X509_REQ* req = X509_REQ_new();
  mu_ensure(req);
  mu_check(RsaDevice_GenEaSigningRequest(rsa, req, dx, dy, rand_n, &ev));

  const int n_checks = BN_prime_checks;

  // Check that p is prime
  mu_check(BN_is_prime(RsaDevice_GetP(rsa), n_checks, NULL,
        RsaParams_GetCtx(params), NULL));

  // Check that q is prime
  mu_check(BN_is_prime(RsaDevice_GetQ(rsa), n_checks, NULL,
        RsaParams_GetCtx(params), NULL));

  BIGNUM *tmp = BN_new();

  // Check that p = x + x' + delta_x
  CHECK_CALL(BN_copy(tmp, RsaDevice_GetX(rsa)));
  CHECK_CALL(BN_add(tmp, tmp, RsaDevice_GetXPrime(rsa)));
  CHECK_CALL(BN_add(tmp, tmp, dx));
  mu_check(!BN_cmp(tmp, RsaDevice_GetP(rsa)));

  // Check that q = y + y' + delta_y
  CHECK_CALL(BN_copy(tmp, RsaDevice_GetY(rsa)));
  CHECK_CALL(BN_add(tmp, tmp, RsaDevice_GetYPrime(rsa)));
  CHECK_CALL(BN_add(tmp, tmp, dy));
  mu_check(!BN_cmp(tmp, RsaDevice_GetQ(rsa)));

  // Check that deltas are small
  CHECK_CALL(BN_set_word(tmp, RsaParams_GetDeltaMax(params)));
  mu_check(BN_cmp(dx, tmp) == -1);
  mu_check(BN_cmp(dy, tmp) == -1);

  ProductEvidence_Free(ev);

  BN_free(commit_x);
  BN_free(commit_y);
  BN_free(dx);
  BN_free(dy);
  BN_free(n);
  BN_free(rand_n);

  BN_free(tmp);
  BN_free(xp);
  BN_free(yp);

  X509_REQ_free(req);

  RsaDevice_Free(rsa);
  RsaParams_Free(params);
}

void mu_test_RsaDevice_Protocol() 
{
  FILE* fp = fopen(TEST_PARAMS_FILE, "r");
  mu_ensure(fp);
  RsaParams params = RsaParams_Unserialize(fp);
  mu_ensure(params);
  fclose(fp);

  RsaDevice rsa = RsaDevice_New(params);

  // Device makes entropy request
  BIGNUM* commit_x = BN_new();
  BIGNUM* commit_y = BN_new(); 

  mu_ensure(commit_x);
  mu_ensure(commit_y);

  mu_check(RsaDevice_GenEntropyRequest(rsa, commit_x, commit_y));

  // EA sends back entropy response
  RsaEa ea = RsaEa_New(params, commit_x, commit_y);
  mu_ensure(ea);
  BN_free(commit_x);
  BN_free(commit_y);

  BIGNUM* xp = BN_new();
  BIGNUM* yp = BN_new();
  mu_ensure(xp);
  mu_ensure(yp);

  RsaEa_GenEntropyResponse(ea, xp, yp);

  mu_check(RsaDevice_SetEntropyResponse(rsa, xp, yp));

  BN_free(xp);
  BN_free(yp);

  BIGNUM *dx = BN_new();
  BIGNUM *dy = BN_new();
  BIGNUM *n = BN_new();
  BIGNUM *rand_n = BN_new();

  mu_ensure(dx);
  mu_ensure(dy);
  mu_ensure(n);
  mu_ensure(rand_n);

  ProductEvidence ev;

  X509_REQ* req = X509_REQ_new();
  // Device sends EA signing requst
  mu_check(RsaDevice_GenEaSigningRequest(rsa, req, dx, dy, rand_n, &ev));

  // EA responds with signature
  mu_check(RsaEa_SetCertRequest(ea, req, dx, dy, rand_n, ev));

  X509* cert = NULL;
  mu_check(RsaEa_GetCertResponse(ea, &cert));

  // Give EA signature back to device
  mu_check(RsaDevice_SetEaCertResponse(rsa, cert));
  X509_free(cert);

  X509* cert2 = NULL;
  mu_ensure(RsaDevice_GenCaCertRequest(rsa, &cert2));

  // CA signs certificate
  RsaCa ca = RsaCa_New(params);
  X509* cert3;
  mu_ensure((cert3 = RsaCa_SignCertificate(ca, cert2)));
  RsaCa_Free(ca);

  mu_check(RsaDevice_SetCaCertResponse(rsa, cert3));

  X509_REQ_free(req);
  X509_free(cert2);
  X509_free(cert3);


  ProductEvidence_Free(ev);

  BN_free(dx);
  BN_free(dy);
  BN_free(n);
  BN_free(rand_n);

  RsaEa_Free(ea);
  RsaDevice_Free(rsa);
  RsaParams_Free(params);
}

/*
void mu_test_x509() 
{
  FILE* fp;
  fp = fopen("keys/ea_pub.pem", "r");
  CHECK_CALL(fp);
  EVP_PKEY* pub = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
  CHECK_CALL(pub);
  fclose(fp);
  fp = fopen("keys/ea_priv.pem", "r");
  CHECK_CALL(fp);
  EVP_PKEY* priv = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
  CHECK_CALL(priv);
  fclose(fp);
  fp = fopen("keys/ca_priv.pem", "r");
  CHECK_CALL(fp);
  EVP_PKEY* ca_priv = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
  CHECK_CALL(ca_priv);
  fclose(fp);
  fp = fopen("keys/ca_pub.pem", "r");
  CHECK_CALL(fp);
  EVP_PKEY* ca_pub= PEM_read_PUBKEY(fp, NULL, NULL, NULL);
  CHECK_CALL(ca_pub);
  fclose(fp);

  X509_REQ* req = X509_REQ_new();
  CHECK_CALL(req);
  CHECK_CALL(X509_REQ_set_pubkey(req, pub));

  X509_NAME* subj = X509_REQ_get_subject_name(req);
  CHECK_CALL(X509_NAME_add_entry_by_txt(
      subj, "O", MBSTRING_ASC, (const unsigned char *)"RSA Device", -1, -1, 0)); 

  // subject name
  CHECK_CALL(X509_REQ_set_subject_name(req, subj));

  unsigned char proof[] = "this is the; proof 0x1231312312312";

  CHECK_CALL(X509_REQ_add1_attr_by_txt(req, "unstructuredAddress",
        MBSTRING_ASC, (const unsigned char*)proof, sizeof(proof)));

  CHECK_CALL(X509_REQ_sign(req, priv, EVP_sha1()));

  //X509_REQ_print_fp(stdout, req);

  BIO* bio = BIO_new(BIO_s_mem());
  CHECK_CALL(BIO_set_close(bio, BIO_NOCLOSE));
  CHECK_CALL(i2d_X509_REQ_bio(bio, req)); 

  BUF_MEM *bp;
  BIO_get_mem_ptr(bio, &bp);

  BIO_free(bio);

  X509_REQ_free(req);
  EVP_PKEY_free(pub);
  EVP_PKEY_free(priv);

  BIO *bin = BIO_new_mem_buf(bp->data, bp->length);

  CHECK_CALL(req = d2i_X509_REQ_bio(bin, NULL));

  // Check sig on X509 request
  EVP_PKEY *req_key;
  CHECK_CALL(req_key = X509_REQ_get_pubkey(req));
  CHECK_CALL(X509_REQ_verify(req, req_key));

  CHECK_CALL(X509_REQ_get_attr_count(req) == 1);

  X509_ATTRIBUTE *attr;
  CHECK_CALL(attr = X509_REQ_get_attr(req, 0));

  ASN1_TYPE *attr_type = X509_ATTRIBUTE_get0_type(attr, 0);
  ASN1_PRINTABLESTRING *astring = (ASN1_PRINTABLESTRING *)X509_ATTRIBUTE_get0_data(
      attr, 0, ASN1_TYPE_get(attr_type), NULL);

  printf("%d, %s\n", astring->length, astring->data);

  // Create and sign X509 cert
  X509* cert = X509_new();
  CHECK_CALL(cert);

  CHECK_CALL(cert->cert_info->version = M_ASN1_INTEGER_new());
  CHECK_CALL(ASN1_INTEGER_set(cert->cert_info->version, 3));
  // issuer name

  X509_NAME* issuer = X509_get_issuer_name(cert);
  CHECK_CALL(X509_NAME_add_entry_by_txt(
      issuer, "O", MBSTRING_ASC, (const unsigned char *)"RSA CA Issuer", -1, -1, 0)); 
  CHECK_CALL(X509_set_issuer_name(cert, issuer));
  X509_NAME* csubj= X509_get_subject_name(cert);
  CHECK_CALL(X509_NAME_add_entry_by_txt(
      csubj, "O", MBSTRING_ASC, (const unsigned char *)"RSA Device", -1, -1, 0)); 
  CHECK_CALL(X509_set_subject_name(cert, csubj));

  CHECK_CALL(X509_gmtime_adj(cert->cert_info->validity->notBefore, 0));
  CHECK_CALL(X509_gmtime_adj(cert->cert_info->validity->notAfter, 263*24*60*60));
  CHECK_CALL(X509_set_pubkey(cert, X509_REQ_get_pubkey(req)));

  CHECK_CALL(X509_sign(cert, ca_priv, EVP_sha1()));

  CHECK_CALL(X509_verify(cert, ca_pub));

  X509_free(cert);
  EVP_PKEY_free(ca_priv);
  EVP_PKEY_free(ca_pub);
  BUF_MEM_free(bp);
  BIO_free(bin);
}
*/
