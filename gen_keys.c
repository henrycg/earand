#include <openssl/rsa.h>

#include "gen_keys.h"
#include "util.h"

void SetBogusTimeSubject(X509* cert)
{
  // Set the X509 version to 3
  CHECK_CALL(cert->cert_info->version = M_ASN1_INTEGER_new());
  CHECK_CALL(ASN1_INTEGER_set(cert->cert_info->version, 3));

  // Set the issuer field of the cert
  X509_NAME* issuer = X509_get_issuer_name(cert);
  CHECK_CALL(issuer);
  CHECK_CALL(X509_NAME_add_entry_by_txt(issuer, "O", MBSTRING_ASC, 
        (const unsigned char *)"CA Issuer", -1, -1, 0)); 
  CHECK_CALL(X509_set_issuer_name(cert, issuer));

  // Set the subject field of the cert
  X509_NAME* subj = X509_get_subject_name(cert);
  CHECK_CALL(subj);
  CHECK_CALL(X509_NAME_add_entry_by_txt(subj, "O", MBSTRING_ASC, 
        (const unsigned char *)"CA Subject", -1, -1, 0)); 
  CHECK_CALL(X509_set_subject_name(cert, subj));

  // Set cert to expire in one year
  CHECK_CALL(X509_gmtime_adj(cert->cert_info->validity->notBefore, 0));
  CHECK_CALL(X509_gmtime_adj(cert->cert_info->validity->notAfter, 365*24*60*60));
}

X509* GenerateDsa(DsaParams params)
{
  EVP_PKEY* pk = EVP_PKEY_new();
  EC_KEY* key = EC_KEY_new();
  CHECK_CALL(EC_KEY_set_group(key, DsaParams_GetCurve(params)));
  CHECK_CALL(EC_KEY_generate_key(key));
  CHECK_CALL(EC_KEY_get0_public_key(key));

  CHECK_CALL(EVP_PKEY_set1_EC_KEY(pk, key));

  X509* cert = X509_new();
  CHECK_CALL(cert);
  CHECK_CALL(X509_set_pubkey(cert, pk));

  EC_KEY_free(key);
  EVP_PKEY_free(pk);

  SetBogusTimeSubject(cert);

  return cert;
}

X509* GenerateRsa(RsaParams params)
{
  EVP_PKEY* pk = EVP_PKEY_new();
  RSA* rsa = RSA_new();

  CHECK_CALL(rsa = RSA_generate_key(RsaParams_GetModulusBits(params), 
       65537, NULL, NULL));

  CHECK_CALL(EVP_PKEY_set1_RSA(pk, rsa));

  X509* cert = X509_new();
  CHECK_CALL(cert);
  CHECK_CALL(X509_set_pubkey(cert, pk));

  RSA_free(rsa);
  EVP_PKEY_free(pk);

  SetBogusTimeSubject(cert);

  return cert;
}
