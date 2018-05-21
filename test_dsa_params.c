#include <stdbool.h>
#include <stdio.h>

#include "dsa_params.h"
#include "test_common.h"

void mu_test_DsaParams_new() 
{
  DsaParams p = DsaParams_New("secp224r1");
  DsaParams_Free(p);
}

void mu_test_DsaParams_serialize() 
{
  DsaParams params = DsaParams_New("secp224r1");

  // Write params to temp file
  FILE *file = tmpfile();
  mu_ensure(file);
  mu_ensure(DsaParams_Serialize(params, file));

  // Read params from file
  rewind(file);

  DsaParams params2 = DsaParams_Unserialize(file);
  mu_ensure(params2);
  fclose(file);

  // Delete params
  DsaParams_Free(params);
  DsaParams_Free(params2);
}

void mu_test_DsaParams_RandomExponent() 
{
  DsaParams p = DsaParams_New("secp224r1");

  for(int i=0; i<50; i++) {
    BIGNUM* v = DsaParams_RandomExponent(p);
    BIGNUM* r = DsaParams_RandomExponent(p);
    CHECK_CALL(v);
    CHECK_CALL(r);

    EC_POINT* comm = DsaParams_Commit(p, v, r);
    CHECK_CALL(comm);
    BN_free(v);
    BN_free(r);
    EC_POINT_free(comm);
  }

  DsaParams_Free(p);
}

void mu_test_DsaParams_sign_verify() 
{
  DsaParams params = DsaParams_New("secp224r1");

  unsigned char msg[] = "This is the message to be signed";
  for(int i=sizeof(msg); i; i--) { 
    msg[i] = '\0';
    unsigned char ca_sig[DsaParams_CaSignatureLength(params)];
    unsigned char ea_sig[DsaParams_EaSignatureLength(params)];

    // sig must be CaSignatureLength bytes long
    int sig_len;
    mu_ensure(DsaParams_CaSign(params, ca_sig, &sig_len, msg, sizeof(msg)));
    mu_ensure(DsaParams_CaVerify(params, ca_sig, sig_len, msg, sizeof(msg)));

    mu_ensure(DsaParams_EaSign(params, ea_sig, &sig_len, msg, sizeof(msg)));
    mu_ensure(DsaParams_EaVerify(params, ea_sig, sig_len, msg, sizeof(msg)));
  }

  DsaParams_Free(params);
}

/*
void mu_test_DsaParams_get_key()
{
  DsaParams params = DsaParams_New("secp224r1");

  FILE* f = tmpfile();
  do {
    X509_REQ* req = X509_REQ_new();
    EVP_PKEY *evp = EVP_PKEY_new();
    EC_KEY *ec = EC_KEY_new();
    BIGNUM *a = DsaParams_RandomExponent(params);
    BN_DEBUG("a", a);
    BN_DEBUG("q", DsaParams_GetQ(params));
    EC_POINT *g_a = DsaParams_MultiplyG(params, a);
    EC_DEBUG("g", DsaParams_GetCurve(params), DsaParams_GetG(params), 
        DsaParams_GetCtx(params));
    g_a = DsaParams_Multiply(params, DsaParams_GetG(params), a);
    EC_DEBUG("g_a", DsaParams_GetCurve(params), g_a, DsaParams_GetCtx(params));

    // Create EC_KEY
    CHECK_CALL(EC_KEY_set_group(ec, DsaParams_GetCurve(params)));
    CHECK_CALL(EC_KEY_set_private_key(ec, a));
    CHECK_CALL(EC_KEY_set_public_key(ec, g_a));
   
    // Create EVP
    CHECK_CALL(EVP_PKEY_set1_EC_KEY(evp, ec));
    CHECK_CALL(EC_KEY_check_key(ec));

    // Create X509_REQ
    CHECK_CALL(X509_REQ_set_pubkey(req, evp));
  
    // Write to buffer
    CHECK_CALL(i2d_X509_REQ_fp(f, req));
    X509_REQ_free(req);
  } while(0);
  
  rewind(f);

  do {
    // Read X509_REQ
    X509_REQ* req = d2i_X509_REQ_fp(f, NULL);
    CHECK_CALL(req);

    // Read EVP
    EVP_PKEY* pkey = X509_REQ_get_pubkey(req);
    CHECK_CALL(pkey);

    // Read EC_KEY
    EC_KEY* eckey = EVP_PKEY_get1_EC_KEY(pkey);
    CHECK_CALL(eckey);

    bool b = EC_KEY_check_key(eckey);
    CHECK_CALL(b);
    BIO* bio = BIO_new_fd(0, 0);
    EVP_PKEY_print_public(bio, pkey, 0, NULL);

    const EC_POINT* pub_point = EC_KEY_get0_public_key(eckey);
    CHECK_CALL(pub_point);
    EC_DEBUG("pub", EC_KEY_get0_group(eckey), pub_point, 
        DsaParams_GetCtx(params));
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    CHECK_CALL(EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(eckey),
          pub_point, x, y, DsaParams_GetCtx(params)));
    BN_DEBUG("x", x);
    BN_DEBUG("y", y);
  } while(0);
  fclose(f);
  DsaParams_Free(params);
}
*/


