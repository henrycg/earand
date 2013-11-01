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


