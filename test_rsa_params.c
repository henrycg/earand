#include <stdbool.h>
#include <stdio.h>

#include <openssl/bn.h>

#include "rsa_params.h"
#include "test_common.h"

void mu_test_params_new() 
{
  const int bits = 100;
  RsaParams p = RsaParams_New(bits);
  mu_check(bits == RsaParams_GetModulusBits(p));
  RsaParams_Free(p);
}

void mu_test_serialize() 
{
  const int bits = 115;
  RsaParams params = RsaParams_New(bits);

  // Save params
  const int prime_bits = RsaParams_GetModulusBits(params)/2;
  const BIGNUM *p = IntegerGroup_GetP(RsaParams_GetGroup(params));
  const BIGNUM *q = IntegerGroup_GetQ(RsaParams_GetGroup(params));
  const BIGNUM *g = IntegerGroup_GetG(RsaParams_GetGroup(params));
  const BIGNUM *h = IntegerGroup_GetH(RsaParams_GetGroup(params));

  // Write params to temp file
  FILE *file = tmpfile();
  mu_ensure(file);
  mu_ensure(RsaParams_Serialize(params, file));

  // Read params from file
  rewind(file);

  RsaParams params2 = RsaParams_Unserialize(file);
  mu_ensure(params2);
  fclose(file);

  // Make sure params match saved ones
  mu_check(prime_bits == RsaParams_GetModulusBits(params2)/2);
  mu_check(!BN_cmp(p, IntegerGroup_GetP(RsaParams_GetGroup(params2))));
  mu_check(!BN_cmp(q, IntegerGroup_GetQ(RsaParams_GetGroup(params2))));
  mu_check(!BN_cmp(g, IntegerGroup_GetG(RsaParams_GetGroup(params2))));
  mu_check(!BN_cmp(h, IntegerGroup_GetH(RsaParams_GetGroup(params2))));

  // Delete params
  RsaParams_Free(params);
  RsaParams_Free(params2);
}

void mu_test_random_value() 
{
  const int bits = 120;
  RsaParams p = RsaParams_New(bits);

  for(int i=0; i<50; i++) {
    BIGNUM* rnd = RsaParams_RandomLargeValue(p);
    mu_check(RsaParams_InRange(p, rnd));
    BN_free(rnd);
  }

  RsaParams_Free(p);
}

void mu_test_sign_verify() 
{
  FILE* fp = fopen(TEST_PARAMS_FILE, "r");
  mu_ensure(fp);
  RsaParams params = RsaParams_Unserialize(fp);
  fclose(fp);

  unsigned char msg[] = "This is the message to be signed";
  for(int i=sizeof(msg); i; i--) { 
    msg[i] = '\0';
    unsigned char ca_sig[RsaParams_CaSignatureLength(params)];
    unsigned char ea_sig[RsaParams_EaSignatureLength(params)];

    // sig must be CaSignatureLength bytes long
    int sig_len;
    mu_ensure(RsaParams_CaSign(params, ca_sig, &sig_len, msg, sizeof(msg)));
    mu_ensure(RsaParams_CaVerify(params, ca_sig, sig_len, msg, sizeof(msg)));

    mu_ensure(RsaParams_EaSign(params, ea_sig, &sig_len, msg, sizeof(msg)));
    mu_ensure(RsaParams_EaVerify(params, ea_sig, sig_len, msg, sizeof(msg)));
  }

  RsaParams_Free(params);
}


void mu_test_params_generate() 
{
  const int bits = 3072;
  RsaParams p = RsaParams_New(bits);

  FILE* fp = fopen("params/rsa3072", "w");
  mu_ensure(fp);
  mu_ensure(RsaParams_Serialize(p, fp));
  fclose(fp);

  RsaParams_Free(p);
}

