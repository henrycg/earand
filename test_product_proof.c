#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>

#include "product_proof.h"
#include "test_common.h"

void mu_test_ProductStatement_New()
{
  const int bits = 180;
  IntegerGroup g = IntegerGroup_Generate(bits);
  BIGNUM *commit_a = IntegerGroup_RandomElement(g);
  BIGNUM *commit_b = IntegerGroup_RandomElement(g);
  BIGNUM *commit_c = IntegerGroup_RandomElement(g);

  mu_ensure(commit_a);
  mu_ensure(commit_b);
  mu_ensure(commit_c);

  ProductStatement proof = ProductStatement_New(g, commit_a, commit_b, commit_c);

  BN_free(commit_a);
  BN_free(commit_b);
  BN_free(commit_c);

  ProductStatement_Free(proof);
  IntegerGroup_Free(g);
}

void mu_test_ProductProof_Correct()
{
  for(int i=0; i<50; i++) {
    const int bits = 180;
    IntegerGroup g = IntegerGroup_Generate(bits);
    BIGNUM* a = IntegerGroup_RandomExponent(g);
    BIGNUM* b = IntegerGroup_RandomExponent(g);
    BIGNUM* c = BN_new();

    mu_ensure(a);
    mu_ensure(b);
    mu_ensure(c);

    // c = a*b mod q
    mu_ensure(BN_mod_mul(c, a, b, IntegerGroup_GetQ(g), IntegerGroup_GetCtx(g)));

    BIGNUM* r_a = IntegerGroup_RandomExponent(g);
    BIGNUM* r_b = IntegerGroup_RandomExponent(g);
    BIGNUM* r_c = IntegerGroup_RandomExponent(g);

    mu_ensure(r_a);
    mu_ensure(r_b);
    mu_ensure(r_c);

    BIGNUM* commit_a = IntegerGroup_Commit(g, a, r_a);
    BIGNUM* commit_b = IntegerGroup_Commit(g, b, r_b);
    BIGNUM* commit_c = IntegerGroup_Commit(g, c, r_c);

    mu_ensure(commit_a);
    mu_ensure(commit_b);
    mu_ensure(commit_c);

    ProductStatement proof = ProductStatement_New(g, commit_a, commit_b, commit_c);

    ProductEvidence ev = ProductEvidence_New(proof, a, r_a, r_b, r_c);
    mu_ensure(ProductEvidence_Verify(ev, proof));

    // Write params to temp file
    FILE *file = tmpfile();
    mu_ensure(file);

    mu_ensure(ProductEvidence_Serialize(ev, file));
    rewind(file);

    ProductEvidence ev2 = ProductEvidence_Unserialize(file);
    mu_ensure(ev2);
    mu_ensure(ProductEvidence_Verify(ev2, proof));

    fclose(file);

    BN_free(a);
    BN_free(b);
    BN_free(c);

    BN_free(commit_a);
    BN_free(commit_b);
    BN_free(commit_c);

    BN_free(r_a);
    BN_free(r_b);
    BN_free(r_c);

    ProductEvidence_Free(ev);
    ProductEvidence_Free(ev2);
    ProductStatement_Free(proof);
    IntegerGroup_Free(g);
  }
}

