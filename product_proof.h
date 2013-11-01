#ifndef _PRODUCT_PROOF_H
#define _PRODUCT_PROOF_H

#include <stdbool.h>
#include <openssl/bn.h>

#include "integer_group.h"

/**
 * ProductStatement holds the commitments
 * to a, b, and c
 */
typedef struct product_statement* ProductStatement;
typedef const struct product_statement* const_ProductStatement;

/**
 * ProductEvidence holds the proof values to 
 * prove that: 
 *    Commit(a) * Commit(b) = Commit(c)
 */
typedef struct product_evidence* ProductEvidence;
typedef const struct product_evidence* const_ProductEvidence;

/**
 * Create a new statement for a multiplication proof
 */
ProductStatement ProductStatement_New(const_IntegerGroup group, 
    const BIGNUM* commit_a, const BIGNUM* commit_b, const BIGNUM* commit_c);
void ProductStatement_Free(ProductStatement st);

/**
 * Prover knows a, b, r_a, r_c in:
 *    Commit(a) = g^a h^{r_a}
 *    Commit(b) = g^b h^{r_b}
 *    Commit(c) = g^c h^{r_c}
 */
ProductEvidence ProductEvidence_New(ProductStatement st, 
    const BIGNUM *a, const BIGNUM *r_a, const BIGNUM *r_b, const BIGNUM *r_c);

void ProductEvidence_Free(ProductEvidence ev);

bool ProductEvidence_Serialize(const_ProductEvidence ev, FILE* fp);

ProductEvidence ProductEvidence_Unserialize(FILE* fp);

bool ProductEvidence_Verify(const_ProductEvidence ev, const_ProductStatement st);

#endif
