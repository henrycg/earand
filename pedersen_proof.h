#ifndef _PEDERSEN_PROOF_H
#define _PEDERSEN_PROOF_H

#include <stdbool.h>
#include <openssl/ec.h>

/**
 * Holds the statement to be proven
 */
typedef struct pedersen_statement* PedersenStatement;
typedef const struct pedersen_statement* const_PedersenStatement;

/**
 * Holds the prover's witness
 */
typedef struct pedersen_evidence* PedersenEvidence;
typedef const struct pedersen_evidence* const_PedersenEvidence;

/**
 * Proves the statement:
 *    PoK{ x, r: commit_x = (g^x * h^r) AND g_to_the_x = g^x }
 * using a non-interactive zero-knowledge proof of knowledge.
 * See Camenisch and Stadler's 1997 paper for details on how
 * to construct such a proof.
 */
PedersenStatement PedersenStatement_New(const EC_GROUP* group, 
    const EC_POINT* g, 
    const EC_POINT* h, 
    const EC_POINT* commit_x,
    const EC_POINT* g_to_the_x);
void PedersenStatement_Free(PedersenStatement st);

PedersenEvidence PedersenEvidence_New(PedersenStatement st, 
    const BIGNUM *x, const BIGNUM *r);

void PedersenEvidence_Free(PedersenEvidence ev);

bool PedersenEvidence_Verify(const_PedersenEvidence ev, const_PedersenStatement st);

bool PedersenEvidence_Serialize(const_PedersenEvidence ev, FILE* fp);

PedersenEvidence PedersenEvidence_Unserialize(FILE* fp);

#endif
