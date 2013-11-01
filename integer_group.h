#ifndef _INTEGER_GROUP_H
#define _INTEGER_GROUP_H

#include <stdbool.h>
#include <openssl/bn.h>

#include "util.h"

typedef struct integer_group* IntegerGroup;
typedef const struct integer_group* const_IntegerGroup;

/**
 * This represents the order-q multiplicative group of integers
 * modulo p, where p = 2q+1. g and h are generators of the group.
 */
IntegerGroup IntegerGroup_New(BIGNUM* p, BIGNUM* q, 
    BIGNUM* g, BIGNUM* h);
void IntegerGroup_Free(IntegerGroup group);

/**
 * Generate a new group where p is p_bits long.
 */
IntegerGroup IntegerGroup_Generate(int p_bits);

/**
 * Write group description to a file. 
 * Returns 1 on success, 0 on failure.
 */
int IntegerGroup_Serialize(const_IntegerGroup group, FILE* file);

/**
 * Return true if BIGNUM is in the order-q group mod p
 */
bool IntegerGroup_IsElement(const_IntegerGroup group, const BIGNUM *a);

/**
 * Read group description from a file. 
 * Returns NULL on failure.
 */
IntegerGroup IntegerGroup_Unserialize(FILE* file);

/**
 * Return a^{-1} mod p
 */
BIGNUM* IntegerGroup_Inverse(const_IntegerGroup group, const BIGNUM *a);
    
/**
 * Return g^x mod p
 */
BIGNUM* IntegerGroup_Exponentiate(const_IntegerGroup group,
    const BIGNUM* g, const BIGNUM* x);

/**
 * Return g1^x1 g2^x2 mod p
 */
BIGNUM* IntegerGroup_CascadeExponentiate(const_IntegerGroup group,
    const BIGNUM* g1, const BIGNUM* x1,
    const BIGNUM* g2, const BIGNUM* x2);

/**
 * Return a random quadratic residue
 */
BIGNUM* IntegerGroup_RandomElement(const_IntegerGroup group);

/**
 * Return a value in the range
 * [0, ..., q)
 */
BIGNUM* IntegerGroup_RandomExponent(const_IntegerGroup group);

/**
 * Generate Chaum-Pedersen commitment: C(x,r) = g^x h^r
 */
BIGNUM* IntegerGroup_Commit(const_IntegerGroup group, 
    const BIGNUM* v, const BIGNUM *r);

const BIGNUM* IntegerGroup_GetP(const_IntegerGroup group);
const BIGNUM* IntegerGroup_GetQ(const_IntegerGroup group);
const BIGNUM* IntegerGroup_GetG(const_IntegerGroup group);
const BIGNUM* IntegerGroup_GetH(const_IntegerGroup group);
BN_CTX* IntegerGroup_GetCtx(const_IntegerGroup group);

#endif

