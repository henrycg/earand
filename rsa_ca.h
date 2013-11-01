#ifndef _RSA_CA_H
#define _RSA_CA_H

#include <openssl/x509.h>

#include "product_proof.h"
#include "rsa_params.h"
#include "util.h"

typedef struct rsa_ca* RsaCa;
typedef const struct rsa_ca* const_RsaCa;

/**
 * Create a new RSA CA object.
 */
RsaCa RsaCa_New(RsaParams params);

void RsaCa_Free(RsaCa ca);

/**
 * Validate and sign a device's certificate
 * after making sure that the EA signed it.
 */
X509* RsaCa_SignCertificate(RsaCa ca, X509* req);

#endif
