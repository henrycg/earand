#ifndef _DSA_CA_H
#define _DSA_CA_H

#include <openssl/x509.h>

#include "dsa_params.h"
#include "util.h"

typedef struct dsa_ca* DsaCa;
typedef const struct dsa_ca* const_DsaCa;

/**
 * Create a new DSA CA object.
 */
DsaCa DsaCa_New(DsaParams params);

void DsaCa_Free(DsaCa ca);

/**
 * Validate and sign a device's certificate
 * after making sure that the EA signed it.
 */
X509* DsaCa_SignCertificate(DsaCa ca, X509* cert_in);

#endif
