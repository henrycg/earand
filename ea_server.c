#include <unistd.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include "dsa_ea.h"
#include "rsa_ea.h"
#include "pedersen_proof.h"
#include "ssl_server.h"
#include "util.h"

/**
 * ===== EA Server =====
 * This process plays the role of the EA in the
 * RSA keygen protocol.  
 */

struct param_tuple {
  DsaParams dsa;
  RsaParams rsa;
};

void EaServer(SSL* ssl, void* data)
{
  struct param_tuple *tup = (struct param_tuple*)data;

  int rfd, wfd;
  FILE* rfp;
  FILE* wfp;
  SetupFileDescriptors(ssl, &rfd, &rfp, &wfd, &wfp);

  int mode;
  CHECK_CALL(fscanf(rfp, "%d ", &mode) == 1);
  if(mode == RSA_CLIENT) {

    RsaParams params = tup->rsa;

    // Temp values
    BIGNUM* v1 = BN_new();
    BIGNUM* v2 = BN_new();
    BIGNUM* v3 = BN_new();
    BIGNUM* v4 = BN_new();
    CHECK_CALL(v1);
    CHECK_CALL(v2);
    CHECK_CALL(v3);
    CHECK_CALL(v4);

    // Read in C(x), C(y)
    CHECK_CALL(ReadOneBignum(&v1, rfp, STRING_COMMIT_X));
    CHECK_CALL(ReadOneBignum(&v2, rfp, STRING_COMMIT_Y));

    fprintf(stderr, "\tGot commits.\n");

    RsaEa ea = RsaEa_New(params, v1, v2);

    // Send back x', y'
    RsaEa_GenEntropyResponse(ea, v1, v2);

    CHECK_CALL(WriteOneBignum(STRING_X_PRIME, 3, wfp, v1));
    CHECK_CALL(WriteOneBignum(STRING_Y_PRIME, 3, wfp, v2));
    CHECK_CALL(!fflush(wfp));
    fprintf(stderr, "\tSent entropy response.\n");

    // Read in signing request
    fprintf(stderr, "\tReading request...\n");
    X509_REQ* req = d2i_X509_REQ_fp(rfp, NULL);
    if(!req) {
      fatal("CA failed to read X509 request");
    }

    CHECK_CALL(ReadOneBignum(&v1, rfp, STRING_DELTA_X));
    CHECK_CALL(ReadOneBignum(&v2, rfp, STRING_DELTA_Y));
    CHECK_CALL(ReadOneBignum(&v3, rfp, STRING_MODULUS_RAND));
    ProductEvidence ev = ProductEvidence_Unserialize(rfp);
    fprintf(stderr, "\tGot proof.\n");

    CHECK_CALL(ev);
    CHECK_CALL(RsaEa_SetCertRequest(ea, req, v1, v2, v3, ev));

    fprintf(stderr, "\tSigning cert...\n");
    X509* cert = NULL;
    CHECK_CALL(RsaEa_GetCertResponse(ea, &cert));

    // Write cert out
    fprintf(stderr, "\tWriting cert...\n");
    if(!i2d_X509_fp(wfp, cert)) {
      fatal("CA failed to write X509 certificate");
    }
    X509_free(cert);

    CHECK_CALL(!fflush(wfp));

    ProductEvidence_Free(ev);
    BN_clear_free(v1);
    BN_clear_free(v2);
    BN_clear_free(v3);
    BN_clear_free(v4);

    X509_REQ_free(req);

    RsaEa_Free(ea);
  } else if(mode == DSA_CLIENT) {
    DsaEa ea = DsaEa_New(tup->dsa);

    EC_GROUP* group = DsaParams_GetCurve(tup->dsa);
    EC_POINT* commit_x = EC_POINT_new(group);

    // Read commit_x from stream
    CHECK_CALL(ReadOnePoint(&commit_x, group, rfp, 
          STRING_COMMIT_X, DsaParams_GetCtx(tup->dsa)));

    BIGNUM* x_prime = BN_new();
    BIGNUM* rand_x_prime = BN_new();

    CHECK_CALL(x_prime);
    CHECK_CALL(rand_x_prime);

    CHECK_CALL(DsaEa_SetEntropyRequest(ea, commit_x));
    CHECK_CALL(DsaEa_GetEntropyResponse(ea, &x_prime));

    // Send back x'
    CHECK_CALL(WriteOneBignum(STRING_X_PRIME, sizeof(STRING_X_PRIME), wfp, x_prime));
    
    CHECK_CALL(!fflush(wfp));

    EC_POINT_clear_free(commit_x);
    BN_clear_free(x_prime);
    BN_clear_free(rand_x_prime);

    fprintf(stderr, "\tReading randomness request...\n");
    // Read in proof
    BIGNUM* rand_a = BN_new();
    PedersenEvidence ev = PedersenEvidence_Unserialize(rfp);
    CHECK_CALL(ev);

    // Read in signing request
    fprintf(stderr, "\tReading request...\n");
    X509_REQ* req = d2i_X509_REQ_fp(rfp, NULL);
    if(!req) {
      fatal("EA failed to read X509 request");
    }
    CHECK_CALL(DsaEa_SetCertRequest(ea, ev, req));
    X509_REQ_free(req);
    BN_clear_free(rand_a);

    X509* cert;
    CHECK_CALL(DsaEa_GetCertResponse(ea, &cert));
    fprintf(stderr, "\tWriting cert...\n");
    if(!i2d_X509_fp(wfp, cert)) {
      fatal("CA failed to write X509 certificate");
    }
    X509_free(cert);

    CHECK_CALL(!fflush(wfp));
    DsaEa_Free(ea);

  } else {
    fprintf(stderr, "\tGot invalid mode: %d... closing\n", mode);
  }
  fclose(rfp);
  fclose(wfp);
  fprintf(stderr, "\tDone!.\n");
}

int main(int argc, char *argv[])
{   
  if (argc != 4) {
      printf("Usage: %s <rsa_params_file> <dsa_params_file> <portnum>\n", argv[0]);
      exit(0);
  }

  struct param_tuple tup;
  tup.rsa = RsaParams_Read(argv[1]);
  tup.dsa = DsaParams_Read(argv[2]);

  CHECK_CALL(tup.rsa);
  CHECK_CALL(tup.dsa);

  CHECK_CALL(StartSSLServer(EA_CERTIFICATE_FILE, EA_PRIVATE_KEY_FILE, 
        atoi(argv[3]), &EaServer, (void*)&tup));

  RsaParams_Free(tup.rsa);
  DsaParams_Free(tup.dsa);
}

