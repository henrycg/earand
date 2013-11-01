#include <unistd.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include "dsa_ca.h"
#include "rsa_ca.h"
#include "ssl_server.h"

/**
 * ===== CA Server =====
 * This process plays the role of the CA in the
 * RSA keygen protocol.  
 */

struct ca_tuple {
  DsaCa dsa;
  RsaCa rsa;
};

void CaServer(SSL* ssl, void* data)
{
  struct ca_tuple* tuple = (struct ca_tuple*)data;

  int rfd, wfd;
  FILE* rfp;
  FILE* wfp;
  SetupFileDescriptors(ssl, &rfd, &rfp, &wfd, &wfp);

  int mode;
  CHECK_CALL(fscanf(rfp, "%d ", &mode) == 1);

    // Read signing request in
  fprintf(stderr, "\tReading request...\n");
  X509* cert_in = d2i_X509_fp(rfp, NULL);
  if(!cert_in) {
    fatal("CA failed to read X509 cert in");
  }

  fprintf(stderr, "\tSigning cert...\n");

  X509* cert_out = NULL;
  if(mode == RSA_CLIENT) {
    cert_out = RsaCa_SignCertificate(tuple->rsa, cert_in);
  } else if(mode == DSA_CLIENT) {
    cert_out = DsaCa_SignCertificate(tuple->dsa, cert_in);
  } else {
    fprintf(stderr, "\tGot invalid mode: %d\n", mode);
  }
    
  if(!cert_out) {
    fatal("CA failed to sign X509 request");
  }

  // Write cert out
  fprintf(stderr, "\tWriting cert...\n");
  if(!i2d_X509_fp(wfp, cert_out)) {
    fatal("CA failed to write X509 certificate");
  }
  CHECK_CALL(!fflush(wfp));

  fprintf(stderr, "\tDone!\n");

  X509_free(cert_in);
  X509_free(cert_out);
  fclose(rfp);
  fclose(wfp);
}

int main(int argc, char *argv[])
{   
  if (argc != 4) {
    printf("Usage: %s <rsa_params_file> <dsa_params_file> <portnum>\n", argv[0]);
    exit(0);
  }

  RsaParams rsa_params = RsaParams_Read(argv[1]);
  DsaParams dsa_params = DsaParams_Read(argv[2]);
  CHECK_CALL(rsa_params);
  CHECK_CALL(dsa_params);

  struct ca_tuple ca;
  ca.rsa = RsaCa_New(rsa_params);
  ca.dsa = DsaCa_New(dsa_params);

  CHECK_CALL(StartSSLServer(CA_CERTIFICATE_FILE, CA_PRIVATE_KEY_FILE, 
        atoi(argv[3]), &CaServer, (void*)&ca));

  RsaCa_Free(ca.rsa);
  DsaCa_Free(ca.dsa);
  RsaParams_Free(rsa_params);
  DsaParams_Free(dsa_params);
}

