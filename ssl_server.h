#ifndef _SSL_SERVER_H
#define _SSL_SERVER_H

#include <openssl/ssl.h>
#include "util.h"

#define FAIL    -1

/* This is the type of a server object */
typedef void (*ServerFunction)(SSL* ssl, void* data);

/**
 * Start an SSL server process using the certificate and
 * private key provided. The server_data pointer is passed
 * to each server instance started up.
 */
int StartSSLServer(const char* cert_file, const char* key_file, 
    int portnum, ServerFunction server_func,
    void* server_data);

/**
 * A ServerFunction that prints debugging info
 */
void DebugServer(SSL* ssl, void* data); 

#endif
