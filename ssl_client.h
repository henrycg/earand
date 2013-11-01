#ifndef _SSL_CLIENT_H
#define _SSL_CLIENT_H

#include <stdbool.h>

typedef void (*ClientFunction)(SSL* ssl, void* data);

/**
 * Start up an SSL client that connects to the 
 * host/port. When the connection is open, 
 * client_func is called with the SSL* object.
 */
bool MakeSSLRequest(const char* hostname, int port,
    ClientFunction client_func, void* client_data);

#endif
