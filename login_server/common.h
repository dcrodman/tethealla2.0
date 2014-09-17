/* Temporary source file to organize functions used by multiple server functions
 without leaving them in login_server.cc and creating cyclical dependencies.
 */

#ifndef tethealla_common_h
#define tethealla_common_h

#include <list>
#include "login_server.h"

extern "C" {
    #include "sniffex.h"
    #include "utils.h"
}

extern std::list<BANANA*> client_connections;

void MDString (char *inString, char *outString);
void limit_connections(BANANA* connect);

void prepare_key(unsigned char *keydata, unsigned len, struct rc4_key *key);
void rc4(unsigned char *buffer, unsigned len, struct rc4_key *key);
void compressShipPacket ( ORANGE* ship, unsigned char* src, unsigned long src_size );
void decompressShipPacket ( ORANGE* ship, unsigned char* dest, unsigned char* src );

#endif
