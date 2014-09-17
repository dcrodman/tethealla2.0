//
//  common.cc
//  tethealla
//
//  Created by Drew Rodman on 8/21/14.
//
//

#include <cstring>

extern "C" {
    #include "md5.h"
}

#include "common.h"

/* Computes the message digest for string inString.
 Prints out message digest, a space, the string (in quotes) and a
 carriage return.
 */
void MDString (char *inString, char *outString) {
    unsigned char c;
    MD5_CTX mdContext;
    unsigned int len = strlen (inString);
    
    MD5Init (&mdContext);
    MD5Update (&mdContext, (unsigned char*)inString, len);
    MD5Final (&mdContext);
    for (c=0;c<16;c++) {
        *outString = mdContext.digest[c];
        outString++;
    }
}

/* Ensure that a client has not connected more than MAX_SIMULTANEOUS_CONNECTIONS times.
 If they have, mark the oldest connection as being ready to disconnect. */
void limit_connections(BANANA* connect)
{
	unsigned numConnections = 0, c4;
	BANANA *c5;
    std::list<BANANA*>::const_iterator c, c_end;
    
    // Limit the number of connections from an IP address to MAX_SIMULTANEOUS_CONNECTIONS.
    for (c = client_connections.begin(), c_end = client_connections.end(); c != c_end; ++c) {
        if ((!strcmp((const char*)(*c)->IP_Address, (const char*)connect->IP_Address)))
            numConnections++;
    }
    
    // Delete the oldest connection to the server if there are more than
    // MAX_SIMULTANEOUS_CONNECTIONS connections from a certain IP address.
	if (numConnections > MAX_SIMULTANEOUS_CONNECTIONS) {
		c4 = 0xFFFFFFFF;
		c5 = NULL;
        for (c = client_connections.begin(), c_end = client_connections.end(); c != c_end; ++c) {
            if ((!strcmp((const char*)(*c)->IP_Address, (const char*)connect->IP_Address)))
                if ((*c)->connected < c4) {
                    c4 = (*c)->connected;
                    c5 = (*c);
                }
        }
        
        if (c5)
            c5->todc = true;
	}
}

/* expand a key (makes a rc4_key) */

void prepare_key(unsigned char *keydata, unsigned len, struct rc4_key *key)
{
    unsigned index1, index2, counter;
    unsigned char *state;
    
    state = key->state;
    
    for (counter = 0; counter < 256; counter++)
        state[counter] = counter;
    
    key->x = key->y = index1 = index2 = 0;
    
    for (counter = 0; counter < 256; counter++) {
        index2 = (keydata[index1] + state[counter] + index2) & 255;
        
        /* swap */
        state[counter] ^= state[index2];
        state[index2]  ^= state[counter];
        state[counter] ^= state[index2];
        
        index1 = (index1 + 1) % len;
    }
}

/* reversible encryption, will encode a buffer updating the key */

void rc4(unsigned char *buffer, unsigned len, struct rc4_key *key)
{
    unsigned x, y, xorIndex, counter;
    unsigned char *state;
    
    /* get local copies */
    x = key->x; y = key->y;
    state = key->state;
    
    for (counter = 0; counter < len; counter++) {
        x = (x + 1) & 255;
        y = (state[x] + y) & 255;
        
        /* swap */
        state[x] ^= state[y];
        state[y] ^= state[x];
        state[x] ^= state[y];
        
        xorIndex = (state[y] + state[x]) & 255;
        
        buffer[counter] ^= state[xorIndex];
    }
    
    key->x = x; key->y = y;
}

void compressShipPacket ( ORANGE* ship, unsigned char* src, unsigned long src_size )
{
	unsigned char* dest;
	unsigned long result;
    
	if (ship->shipSockfd >= 0)
	{
		if (PACKET_BUFFER_SIZE - ship->snddata < (int) ( src_size + 100 ) )
			//initialize_ship(ship);
            ship->todc = true;
		else
		{
			if ( ship->crypt_on )
			{
				dest = &ship->sndbuf[ship->snddata];
				// Store the original packet size before RLE compression at offset 0x04 of the new packet.
				dest += 4;
				*(unsigned *) dest = src_size;
				// Compress packet using RLE, storing at offset 0x08 of new packet.
				//
				// result = size of RLE compressed data + a DWORD for the original packet size.
				result = RleEncode (src, dest+4, src_size) + 4;
				// Encrypt with RC4
				rc4 (dest, result, &ship->sc_key);
				// Increase result by the size of a DWORD for the final ship packet size.
				result += 4;
				// Copy it to the front of the packet.
				*(unsigned *) &ship->sndbuf[ship->snddata] = result;
				ship->snddata += (int) result;
			}
			else
			{
				memcpy ( &ship->sndbuf[ship->snddata+4], src, src_size );
				src_size += 4;
				*(unsigned *) &ship->sndbuf[ship->snddata] = src_size;
				ship->snddata += src_size;
			}
		}
	}
}

void decompressShipPacket ( ORANGE* ship, unsigned char* dest, unsigned char* src )
{
	unsigned src_size, dest_size;
	unsigned char *srccpy;
    
	if (ship->crypt_on)
	{
		src_size = *(unsigned *) src;
		src_size -= 8;
		src += 4;
		srccpy = src;
		// Decrypt RC4
		rc4 (src, src_size+4, &ship->cs_key);
		// The first four bytes of the src should now contain the expected uncompressed data size.
		dest_size = *(unsigned *) srccpy;
		// Increase expected size by 4 before inserting into the destination buffer.  (To take account for the packet
		// size DWORD...)
		dest_size += 4;
		*(unsigned *) dest = dest_size;
		// Decompress the data...
		RleDecode (srccpy+4, dest+4, src_size);
	}
	else
	{
		src_size = *(unsigned *) src;
		memcpy (dest + 4, src + 4, src_size);
		src_size += 4;
		*(unsigned *) dest = src_size;
	}
}
