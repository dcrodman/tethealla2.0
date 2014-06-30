#ifndef tehealla_login_server_h
#define tehealla_login_server_h

#include <cstdlib>

extern "C" {
    #include "encryption.h"
}

#define TCP_BUFFER_SIZE 64000
#define MAX_SENDCHECK 0x0B

const char Message03[] = { "Tethealla Gate v.047" };

/* Player Structure */

typedef struct st_banana {
	int plySockfd;  // client's socket fd
	int login;  // are we connected to LOGIN or CHARACTER?
	unsigned char peekbuf[8];   // decrypted header
	unsigned char rcvbuf [TCP_BUFFER_SIZE]; // intermediate rcv buffer?
	unsigned short rcvread; // how much data is in rcvbuf
	unsigned short expect; // how much data we're expecting
	unsigned char decryptbuf [TCP_BUFFER_SIZE];
	unsigned char sndbuf [TCP_BUFFER_SIZE]; // our buffer of data to send (used directly)
	unsigned char encryptbuf [TCP_BUFFER_SIZE]; // where send data is dumped before encryption
	int snddata, sndwritten; // how much data we have to send and how much we have sent
	unsigned char packet [TCP_BUFFER_SIZE]; // our current working packet
	unsigned short packetdata; // size of our current working packet?
	unsigned short packetread;
	int crypt_on;
	CRYPT_SETUP server_cipher, client_cipher; // client/server keys
	unsigned guildcard;
	char guildcard_string[12];
	unsigned char guildcard_data[20000];
	int sendingchars;
	short slotnum;
	unsigned lastTick;		// The last second
	unsigned toBytesSec;	// How many bytes per second the server sends to the client
	unsigned fromBytesSec;	// How many bytes per second the server receives from the client
	unsigned packetsSec;	// How many packets per second the server receives from the client
	unsigned connected;
	unsigned char sendCheck[MAX_SENDCHECK+2];
	int todc; // this this client about to be disconnected?
	unsigned char IP_Address[16];
	char hwinfo[18];
	int isgm;
	int dress_flag;
	unsigned connection_index; // corresponds to index in connection list
} BANANA;

#endif