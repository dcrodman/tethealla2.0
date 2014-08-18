#ifndef tehealla_login_server_h
#define tehealla_login_server_h

#include <cstdlib>

extern "C" {
    #include "encryption.h"
}

#define TCP_BUFFER_SIZE 64000
#define PACKET_BUFFER_SIZE ( TCP_BUFFER_SIZE * 16 )
#define MAX_SENDCHECK 0x0B

const char Message03[] = { "Tethealla Gate v.047" };

enum server_type {
    LOGIN,
    CHARACTER
};

/* Player Structure */

typedef struct st_banana {
	int plySockfd;  // client's socket fd
	server_type session;  // are we connected to LOGIN or CHARACTER?

    unsigned char send_buffer[TCP_BUFFER_SIZE];
    unsigned int send_size;

    unsigned char recv_buffer[TCP_BUFFER_SIZE];
    unsigned int recv_size;
    unsigned int packet_sz;

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
    int port;
    bool ipv6;
	char hwinfo[18];
	int isgm;
	int dress_flag;
	unsigned connection_index; // corresponds to index in connection list
} BANANA;

/* a RC4 expanded key session */
struct rc4_key {
    unsigned char state[256];
    unsigned x, y;
};

/* Ship Structure */

typedef struct st_orange {
	int shipSockfd;
	unsigned char name[13];
	unsigned playerCount;
	unsigned char shipAddr[5];
	unsigned char listenedAddr[4];
	unsigned short shipPort;
	unsigned char rcvbuf [TCP_BUFFER_SIZE];
	unsigned long rcvread;
	unsigned long expect;
	unsigned char decryptbuf [TCP_BUFFER_SIZE];
	unsigned char sndbuf [PACKET_BUFFER_SIZE];
	unsigned char encryptbuf [TCP_BUFFER_SIZE];
	unsigned char packet [PACKET_BUFFER_SIZE];
	unsigned long packetread;
	unsigned long packetdata;
	int snddata,
    sndwritten;
	unsigned shipID;
	int authed;
	int todc;
	int crypt_on;
	unsigned char user_key[128];
	int key_change[128];
	unsigned key_index;
	struct rc4_key cs_key; // Encryption keys
	struct rc4_key sc_key; // Encryption keys
	unsigned connection_index;
	unsigned connected;
	unsigned last_ping;
	int sent_ping;
} ORANGE;

#endif