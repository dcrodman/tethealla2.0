#ifndef tehealla_login_server_h
#define tehealla_login_server_h

extern "C" {
    #include "encryption.h"
    
}

/* Player Structure */

typedef struct st_banana {
	int plySockfd;
	int login;
	unsigned char peekbuf[8];
	unsigned char rcvbuf [TCP_BUFFER_SIZE];
	unsigned short rcvread;
	unsigned short expect;
	unsigned char decryptbuf [TCP_BUFFER_SIZE];
	unsigned char sndbuf [TCP_BUFFER_SIZE];
	unsigned char encryptbuf [TCP_BUFFER_SIZE];
	int snddata,
    sndwritten;
	unsigned char packet [TCP_BUFFER_SIZE];
	unsigned short packetdata;
	unsigned short packetread;
	int crypt_on;
	PSO_CRYPT server_cipher, client_cipher;
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
	int todc;
	unsigned char IP_Address[16];
	char hwinfo[18];
	int isgm;
	int dress_flag;
	unsigned connection_index;
} BANANA;

#endif