#ifndef tehealla_login_h
#define tehealla_login_h

// TODO: Fix cyclical import.
#include <cstdint>
#include "login_server.h"

/* Borrowed from Sylverant for reversing byte order of packets. */
#if defined(WORDS_BIGENDIAN) || defined(__BIG_ENDIAN__)
#define LE16(x) (((x >> 8) & 0xFF) | ((x & 0xFF) << 8))
#define LE32(x) (((x >> 24) & 0x00FF) | \
((x >>  8) & 0xFF00) | \
((x & 0xFF00) <<  8) | \
((x & 0x00FF) << 24))
#else
#define LE16(x) x
#define LE32(x) x
#endif

#define BB_HEADER_LEN 8

#define BB_LOGIN_WELCOME_TYPE 0x03
#define BB_LOGIN_WELCOME_SZ 0xC8

#define BB_LOGIN_SZ 0xB4
#define BB_LOGIN_LOGIN 0x93

#define BB_LOGIN_DISCONNECT 0x05

const char BB_COPYRIGHT[] = "Phantasy Star Online Blue Burst Game Server. Copyright 1999-2004 SONICTEAM.";
const char *PSO_CLIENT_VER_STRING = "TethVer12510";
const int PSO_CLIENT_VER = 0x41;

/* The BlueBurst header (8 bytes as opposed to 4). */
struct bb_packet_header {
    uint16_t length;
    uint16_t type;
    uint32_t flags;
};

/* Login welcome packet.*/
struct bb_login_welcome_pkt {
    bb_packet_header header;
    char copyright[96];
    uint8_t server_vector[48];
    uint8_t client_vector[48];
};

bool send_packet(BANANA *client, int len);
int send_bb_login_welcome(BANANA* client, uint8_t s_seed[48], uint8_t c_seed[48]);

int handle_login(BANANA* client);
int login_process_packet(BANANA* client);

#endif