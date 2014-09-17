//
//  packets.h
//  tethealla
//
//  Created by Drew Rodman on 8/21/14.
//
//

#ifndef tethealla_packets_h
#define tethealla_packets_h

#include "common.h"
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

const char BB_COPYRIGHT[] =
    "Phantasy Star Online Blue Burst Game Server. Copyright 1999-2004 SONICTEAM.";

/* Indices for client/ship send_check array. */

#define SEND_PACKET_03 0x00
#define SEND_PACKET_E6 0x01
#define SEND_PACKET_E2 0x02
#define SEND_PACKET_E5 0x03
#define SEND_PACKET_E8 0x04
#define SEND_PACKET_DC 0x05
#define SEND_PACKET_EB 0x06
#define SEND_PACKET_E4 0x07
#define SEND_PACKET_B1 0x08
#define SEND_PACKET_A0 0x09
#define RECEIVE_PACKET_93 0x0A

/* Packet types and sizes. */

#define BB_LOGIN_WELCOME_TYPE 0x03
#define BB_LOGIN_WELCOME_SZ 0xC8
#define BB_LOGIN_SZ 0xB4
#define BB_LOGIN_LOGIN 0x93
#define BB_SECURITY_TYPE 0xE6
#define BB_SECURITY_SZ 0x44
#define BB_CLIENT_MSG 0x1A
#define BB_REDIRECT_TYPE 0x19
#define BB_REDIRECT_SZ 0x10
#define BB_LOGIN_DISCONNECT 0x05

/* Error codes for packet E6 */

#define BB_LOGIN_ERROR_NONE        0x00000000
#define BB_LOGIN_ERROR_UNKNOWN     0x00000001
#define BB_LOGIN_ERROR_UNREG       0x00000002
#define BB_LOGIN_ERROR_UNREG2      0x00000003
#define BB_LOGIN_ERROR_MAINT       0x00000004
#define BB_LOGIN_ERROR_USERINUSE   0x00000005
#define BB_LOGIN_ERROR_BANNED      0x00000006
#define BB_LOGIN_ERROR_BANNED2     0x00000007
#define BB_LOGIN_ERROR_UNREG3      0x00000008
#define BB_LOGIN_ERROR_INVALID     0x00000009
#define BB_LOGIN_ERROR_LOCKED      0x0000000A
#define BB_LOGIN_ERROR_PATCH       0x0000000B

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

/* Login packet send to login and ship servers. */
struct bb_login_pkt {
    bb_packet_header header;
    uint8_t unknown[8];
    uint16_t client_version;
    uint8_t unknown2[6];
    uint32_t team_id;
    char username[16];
    uint8_t unused[32];
    char password[16];
    uint8_t unused2[28];
    char hardware_info[8];
    char version_string[28];
};

/* Security data set by login and character servers. */
struct bb_security_pkt {
    bb_packet_header header;
    uint32_t error_code;
    uint32_t player_tag;
    uint32_t guild_card;
    uint32_t team_id;
    uint8_t security64[40];
    uint32_t capabilities;
};

/* Message to the client in the form of scrolling text at the
 top of their screen. */
struct bb_client_msg_pkt {
    bb_packet_header header;
    uint32_t language_code;
    const char *message;
};

/* Sent to the client to indicate the IP and port of the character server. */
struct bb_redirect_pkt {
    bb_packet_header header;
    uint32_t ip_addr;
    uint16_t port;
    uint16_t padding;
};

bool send_packet(BANANA *client, int len);

bool send_bb_login_welcome(BANANA* client, uint8_t s_seed[48], uint8_t c_seed[48]);
bool send_bb_security(BANANA* client, uint32_t guildcard, uint32_t error);
bool send_bb_client_message(BANANA* client, const char* message);
bool send_bb_redirect(BANANA* client, uint32_t ip, uint16_t port);
bool send_ship_disconnect_client (unsigned gcn, ORANGE* ship);

#endif
