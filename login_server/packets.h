//
//  packets.h
//  tethealla
//
//  Created by Drew Rodman on 9/17/14.
//
//

#ifndef tethealla_packets_h
#define tethealla_packets_h

#include "login_server.h"

const char BB_COPYRIGHT[] = "Phantasy Star Online Blue Burst Game Server. Copyright 1999-2004 SONICTEAM.";

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

/* Packet types. */

#define BB_HEADER_LEN 8

#define BB_LOGIN_WELCOME 0x03
#define BB_LOGIN 0x93
#define BB_SECURITY 0xE6
#define BB_CLIENT_MSG 0x1A
#define BB_REDIRECT 0x19
#define BB_LOGIN_DISCONNECT 0x05
#define BB_LOGIN_TIME 0xB1
#define BB_KEYBOARD_CONFIG 0xE2

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

/* Login packet sent from the client. */
struct bb_login_pkt {
    bb_packet_header header;
    uint8_t unknown[8];
    uint16_t client_version;
    uint8_t unknown2[6];
    uint32_t team_id;
    char username[16];
    uint8_t unused[32];
    char password[16];
    uint8_t unused2[40];
    char hardware_info[8];
    char version_string[40];
};

/* Message to the client in the form of scrolling text at the top of their screen. */
struct bb_client_msg_pkt {
    bb_packet_header header;
    uint32_t language_code;
    char *message;
};

/* Client config packet as defined by newserv. */
struct bb_clientconfig {
    uint32_t magic; // must be set to 0x48615467
    uint8_t bbGameState; // status of client connecting on BB
    uint8_t bbplayernum; // selected char
    uint16_t flags; // just in case we lose them somehow between connections
    uint16_t ports[4]; // used by shipgate clients
    uint32_t unused[4];
    uint32_t unusedBBOnly[2];
};

/* Security data set by login and character servers. */
struct bb_security_pkt {
    bb_packet_header header;
    uint32_t error_code;
    uint32_t player_tag;
    uint32_t guild_card;
    uint32_t team_id;
    bb_clientconfig clientconfig;
    uint32_t capabilities;
};

/* Sent to the client to indicate the IP and port of the character server. */
struct bb_redirect_pkt {
    bb_packet_header header;
    uint32_t ip_addr;
    uint16_t port;
    uint16_t padding;
};

#endif
