//
//  packets.h
//  tethealla
//
//  Created by Drew Rodman on 9/17/14.
//
//

#ifndef tethealla_packets_h
#define tethealla_packets_h

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

#endif
