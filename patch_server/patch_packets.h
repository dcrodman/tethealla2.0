/************************************************************************
 Tethealla Patch Server 2.0
 Copyright (C) 2008 Terry Chatman Jr., modified version Copyright (C) 2014
 Andrew Rodman.

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License version 3 as
 published by the Free Software Foundation.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
 ************************************************************************

 This project is based on Terry Chatman Jr.'s original implementation of the
 Tethealla PSOBB Private Server version 0.01. Please note that this project
 also includes code borrowed from Lawrennce Sebald's Sylverant project at
 <http://sylverant.net>. I do not claim to have written all of the code included,
 in many cases only modified or just included it as a convenience for my own work.

 */

#ifndef tethealla_patch_packets_h
#define tethealla_patch_packets_h

#define BB_WELCOME_LENGTH 0x04C
#define BB_WELCOME_TYPE 0x02
#define BB_WELCOME_ACK 0x02
#define BB_PATCH_LOGIN 0x04
#define PATCH_WELCOME_MSG 0x13
#define PATCH_REDIRECT 0x14

#define DATA_WELCOME_ACK 0x0B
#define DATA_CHDIR_TYPE 0x09
#define DATA_CHDIR_SIZE 0x44
#define DATA_CHDIR_ABOVE 0x0A
#define DATA_CHKFILE_TYPE 0x0C
#define DATA_CHKFILE_SIZE 0x28
#define DATA_LIST_DONE 0x0D
#define DATA_FILES_DONE 0x12

#define DATA_CLIENT_LIST_DONE 0x10
#define DATA_CLIENT_FILE_TYPE 0x0F
#define DATA_CLIENT_FILE_SIZE 0x10

#include <cstdint>
#include <sys/socket.h>

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

const static char copyright_message[] = {
    "Patch Server. Copyright SonicTeam, LTD. 2001"
};

/* 8-byte header included with all packets sent by PSOBB. */
struct packet_hdr {
    uint16_t pkt_len;
    uint16_t pkt_type;
};

/* Welcome packet sent by the server to the client after connecting. */
struct welcome_packet {
    packet_hdr header;
    char copyright[44];
    uint8_t padding[20];     /* All zeroes */
    uint32_t server_vector;
    uint32_t client_vector;
};

/* Redirect packet sent by PATCH with the IP & port of DATA. */
struct redirect_packet {
    packet_hdr header;
    uint32_t dataIP;
    uint16_t dataPort;
    uint16_t padding;
};

/* The Login packet which contains the user's username/password. (Sylverant) */
struct login_packet {
    packet_hdr header;
    uint8_t padding1[12];    /* All zeroes */
    char username[16];
    char password[16];
    uint8_t padding2[64];    /* All zeroes */
};

/* Set directory packet sent to the client. */
struct change_dir_packet {
    packet_hdr header;
    char dirname[64];
};

/* Packet for a file for the client to report back. */
struct check_file_packet {
    packet_hdr header;
    uint32_t patchID;
    char filename[32];
};

void print_hex_ascii_line(const u_char *payload, int len, int offset);
void print_payload(const u_char *payload, int len);

bool send_packet(patch_client* client);
bool send_welcome(patch_client* client, uint32_t cvector, uint32_t svector);
bool send_welcome_ack(patch_client* client);
bool send_welcome_message(patch_client *client, packet_hdr *header,
    const char* msg, uint32_t size);
bool send_redirect(patch_client* client, uint32_t serverIP, uint16_t serverPort);

bool send_data_ack(patch_client* client);
bool send_change_directory(patch_client* client, char* dir);
bool send_dir_above(patch_client* client);
bool send_check_file(patch_client* client, uint32_t index, char *filename);
bool send_list_done(patch_client* client);
bool send_files_done(patch_client* client);

#endif
