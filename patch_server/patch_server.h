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

#ifndef __tethealla2_0__patch_server__
#define __tethealla2_0__patch_server__

#include <iostream>
#include <sys/socket.h>

extern "C" {
    #include "encryption.h"
    #include "mtwist.h"
}

#define BB_WELCOME_LENGTH 0x04C
#define BB_WELCOME_TYPE 0x02

const static char copyright_message[] = {
    "Patch Server. Copyright SonicTeam, LTD. 2001"
};

/* 8-byte header included with all packets sent by PSOBB. */
struct packet_hdr {
    u_short pkt_len;
    u_short pkt_type;
};

/* Welcome packet sent by the server to the client after connecting. */
struct welcome_packet {
    packet_hdr header;
    char copyright[44];
    uint8_t padding[20];     /* All zeroes */
    u_int8_t server_vector[48];
    u_int8_t client_vector[48];
};

/* The Login packet which contains the user's username/password. */
struct login_packet {
    packet_hdr hdr;
    uint8_t padding1[12];    /* All zeroes */
    char username[16];
    char password[16];
    uint8_t padding2[64];    /* All zeroes */
};

/* Structure for representing connected clients. */
struct patch_client {
    int socket;
    int port;
    bool ipv6;

    char* ip_addr_str;
    sockaddr_storage ip_addr;
    
    CRYPT_SETUP client_cipher;
    CRYPT_SETUP server_cipher;
    
    unsigned char *send_buffer;
    unsigned char *receive_buffer;
};

#endif
