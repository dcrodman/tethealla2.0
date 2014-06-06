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

#include <cstdio>
#include <cctype>

#include "patch_server.h"
#include "patch_packets.h"
extern "C" {
    #include "sniffex.h"
}

/* Send the packet from the client's send buffer to the client. Will try
 until the entire packet is sent. Note that client->send_size must be
 set to the expected length of the packet. */
bool send_packet(patch_client* client) {

    uint32_t length = client->send_size;
    int total = 0, remaining = length;
    int bytes_sent;

    while (total < length) {
        bytes_sent = send(client->socket, client->send_buffer + total, remaining, 0);
        if (bytes_sent == -1) {
            perror("send");
            return false;
        }
        total += bytes_sent;
        remaining -= bytes_sent;
    }
    // TODO: Handle moving client buffer or whatever
    memset(client->send_buffer, 0, TCP_BUFFER_SIZE);
    return true;
}

/* Send the BB welcome packet. */
bool send_welcome(patch_client* client, uint32_t cvector, uint32_t svector) {
    welcome_packet w_pkt;
    w_pkt.header.pkt_len = BB_WELCOME_LENGTH;
    w_pkt.header.pkt_type = BB_WELCOME_TYPE;

    memcpy(w_pkt.copyright, copyright_message, 44);
    memset(w_pkt.padding, 0, 20);
    w_pkt.server_vector = svector;
    w_pkt.client_vector = cvector;

    client->send_size = BB_WELCOME_LENGTH;
    memcpy(client->send_buffer, &w_pkt, BB_WELCOME_LENGTH);

    if (!send_packet(client)) {
        perror("send");
        return false;
    }
    return true;
}

/* Simple 4-byte acknowledgement from the server upon receipt of the client's
 4-byte ack of the welcome packet. */
bool send_welcome_ack(patch_client* client) {
    packet_hdr pkt;
    pkt.pkt_len = 0x04;
    pkt.pkt_type = 0x04;

    client->send_size = 4;
    memcpy(client->send_buffer, &pkt, 4);
    CRYPT_CryptData(&client->server_cipher, &client->send_buffer, 4, 1);

    return send_packet(client);
}

// Send IP address and port # of the DATA portion of the patch server.
bool send_redirect(patch_client* client, uint32_t serverIP, uint16_t serverPort) {
    redirect_packet *pkt = (redirect_packet*) client->send_buffer;
    pkt->header.pkt_type = PATCH_REDIRECT;
    pkt->header.pkt_len = 0x0C;

    pkt->dataIP = serverIP;
    pkt->dataPort = serverPort;
    pkt->padding = 0;

    printf("Redirect packet\n");
    print_payload(client->send_buffer, 0x0C);
    printf("\n");

    CRYPT_CryptData(&client->server_cipher, &client->send_buffer, 0x0C, 1);
    client->send_size = 0x0C;

    return send_packet(client);
}

/* In order to get here, the client must have sent us packet 0x04 containing
 the login information of the client. At this point I don't care whether or
 not the client has a valid username and password since we're just patching
 their PSOBB client and not accessing account information, so I'm going to
 ignore it for now and respond with the subsequent 0x13 packet (patch server
 welcome message visible to the user). */
bool send_welcome_message(patch_client *client, packet_hdr *header,
        const char* msg, uint32_t size) {

    //login_packet *pkt = (login_packet*) (client->send_buffer + sizeof(packet_hdr));
    memset(client->send_buffer, 0, TCP_BUFFER_SIZE);

    uint8_t header_size = sizeof(packet_hdr);
    memcpy(client->send_buffer + header_size, msg, size);

    // Pad with 0s until packet length is a mutliple of 4 (we've already
    // 0'd out the buffer, so we just need to make sure the packet size
    // is correct.
    uint16_t pkt_size = header_size + size;
    while (pkt_size % 4)
        pkt_size++;

    packet_hdr *pkt_hdr = (packet_hdr*) client->send_buffer;
    pkt_hdr->pkt_type = LE16(PATCH_WELCOME_MSG);
    pkt_hdr->pkt_len = LE16(pkt_size);
    client->send_size = pkt_size;

    printf("Welcome Message Packet: \n");
    print_payload(client->send_buffer, pkt_size);
    printf("\n");

    CRYPT_CryptData(&client->server_cipher, &client->send_buffer, pkt_size, 1);

    return send_packet(client);
}
