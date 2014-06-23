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
 until the entire packet is sent. Len indicates the total number of bytes
 that will be sent. */
bool send_packet(patch_client* client, int len) {
    int total = 0, remaining = len;
    int bytes_sent;

    while (total < len) {
        bytes_sent = send(client->socket, client->send_buffer + total, remaining, 0);
        if (bytes_sent == -1) {
            perror("send");
            return false;
        }
        total += bytes_sent;
        remaining -= bytes_sent;
    }

    memmove(client->send_buffer, client->send_buffer + total, total);
    client->send_size -= total;

    return true;
}

/* Send the BB welcome packet. */
bool send_welcome(patch_client* client, uint32_t cvector, uint32_t svector) {
    welcome_packet w_pkt;
    w_pkt.header.pkt_len = PATCH_WELCOME_LENGTH;
    w_pkt.header.pkt_type = PATCH_WELCOME_TYPE;

    memcpy(w_pkt.copyright, copyright_message, 44);
    memset(w_pkt.padding, 0, 20);
    w_pkt.server_vector = svector;
    w_pkt.client_vector = cvector;

    client->send_size += PATCH_WELCOME_LENGTH;
    memcpy(client->send_buffer, &w_pkt, PATCH_WELCOME_LENGTH);

    if (!send_packet(client, PATCH_WELCOME_LENGTH)) {
        perror("send");
        return false;
    }
    return true;
}

/* Simple 4-byte acknowledgement from the server upon receipt of the client's
 4-byte ack of the welcome packet. */
bool send_welcome_ack(patch_client* client) {
    packet_hdr *pkt = (packet_hdr*) client->send_buffer;
    pkt->pkt_len = 0x04;
    pkt->pkt_type = 0x04;

    client->send_size += 4;
    CRYPT_CryptData(&client->server_cipher, &client->send_buffer, 4, 1);

    return send_packet(client, 0x04);
}

// Send IP address and port # of the DATA portion of the patch server.
bool send_redirect(patch_client* client, uint32_t serverIP, uint16_t serverPort) {
    redirect_packet *pkt = (redirect_packet*) client->send_buffer;
    pkt->header.pkt_type = PATCH_REDIRECT;
    pkt->header.pkt_len = 0x0C;

    pkt->dataIP = serverIP;
    pkt->dataPort = serverPort;
    pkt->padding = 0;

    CRYPT_CryptData(&client->server_cipher, &client->send_buffer, 0x0C, 1);
    client->send_size += 0x0C;

    return send_packet(client, 0x0C);
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
    client->send_size += pkt_size;

    CRYPT_CryptData(&client->server_cipher, &client->send_buffer, pkt_size, 1);

    return send_packet(client, pkt_size);
}

/* Acknowledgement sent by the DATA portion after receiving the login packet
 and before sending patch data. */
bool send_data_ack(patch_client* client) {
    packet_hdr *header = (packet_hdr*) client->send_buffer;
    header->pkt_type = LE16(DATA_WELCOME_ACK);
    header->pkt_len = LE16(0x04);
    client->send_size += 0x04;

    CRYPT_CryptData(&client->server_cipher, client->send_buffer, client->send_size, 1);

    return send_packet(client, 0x04);
}

/* Tell the clinet to change directories to the one specified by dir. */
bool send_change_directory(patch_client* client, char* dir) {
    change_dir_packet *pkt = (change_dir_packet*) client->send_buffer;
    memset(&client->send_buffer, 0, sizeof(client->send_buffer));

    pkt->header.pkt_type = LE16(DATA_CHDIR_TYPE);
    pkt->header.pkt_len = LE16(DATA_CHDIR_SIZE);
    strcpy(pkt->dirname, dir);
    client->send_size += DATA_CHDIR_SIZE;

    printf("Change Directory:\n");
    print_payload(client->send_buffer, DATA_CHDIR_SIZE);
    printf("\n");

    CRYPT_CryptData(&client->server_cipher, client->send_buffer, DATA_CHDIR_SIZE, 1);

    return send_packet(client, DATA_CHDIR_SIZE);
}

/* Tell the client to set the directory to one dir above. */
bool send_dir_above(patch_client* client) {
    packet_hdr *header = (packet_hdr*) client->send_buffer;
    header->pkt_type = LE16(DATA_CHDIR_ABOVE);
    header->pkt_len = LE16(0x04);
    client->send_size += 0x04;

    printf("Set Dir Above:\n");
    print_payload(client->send_buffer, 0x04);
    printf("\n");

    CRYPT_CryptData(&client->server_cipher, client->send_buffer, 0x04, 1);

    return send_packet(client, 0x04);
}

/* Send information about a particular file to the client to verify its
 checksum and see if it needs patching. */
bool send_check_file(patch_client* client, uint32_t index, char *filename) {
    if (strlen(filename) > 32)
        return false;

    check_file_packet *pkt = (check_file_packet*) client->send_buffer;
    pkt->header.pkt_type = LE16(DATA_CHKFILE_TYPE);
    pkt->header.pkt_len = LE16(DATA_CHKFILE_SIZE);
    pkt->patchID = LE32(index);
    strcpy(pkt->filename, filename);

    printf("Send File Check\n");
    print_payload(client->send_buffer, DATA_CHKFILE_SIZE);
    printf("\n");

    client->send_size += DATA_CHKFILE_SIZE;
    CRYPT_CryptData(&client->server_cipher, client->send_buffer, DATA_CHKFILE_SIZE, 1);

    return send_packet(client, DATA_CHKFILE_SIZE);
}

/* Tell the client that we're done sending our list of patches. */
bool send_list_done(patch_client* client) {
    packet_hdr *header = (packet_hdr*) client->send_buffer;
    header->pkt_type = LE16(DATA_LIST_DONE);
    header->pkt_len = LE16(0x04);
    client->send_size += 0x04;

    printf("Send List Done\n");
    print_payload(client->send_buffer, 0x04);
    printf("\n");

    CRYPT_CryptData(&client->server_cipher, client->send_buffer, client->send_size, 1);

    return send_packet(client, 0x04);
}

/* Sent to the client to inform them that the server has finished sending the list
 of files to check. */
bool send_files_done(patch_client* client) {
    packet_hdr *header = (packet_hdr*) client->send_buffer;
    header->pkt_type = LE16(DATA_FILES_DONE);
    header->pkt_len = LE16(0x04);
    client->send_size += 0x04;

    printf("Send Files Done\n");
    print_payload(client->send_buffer, 0x04);
    printf("\n");

    CRYPT_CryptData(&client->server_cipher, client->send_buffer, client->send_size, 1);

    return send_packet(client, 0x04);
}

/* Sent to the client to detail the files that are about to be sent. */
bool send_update_files(patch_client *client, uint32_t total_size, uint32_t num_files) {
    update_files_packet *packet = (update_files_packet*) client->send_buffer;
    packet->header.pkt_type = LE16(DATA_UPDATE_FILES_TYPE);
    packet->header.pkt_len = LE16(DATA_UPDATE_FILES_SIZE);
    packet->total_size = total_size;
    packet->num_files = num_files;

    printf("Sending Needs Update\n");
    print_payload(client->send_buffer, DATA_UPDATE_FILES_SIZE);
    printf("\n");

    client->send_size += DATA_UPDATE_FILES_SIZE;
    CRYPT_CryptData(&client->server_cipher, client->send_buffer, DATA_UPDATE_FILES_SIZE, 1);
    return send_packet(client, DATA_UPDATE_FILES_SIZE);
}
