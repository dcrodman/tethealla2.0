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

/* Send the packet from the client's send buffer to the client. Will try
 until the entire packet is sent. */
bool send_packet(patch_client* client) {

    uint32_t length = client->send_size;
    printf("send_packet; length: %d\n", length);
    int total = 0, remaining = length;
    int bytes_sent;

    if (DEBUGGING) {
        printf("Sending to %s: \n", client->ip_addr_str);
        print_payload(client->send_buffer, length);
    }

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

void print_hex_ascii_line(const u_char *payload, int len, int offset) {

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

    return;
}

void print_payload(const u_char *payload, int len) {

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

    return;
}