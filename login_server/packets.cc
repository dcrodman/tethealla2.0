//
//  packets.cc
//  tethealla
//
//  Created by Drew Rodman on 8/21/14.
//
//

#include <cassert>
#include <cstdio>
#include <cstring>
#include <random>
#include <sys/socket.h>

extern "C" {
    #include "sniffex.h"
}
#include "common.h"
#include "packets.h"

/* Send the packet from the client's send buffer to the client. Will try
 until the entire packet is sent or an error occurs. Len indicates the
 total number of bytes that will be sent and the client's send_size will
 be recued by len. */
bool send_packet(BANANA *client, int len) {
    int total = 0, remaining = len;
    int bytes_sent;
    
    while (total < len) {
        bytes_sent = send(client->plySockfd, client->send_buffer + total, remaining, 0);
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

/* Send the welcome packet to the client when they connect to the login server.*/
bool send_bb_login_welcome(BANANA* client, uint8_t s_seed[48], uint8_t c_seed[48]) {
    bb_login_welcome_pkt *pkt = (bb_login_welcome_pkt*) client->send_buffer + client->send_size;
    memset(pkt, 0, BB_LOGIN_WELCOME_SZ);
    
    pkt->header.type = LE16(BB_LOGIN_WELCOME_TYPE);
    pkt->header.length = LE16(BB_LOGIN_WELCOME_SZ);
    strcpy(pkt->copyright, BB_COPYRIGHT);
    memcpy(pkt->server_vector, s_seed, 48);
    memcpy(pkt->client_vector, c_seed, 48);
    
    client->send_size += BB_LOGIN_WELCOME_SZ;
    
    printf("Sending BB Login Welcome\n");
    print_payload((unsigned char*)pkt, BB_LOGIN_WELCOME_SZ);
    printf("\n");
    
    return send_packet(client, BB_LOGIN_WELCOME_SZ);
}

/* Sends security data to the client. Note that the guildcard must exist and
 the error must be one of the constants from packets.h (or otherwise in the
 range of 0x00-0x0B) or the packet will cause an error in the client. */
bool send_bb_security(BANANA* client, uint32_t guildcard, uint32_t error) {
    bb_security_pkt* pkt = (bb_security_pkt*) client->send_buffer + client->send_size;
    memset(pkt, 0, BB_SECURITY_SZ);
    pkt->header.type = LE16(BB_SECURITY_TYPE);
    pkt->header.length = LE16(BB_SECURITY_SZ);
    
    pkt->player_tag = 0x00010000;
    pkt->guild_card = guildcard;
    pkt->capabilities = 0x00000101; // Magic number - Tethealla always sets this.
    pkt->error_code = error;
    
    // Tethealla and newserv randomize this, so do the same.
    static std::mt19937 rand_gen(time(NULL));
    static std::uniform_int_distribution<uint32_t> dist(0, 255);
    pkt->team_id = dist(rand_gen);
    
    printf("Sending BB Security Info\n");
    print_payload((unsigned char*)pkt, BB_SECURITY_SZ);
    printf("\n");
    
    client->send_size += BB_SECURITY_SZ;
    
    return send_packet(client, BB_SECURITY_SZ);
}

/* Sends the packet that will display a large message box to the user. Intended to
 be sent before disconnecting a client in the case of some errors. */
bool send_bb_client_message(BANANA* client, const char* message) {
    bb_client_msg_pkt *pkt = (bb_client_msg_pkt*) client->send_buffer + client->send_size;
    memset(client->send_buffer + client->send_size, 0, 0x0C + strlen(message) + 8);
    pkt->header.type = LE16(BB_CLIENT_MSG);
    pkt->language_code = 0x00450009;
    int pkt_len = 0x0C + strlen(message);
    
    // TODO: Convert message to UTF-16 LE.
    char utf_message[1024];
    strcpy(utf_message, message);
    
    
    
    
    
    // Pad the packet until its length is divisible by 8.
    while (pkt_len % 8) {
        client->send_buffer[pkt_len] = 0x00;
        pkt_len++;
    }

    pkt->header.length = LE16(pkt_len);
    
    printf("Sending BB Client Message\n");
    print_payload((unsigned char*)pkt, pkt_len);
    printf("\n");

    client->send_size += pkt_len;
    
    return send_packet(client, pkt_len);
}

/* Sends the redirect packet from the login server to indicate the IP
 and port number of the character server. */
bool send_bb_redirect(BANANA* client, uint32_t ip, uint16_t port) {
    bb_redirect_pkt *pkt = (bb_redirect_pkt*) client->send_buffer + client->send_size;
    memset(pkt, 0, BB_REDIRECT_SZ);
    pkt->header.type = LE16(BB_REDIRECT_TYPE);
    pkt->header.length = LE16(BB_REDIRECT_SZ);
    
    pkt->ip_addr = ip;
    pkt->port = LE16(port);
    
    client->send_size += BB_REDIRECT_SZ;
    
    return send_packet(client, BB_REDIRECT_SZ);
}

/* Packet sent between ships to tell the other ships that this user logged on and
 to disconnect him/her if they're still active. */
bool send_ship_disconnect_client (unsigned gcn, ORANGE* ship) {
	ship->encryptbuf[0x00] = 0x08;
	ship->encryptbuf[0x01] = 0x00;
	*(unsigned *) &ship->encryptbuf[0x02] = gcn;
	compressShipPacket ( ship, &ship->encryptbuf[0x00], 0x06 );
    
    // TODO: Send this to all connected ships.
    assert(false);
}
