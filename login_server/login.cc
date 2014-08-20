#include <cstring>
#include <cstdio>
#include <sys/socket.h>

extern "C" {
    #include "sniffex.h"
}

#include "login.h"

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

int send_bb_login_welcome(BANANA* client, uint8_t s_seed[48], uint8_t c_seed[48]) {
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

int handle_login(BANANA* client) {

}

/* Process a client packet sent to the LOGIN server. Returns 0 on success, 1
 - on error and -1 if the handler received an unrecognized packet type. */
int login_process_packet(BANANA* client) {
    bb_packet_header* header = (bb_packet_header*) client->recv_buffer;
    header->type = LE16(header->type);
    header->length = LE16(header->length);

    bool result;
    switch (header->type) {
        case BB_LOGIN_DISCONNECT:
            client->todc = true;
            result = 0;
            break;
        case BB_LOGIN_LOGIN:
            result = handle_login(client);
            break;
        default:
            result = -1;
            break;
        }
    return result;
}