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
#include <cstdlib>
#include <cerrno>
#include <iostream>
#include <list>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

#include "patch_server.h"
#include "mtwist.h"

const bool DEBUGGING = true;

// Allowed number of pending connections.
const int BACKLOG = 10;

const char *PATCH_PORT = "11000";
const char *DATA_PORT = "11001";

std::list<patch_client*> client_connections;

void destory_client(patch_client* client);

/* Send the packet from the client's send buffer to the client. Will try
 until the entire packet is sent. The client's send buffer will be freed.*/
bool send_packet(patch_client* client, int length) {
    int total = 0, remaining = length;
    int bytes_sent;

    while (total < length) {
        bytes_sent = send(client->socket, client->send_buffer + total, remaining, 0);

        if (total == -1) {
            perror("send");
            destory_client(client);
            return false;
        }
        total += bytes_sent;
        remaining -= bytes_sent;
    }
    return true;
}

/* Send the BB welcome packet. */
bool send_welcome(patch_client* client, u_int8_t cvector[48], u_int8_t svector[48]) {
    printf("send_welcome: Sending welcome packet to client %d\n", client->socket);
    welcome_packet *w_pkt = (welcome_packet*) malloc(sizeof(welcome_packet));
    memset(&w_pkt, 0, sizeof(welcome_packet));

    w_pkt->header.pkt_len = htons(BB_WELCOME_LENGTH);
    w_pkt->header.pkt_type = htons(BB_WELCOME_TYPE);
    
    memcpy(w_pkt->copyright, copyright_message, 44);
    memcpy(w_pkt->client_vector, cvector, 48);
    memcpy(w_pkt->server_vector, svector, 48);
    
    client->send_buffer = (unsigned char*) w_pkt;
    
    if (DEBUGGING) {
        printf("Sending welcome packet to %s\n", client->ip_addr_str);
        //display_packet(client->send_buffer, BB_WELCOME_LENGTH);
    }

    if (!send_packet(client, BB_WELCOME_LENGTH)) {
        perror("send");
        destory_client(client);
        return false;
    }
    return true;
}

/* Accept a new client connection, initialize the encryption for
 the session and send them the welcome packet. If the welcome packet
 fails, return NULL as the client will have been disconnected. */
patch_client* accept_client(int sockfd) {
    printf("accept_client: Creating client connection\n");
    sockaddr_storage clientaddr;
    socklen_t addrsize = sizeof clientaddr;
    patch_client* client = (patch_client*) calloc(1, sizeof(patch_client));
    
    int clientfd;
    if ((clientfd = accept(sockfd, (struct sockaddr*) &clientaddr, &addrsize)) == -1) {
        perror("accept_client");
        return NULL;
    }
    client->socket = clientfd;

    // IPv6?
    if (clientaddr.ss_family == AF_INET) {
        sockaddr_in* ip = ((sockaddr_in*)&clientaddr);
        client->port = ip->sin_port;
        client->ipv6 = false;

        client->ip_addr_str = (char*) malloc(INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip->sin_addr), client->ip_addr_str, INET_ADDRSTRLEN);
    } else {
        sockaddr_in6* ip = ((sockaddr_in6*)&clientaddr);
        client->port = ip->sin6_port;
        client->ipv6 = true;
        
        client->ip_addr_str = (char*) malloc(INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip->sin6_addr), client->ip_addr_str, INET6_ADDRSTRLEN);
    }
    
    /* Generate the encryption keys for the client and server. Shamelessly
     stolen from Sylverant, thank you Lawrence! */
    uint32_t client_seed_dc, server_seed_dc;
    uint8_t client_seed_bb[48], server_seed_bb[48];
    for(int i = 0; i < 48; i += 4) {
        //client_seed_dc = genrand_int32();
        client_seed_dc = 22284831;
        //server_seed_dc = genrand_int32();
        server_seed_dc = 23948292;
        
        client_seed_bb[i + 0] = (uint8_t)(client_seed_dc >>  0);
        client_seed_bb[i + 1] = (uint8_t)(client_seed_dc >>  8);
        client_seed_bb[i + 2] = (uint8_t)(client_seed_dc >> 16);
        client_seed_bb[i + 3] = (uint8_t)(client_seed_dc >> 24);
        server_seed_bb[i + 0] = (uint8_t)(server_seed_dc >>  0);
        server_seed_bb[i + 1] = (uint8_t)(server_seed_dc >>  8);
        server_seed_bb[i + 2] = (uint8_t)(server_seed_dc >> 16);
        server_seed_bb[i + 3] = (uint8_t)(server_seed_dc >> 24);
    }
    
    CRYPT_CreateKeys(&client->server_cipher, server_seed_bb, CRYPT_BLUEBURST);
    CRYPT_CreateKeys(&client->client_cipher, client_seed_bb, CRYPT_BLUEBURST);
    
    // Add them to our list of currently connected clients.
    client_connections.push_front(client);
    
    /* At this point I really only care about the BlueBurst client, otherwise there would
    be a condition here to check for the type of client. The connection can't continue
    without the client receiving this packet, so it's all or nothing. */
    if (send_welcome(client, client_seed_bb, server_seed_bb))
        return client;
    else
        return NULL;
}

/* Disconnect a client, remove it from the list of client connections
 and free the memory associated with the structure.*/
void destory_client(patch_client* client) {
    // free ip
    // close socket
}

/* Create and open a server socket to start listening on a particular port.
 Args:
    port: Port on which to listen.
    hints: Populated struct for getaddrinfo.
*/
int create_socket(const char* port, const addrinfo *hints) {
    char c;
    int status = 0, sockfd;
    addrinfo *server;
    
    if ((status = getaddrinfo(NULL, port, hints, &server)) != 0) {
        printf("getaddrinfo(): %s\n", gai_strerror(status));
        printf("Press any key to exit.");
        gets(&c);
        exit(1);
    }
    
    if ((sockfd = socket(server->ai_family, server->ai_socktype, server->ai_protocol)) == -1) {
        printf("socket(): ");
        printf("Press any key to exit.");
        gets(&c);
        exit(2);
    }
    
    // Avoid "Address already in use" condition/error.
    int yes = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
    
    if (bind(sockfd, (sockaddr*)server->ai_addr, server->ai_addrlen) == -1) {
        close(sockfd);
        perror("bind");
        gets(&c);
        exit(3);
    }
    
    if (listen(sockfd, BACKLOG) == -1) {
        close(sockfd);
        perror("listen");
        gets(&c);
        exit(4);
    }

    freeaddrinfo(server);
    return sockfd;
}

/* Handle incoming connections to both the PATCH and DATA portions. */
void handle_connections(int patchfd, int datafd) {
    fd_set readfds, writefds, master;
    int fd_max = (patchfd > datafd) ? patchfd : datafd;
    
    FD_ZERO(&master);
    
    FD_ZERO(&readfds);
    FD_SET(patchfd, &readfds);
    FD_SET(datafd, &readfds);
    FD_SET(patchfd, &master);
    FD_SET(datafd, &master);
    
    while (1) {
        // Copy the master set since select will modify read and write fd_sets
        readfds = master;
        writefds = master;
        if (select(fd_max + 1, &readfds, NULL, NULL, NULL) == -1) {
            perror("select");
            exit(5);
        }
        
        for (int i = 0; i < fd_max; i++) {
            if (FD_ISSET(i, &readfds)) {
                if (i == patchfd) {
                    // New connection to PATCH port
                    printf("Accepting connection to PATCH...\n");
                    patch_client *client = accept_client(patchfd);
                    if (client)
                        FD_SET(client->socket, &master);
                    fd_max = (client->socket > fd_max) ? client->socket : fd_max;
                } else if (i == datafd) {
                    // New connection to DATA port
                    printf("Accepting connection to DATA...\n");
                    patch_client *client = accept_client(datafd);
                    if (client)
                        FD_SET(client->socket, &master);
                    fd_max = (client->socket > fd_max) ? client->socket : fd_max;
                } else {
                    // Handle data from the client
                    // remove client from master if recv = 0 & destroy
                    unsigned char rcvbuf[2048];
                    size_t bytes = recv(i, &rcvbuf, sizeof(rcvbuf), 0);
                    //display_packet(rcvbuf, (int)bytes);
                    printf("Client closed connection.\n");
                    close(i);
                }
            }
            
            std::list<patch_client*>::const_iterator iterator, end;
            for (iterator = client_connections.begin(), end = client_connections.end(); iterator != end; ++iterator) {
                if (FD_ISSET((*iterator)->socket, &writefds)) {
                    printf("Could send something...");
                }
            }
        }
    }
}

int main(int argc, const char * argv[]) {
    addrinfo hints;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    
    printf("Opening PATCH socket on port %s...", PATCH_PORT);
    int patch_sockfd = create_socket(PATCH_PORT, &hints);
    printf("OK\nOpening DATA socket on port %s...", DATA_PORT);
    int data_sockfd = create_socket(DATA_PORT, &hints);
    printf("OK\n");
    
    handle_connections(patch_sockfd, data_sockfd);

    return 0;
}

