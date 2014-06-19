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
#include <cstdint>
#include <cerrno>
#include <iostream>
#include <list>
#include <random>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

#include <iconv.h>

extern "C" {
    #include <jansson.h>
}

#include "patch_server.h"
#include "patch_packets.h"

// Allowed number of pending connections.
const int BACKLOG = 10;
const char* CFG_NAME = "patch_config.json";
const char* LOCAL_DIR = "/usr/local/share/tethealla/config/";

// Global list of connected clients for the PATCH portion.
std::list<patch_client*> connections;

std::mt19937 rand_gen(time(NULL));
std::uniform_int_distribution<uint32_t> dist(0, UINT32_MAX);

// Global configuration file populated by load_config().
patch_config *server_config;

void destory_client(patch_client* client);

/* Process a client packet sent to the PATCH server. */
int patch_process_packet(patch_client *client) {
    packet_hdr *header = (packet_hdr*) client->recv_buffer;
    header->pkt_type = LE16(header->pkt_type);
    header->pkt_len = LE16(header->pkt_len);

    bool result;
    switch (header->pkt_type) {
        case BB_WELCOME_ACK:
            result = send_welcome_ack(client);
            break;
        case BB_PATCH_LOGIN:
            result = send_welcome_message(client, header,
                    server_config->welcome_message, server_config->welcome_size);
            if (!result)
                return -1;
            result = send_redirect(client, server_config->serverIP, htons(atoi(DATA_PORT)));
            break;
        default:
            return -2;
    }
    return result;
}

/* Process a client packet sent to the DATA server. */
int data_process_packet(patch_client *client) {
    packet_hdr *header = (packet_hdr*) client->recv_buffer;
    header->pkt_type = LE16(header->pkt_type);
    header->pkt_len = LE16(header->pkt_len);
    printf("DATA Length: %u, Type: %u\n\n", header->pkt_len, header->pkt_type);

    bool result;
    switch (header->pkt_type) {
        case BB_WELCOME_ACK:
            result = send_welcome_ack(client);
            break;
        case BB_PATCH_LOGIN:
            result = send_data_ack(client);
            send_files_done(client);
            break;
        default:
            result = 0;
            break;
    }
    return result;
}

/* Read in whatever a client is trying to send us and store it in their
 respective receiving buffer and pass it along to the packet handler for
 a response. Returns 0 on successful read, -1 on error, or 1 if the client
 closed the connection. Side effect: will close the socket if the client
 disconnects. */
int receive_from_client(patch_client *client) {
    
    printf("Receiving from %s\n", client->ip_addr_str);
    size_t bytes = recv(client->socket, &client->recv_buffer, TCP_BUFFER_SIZE, 0);
    
    if (bytes == 0) {
        client->disconnected = true;
        close(client->socket);
        return 1;
    }

    CRYPT_CryptData(&client->client_cipher, &client->recv_buffer, bytes, 0);
    print_payload(client->recv_buffer, int(bytes));

    if (client->session == PATCH)
        patch_process_packet(client);
    else
        data_process_packet(client);

    memset(client->recv_buffer, 0, sizeof(client->recv_buffer));
    return 0;
}

/* Disconnect a client, remove it from the list of client connections
 and free the memory associated with the structure.*/
void destory_client(patch_client* client) {
    free(client->ip_addr_str);
    free(client);
}

/* Accept a new client connection, initialize the encryption for
 the session and send them the welcome packet. If the welcome packet
 fails, return NULL as the client will have been disconnected. */
patch_client* accept_client(int sockfd) {
    sockaddr_storage clientaddr;
    socklen_t addrsize = sizeof clientaddr;
    patch_client* client = (patch_client*) malloc(sizeof(patch_client));
    
    int clientfd;
    if ((clientfd = accept(sockfd, (struct sockaddr*) &clientaddr, &addrsize)) == -1) {
        perror("accept_client");
        return NULL;
    }
    client->socket = clientfd;
    client->disconnected = false;

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
    
    /* Generate the encryption keys for the client and server.*/
    uint32_t client_seed = dist(rand_gen);
    uint32_t server_seed = dist(rand_gen);

    CRYPT_CreateKeys(&client->server_cipher, &server_seed, CRYPT_PC);
    CRYPT_CreateKeys(&client->client_cipher, &client_seed, CRYPT_PC);
    
    /* At this point I really only care about the BlueBurst client, otherwise there would
    be a condition here to check for the type of client. The connection can't continue
    without the client receiving this packet, so it's all or nothing. */
    if (send_welcome(client, client_seed, server_seed)) {
        // Add them to our list of currently connected clients.
        connections.push_back(client);
        return client;
    }
    else
        return NULL;
}

/* Handle incoming connections to both the PATCH and DATA portions. */
void handle_connections(int patchfd, int datafd) {
    fd_set readfds, writefds, master;
    int fd_max = (patchfd > datafd) ? patchfd : datafd;
    int select_result = 0;
    
    timeval timeout = { .tv_sec = 10 };
    
    FD_ZERO(&master);
    FD_SET(patchfd, &master);
    FD_SET(datafd, &master);
    
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);

    while (1) {
        readfds = master;

        if ((select_result = select(fd_max + 1, &readfds, &writefds, NULL, &timeout))) {
            // Check the sockets listening for new connections.
            if (FD_ISSET(patchfd, &readfds)) {
                // New connection to PATCH port
                printf("Accepting connection to PATCH...\n");
                patch_client *client = accept_client(patchfd);
                if (client) {
                    FD_SET(client->socket, &master);
                    fd_max = (client->socket > fd_max) ? client->socket : fd_max;
                    client->session = PATCH;
                }
            }
            if (FD_ISSET(datafd, &readfds)) {
                // New connection to DATA port
                printf("Accepting connection to DATA...\n");
                patch_client *client = accept_client(datafd);
                if (client) {
                    FD_SET(client->socket, &master);
                    fd_max = (client->socket > fd_max) ? client->socket : fd_max;
                    client->session = DATA;
                }
            }
            
            // Iterate over the connected clients.
            std::list<patch_client*>::const_iterator c, end;
            for (c = connections.begin(), end = connections.end(); c != end; ++c) {
                printf("Checking client %s\n", (*c)->ip_addr_str);

                if (FD_ISSET((*c)->socket, &readfds)) {
                    if (receive_from_client((*c)) == 1) {
                        FD_CLR((*c)->socket, &master);
                        fd_max = datafd;
                        destory_client(*c);
                        connections.erase(c++);
                        continue;
                    }
                }
                if (FD_ISSET((*c)->socket, &writefds)) {
                    printf("Could send something to %d\n", (*c)->socket);
                }
            }
        } else if (select_result == -1) {
            perror("select");
            exit(5);
        } else {
            // We timed out.
            printf("Timed out\n");
        }
    }
}

/* Writes the contents of a JSON error to stdout.*/
void json_error(json_error_t* error) {
    printf("Error: %s\n", error->text);
    printf("Source: %s\n", error->source);
    printf("Line: %d, Column: %d\n", error->line, error->column);
}

/* Load/prepare configuration file with data set by the server admin. It uses a global
 configuration and it's bad, but at least it should never be modified. */
int load_config() {
    server_config = (patch_config*) malloc(sizeof(patch_config));
    memset(server_config, 0, sizeof(patch_config));

    // Provide a default value so that if the user doesn't specify it we aren't hosed.
    server_config->enable_ipv6 = false;

    json_error_t error;
    json_t *cfg_file = json_load_file(CFG_NAME, JSON_DECODE_ANY, &error);

    if (!cfg_file) {
        // Look in LOCAL_DIR in case the files were placed there instead.
        char config_dir[128];
        strncat(config_dir, LOCAL_DIR, strlen(LOCAL_DIR));
        strncat(config_dir, CFG_NAME, strlen(CFG_NAME));

        cfg_file = json_load_file(config_dir, JSON_DECODE_ANY, &error);

        if (!cfg_file) {
            printf("Failed to load configuration file.\n");
            json_error(&error);
            return -1;
        }
    }

    // Unpack the JSON config file into the corresponding server config entries.
    int result = json_unpack_ex(cfg_file, &error, JSON_STRICT,
            "{s:s, s:s, s:s, s:s, s?b, s:s}",
            "patch_ip", &(server_config->serverIPStr),
            "patch_port", &(server_config->patch_port),
            "data_port", &(server_config->data_port),
            "patch_dir", &(server_config->patch_directory),
            "enable_ipv6", &(server_config->enable_ipv6),
            "welcome_message", &(server_config->welcome_message));
    if (result == -1) {
        json_error(&error);
        return -1;
    }

    server_config->serverIP = inet_addr(server_config->serverIPStr);

    // The Welcome Message sent in PATCH_WELCOME_MESSAGE is expected to be encoded
    // as UTF-16 little endian, so it needs to be converted.
    iconv_t conv = iconv_open("UTF-16LE", "UTF-8");
    if (conv == (iconv_t)-1) {
        perror("load_config:iconv_open");
        exit(1);
    }

    char *inbuf = server_config->welcome_message;
    size_t inbytes = (size_t) strlen(server_config->welcome_message);
    size_t outbytes = inbytes * 2, avail = outbytes;
    char *outbuf = (char*) malloc(outbytes), *outptr = outbuf;
    memset(outbuf, 0, outbytes);

    if (iconv(conv, &inbuf, &inbytes, &outptr, &avail) == (size_t)-1) {
        perror("load_config:iconv");
        exit(1);
    }
    iconv_close(conv);

    server_config->welcome_message = outbuf;
    server_config->welcome_size = outbytes;

    return 0;
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

    if ((status = getaddrinfo(server_config->serverIPStr, port, hints, &server)) != 0) {
        printf("getaddrinfo(): %s\n", gai_strerror(status));
        printf("Press any key to exit.\n");
        gets(&c);
        exit(1);
    }

    if ((sockfd = socket(server->ai_family, server->ai_socktype, server->ai_protocol)) == -1) {
        printf("socket(): ");
        printf("Press any key to exit.\n");
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

int main(int argc, const char * argv[]) {

    if (load_config() == -1)
        exit(1);

    addrinfo hints;
    hints.ai_flags = AI_NUMERICHOST;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    printf("Opening PATCH socket on port %s...", server_config->patch_port);
    int patch_sockfd = create_socket(server_config->patch_port, &hints);
    printf("OK\nOpening DATA socket on port %s...", server_config->data_port);
    int data_sockfd = create_socket(server_config->data_port, &hints);
    printf("OK\n");
    
    handle_connections(patch_sockfd, data_sockfd);

    free(server_config);

    return 0;
}

