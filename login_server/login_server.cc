#include <iostream>
#include <list>
#include <random>
#include <cstdlib>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

#include "login_server.h"
#include "packets.h"

extern "C" {
    #include <jansson.h>
    #include "sniffex.h"
    #include "md5.h"
}

#define DEBUG_OUTPUT
#define MAX_SIMULTANEOUS_CONNECTIONS 1

const int BACKLOG = 10;
const char *CFG_NAME = "login_config.json";
const char *LOCAL_DIR = "/usr/local/share/tethealla/config/";

uint32_t normalName = 0xFFFFFFFF;
uint32_t globalName = 0xFF1D94F7;
uint32_t localName = 0xFFB0C4DE;

mysql_config db_config;
login_config server_config;

std::list<login_client*> clients;
std::list<ship_server*> ships;

std::mt19937 rand_gen(time(NULL));
std::uniform_int_distribution<uint8_t> dist(0, 255);

unsigned mob_rate[8]; // rare appearance rate

void MDString (char *inString, char *outString);
int send_packet(login_client *client, int len);

/* Send the welcome packet to the client when they connect to the login server.*/
int send_bb_login_welcome(login_client* client, uint8_t s_seed[48], uint8_t c_seed[48]) {
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

int character_process_packet(login_client* client) {
    return 0;
}

/* Process a client packet sent to the LOGIN server. Returns 0 on success, 1
 * on error and -1 if the handler received an unrecognized packet type.
 */
int login_process_packet(login_client* client) {
    bb_packet_header* header = (bb_packet_header*) client->recv_buffer;
    header->type = LE16(header->type);
    header->length = LE16(header->length);
    
    int result = 0;
    switch (header->type) {
        case BB_LOGIN_DISCONNECT:
            client->todc = true;
            result = 0;
            break;
        case BB_LOGIN_LOGIN:
            //result = handle_login(client);
            break;
        default:
            result = -1;
            break;
    }
    return result;
}

/* Send the amount of data specified by len from the client's buffered to the client.
 * Returns -1 on error and 0 on success.
 */
int send_packet(login_client *client, int len) {
    int total = 0, remaining = len;
    int bytes_sent;
    
    while (total < len) {
        bytes_sent = send(client->socket, client->send_buffer + total, remaining, 0);
        if (bytes_sent == -1) {
            perror("send");
            return -1;
        }
        total += bytes_sent;
        remaining -= bytes_sent;
    }

    memmove(client->send_buffer, client->send_buffer + total, total);
    client->send_size -= total;
    
    return 0;
}

/* Read in whatever a client is trying to send us and store it in their
 * respective receiving buffer and pass it along to the packet handler for
 * a response. Returns 0 on successful read, -1 on error, or 1 if the client
 * closed the connection.
 */
int receive_from_client(login_client *client) {
    bb_packet_header *header;
    ssize_t bytes = 0;
    
    if (client->recv_size < BB_HEADER_LEN) {
        // Start by reading in the packet's header.
        bytes = recv(client->socket, client->recv_buffer,
                     BB_HEADER_LEN - client->recv_size, 0);
        client->recv_size += (int) bytes;
        if (bytes == -1)
            perror("recv");
        
        if (bytes <= 0)
            // Disconnect on error or if the client explicitly closed the connection.
            return (bytes == -1) ? -1 : 1;
        if (client->recv_size < BB_HEADER_LEN)
            // Wait for the client to send us more data since we don't have a header yet.
            return 0;
    }
    
    if (!client->packet_sz) {
        // Decrypt our header since we have all of it by now.
        CRYPT_CryptData(&client->client_cipher, client->recv_buffer, BB_HEADER_LEN, 0);
        header = (bb_packet_header*) client->recv_buffer;
        client->packet_sz = header->length;
        
        // Skip ahead if all we got is an 8 byte header.
        if (client->packet_sz == BB_HEADER_LEN)
            goto handle;
    }
    
    // Receive the rest of the packet (or as much as the client was able to send us).
    bytes = recv(client->socket, client->recv_buffer + client->recv_size, client->packet_sz - client->recv_size, 0);
    client->recv_size += bytes;
    
    if (bytes == -1)
        perror("recv");
    if (bytes <= 0)
        return (bytes == -1) ? -1 : 1;
    
    if (client->recv_size < client->packet_sz)
        // Wait until we get the rest of the packet.
        return 0;
    
    // By now we've received the whole packet.
    CRYPT_CryptData(&client->client_cipher, client->recv_buffer + BB_HEADER_LEN, client->packet_sz - BB_HEADER_LEN, 0);
    
handle:
    
#ifdef DEBUGGING
    printf("Received %lu bytes from %s\n", bytes + BB_HEADER_LEN, client->IP_address);
    print_payload(client->recv_buffer, int(bytes));
    printf("\n");
#endif
    
    int result = 0;
    if (client->session == LOGIN)
        result = login_process_packet(client);
    else
        result = character_process_packet(client);
    
    // Move the packet out of the recv buffer and reduce the currently received size.
    client->recv_size -= client->packet_sz;
    memmove(client->recv_buffer, client->recv_buffer + client->packet_sz, client->packet_sz);
    client->packet_sz = 0;
    
    if (result)
        return -1;
    else
        return 0;
}

/* Ensure that a client has not connected more than MAX_SIMULTANEOUS_CONNECTIONS times.
 * If they have, mark the oldest connection as being ready to disconnect.
 */
void limit_connections(login_client* connect) {
	unsigned numConnections = 0, c4;
	login_client *c5;
    std::list<login_client*>::const_iterator c, c_end;
    
    // Tally up the number of connections from a particular IP address.
    for (c = clients.begin(), c_end = clients.end(); c != c_end; ++c) {
        if ((!strcmp((const char*)(*c)->IP_address, (const char*)connect->IP_address)))
            numConnections++;
    }
    
    // Delete the oldest connection to the server if there are more than
    // MAX_SIMULTANEOUS_CONNECTIONS connections from any one IP address.
	if (numConnections > MAX_SIMULTANEOUS_CONNECTIONS) {
		c4 = 0xFFFFFFFF;
		c5 = NULL;
        for (c = clients.begin(), c_end = clients.end(); c != c_end; ++c) {
            if ((!strcmp((const char*)(*c)->IP_address, (const char*)connect->IP_address)))
                if ((*c)->connected < c4) {
                    c4 = (*c)->connected;
                    c5 = (*c);
                }
        }
        
        if (c5)
            c5->todc = true;
	}
}

/* Free all memory associated with a client structure. */
void destroy_client(login_client* client) {
    
}

/* Allocates and initializes a new client structure for a connection. Also
 * responsible for sending the initial welcome packet with the encryption information.
 * Returns a pointer to the new client struct if successful, otherwise returns NULL
 * if any errors were encountered (including failing to send the welcome packet).
 */
login_client* accept_client(int sockfd, server_session stype) {
    sockaddr_storage clientaddr;
    socklen_t addrsize = sizeof clientaddr;
    
    int clientfd;
    if ((clientfd = accept(sockfd, (struct sockaddr*) &clientaddr, &addrsize)) == -1) {
        perror("accept_client");
        return NULL;
    }
    
    login_client* client = (login_client*) malloc(sizeof(login_client));
    if (!client) {
        perror("malloc");
        return NULL;
    }
    memset(client, 0, sizeof(login_client));
    
    client->socket = clientfd;
    client->session = stype;
    client->send_size = 0;
    
    memset(client->recv_buffer, 0, TCP_BUFFER_SIZE);
    memset(client->send_buffer, 0, TCP_BUFFER_SIZE);
    
    if (clientaddr.ss_family == AF_INET) {
        sockaddr_in* ip = ((sockaddr_in*)&clientaddr);
        client->port = ip->sin_port;
        
        memcpy(client->IP_address, inet_ntoa(ip->sin_addr), 16);
        //inet_ntop(AF_INET, &(ip->sin_addr), client->ip_addr_str, INET_ADDRSTRLEN);
    }
    /* TODO: IPv6 support
     else {
     sockaddr_in6* ip = ((sockaddr_in6*)&clientaddr);
     client->port = ip->sin6_port;
     client->ipv6 = true;
     
     client->ip_addr_str = (char*) malloc(INET6_ADDRSTRLEN);
     inet_ntop(AF_INET6, &(ip->sin6_addr), client->ip_addr_str, INET6_ADDRSTRLEN);
     }
     */
    
    // Initialize our encryption keys.
    uint8_t server_seed[48], client_seed[48];
    for (int i = 0; i < 48; i++) {
        server_seed[i] = dist(rand_gen);
        client_seed[i] = dist(rand_gen);
    }
    CRYPT_CreateKeys(&client->server_cipher, server_seed, CRYPT_BLUEBURST);
    CRYPT_CreateKeys(&client->client_cipher, client_seed, CRYPT_BLUEBURST);
    
    if (send_bb_login_welcome(client, server_seed, client_seed))
        return NULL;
    
    limit_connections(client);
    
    client->connected = (unsigned) time(NULL);
	//client->sendCheck[SEND_PACKET_03] = 1;
    
    clients.push_back(client);
    return client;
}

inline int max(int a, int b) {
    return a > b ? a : b;
}

/* Main connection handling loop. Responsible for handling inbound requests/connections
 * and for coordinating when to send/receive data from clients and ships.
 */
void handle_connections(int loginfd, int charfd, int shipfd) {
    int select_result = 0, fd_max = 0;
    time_t servertime;
    //uint16_t ch2;
    fd_set readfds, writefds, exceptfds;
    timeval timeout = { .tv_sec = 10 };
    
    std::list<login_client*>::const_iterator c, c_end;
    std::list<ship_server*>::const_iterator s, s_end;
    
    while (1) {
        servertime = time(NULL);
        
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        FD_ZERO(&exceptfds);
        
        // Add our clients to the apropriate fd sets.
        for (c = clients.begin(), c_end = clients.end(); c != c_end; ++c) {
            
            // TODO: Figure out what this is for.
            /*
            if ((*c)->lastTick != (unsigned) servertime) {
                if ((*c)->lastTick > (unsigned) servertime)
                    ch2 = 1;
                else
                    ch2 = 1 + ((unsigned) servertime - (*c)->lastTick);
                (*c)->lastTick = (unsigned) servertime;
                (*c)->packetsSec /= ch2;
                (*c)->toBytesSec /= ch2;
                (*c)->fromBytesSec /= ch2;
            }
            */
            
            FD_SET((*c)->socket, &readfds);
            FD_SET((*c)->socket, &exceptfds);
            
            // Only add the client to writefds if we have something to send.
            if ((*c)->send_size > 0)
                FD_SET((*c)->socket, &writefds);
            
            fd_max = max(fd_max, (*c)->socket);
        }
        
        // Add our ships to the apropriate fd sets.
        for (s = ships.begin(), s_end = ships.end(); s != s_end; ++c) {
            // Send a ping request to the ship when 30 seconds passes...
            if (((unsigned) servertime - (*s)->last_ping >= 30) && ((*s)->sent_ping == 0)) {
                (*s)->sent_ping = true;
                //ShipSend11 (workShip);
            }
            
            // If it's been over a minute since we've heard from a ship, terminate
            // the connection with it.
            if ((unsigned) servertime - (*s)->last_ping > 60) {
                printf ("%s ship ping timeout.\n", (*s)->name );
                // TODO: Kill the ship
                continue;
            }
            
            // Limit time of authorization to 60 seconds...
            if ((!(*s)->authenticated && ((unsigned) servertime - (*s)->connected >= 60))) {
                (*s)->todc = false;
            }

            
            FD_SET((*s)->socket, &readfds);
            FD_SET((*s)->socket, &exceptfds);
            // TODO: Rewrite once packing sending functions are implemented.
            if ((*s)->send_size > 0)
                FD_SET((*s)->socket, &writefds);
            
            fd_max = max(fd_max, (*s)->socket);
        }
        
        FD_SET(loginfd, &readfds);
        fd_max = max(fd_max, loginfd);
        FD_SET(charfd, &readfds);
        fd_max = max(fd_max, charfd);
        FD_SET(shipfd, &readfds);
        fd_max = max(fd_max, shipfd);
        
        if ((select_result = select(fd_max + 1, &readfds, &writefds, &exceptfds, &timeout)) > 0) {
            // Check our always-listening sockets first.
            if (FD_ISSET(loginfd, &readfds)) {
                login_client* client = accept_client(loginfd, LOGIN);
                if (client)
                    printf("Accepted LOGIN connection from %s:%d\n", client->IP_address, client->port);
            }
            
            if (FD_ISSET(charfd, &readfds)) {
                login_client* client = accept_client(charfd, CHARACTER);
                if (client)
                    printf("Accepted CHARACTER connection from %s:%d\n", client->IP_address, client->port);
            }
            
            if (FD_ISSET(shipfd, &readfds)) {
                // TODO: Create new ship connection and start encryption.
                /*
                 if ( ( workShip->shipSockfd = tcp_accept ( ship_sockfd, (struct sockaddr*) &listen_in, listen_length ) ) >= 0 ) {
                 workShip->connection_index = ch;
                 serverShipList[serverNumShips++] = ch;
                 printf ("Accepted SHIP connection from %s:%u\n", inet_ntoa (listen_in.sin_addr), listen_in.sin_port );
                 *(unsigned *) &workShip->listenedAddr[0] = *(unsigned*) &listen_in.sin_addr;
                 workShip->connected = workShip->last_ping = (unsigned) servertime;
                 ShipSend00 (workShip);
                 }
                 */
            }
            
            // Check our connected clients for activity.
            for (c = clients.begin(), c_end = clients.end(); c != c_end; ++c) {
                if (FD_ISSET((*c)->socket, &readfds)) {
                    if (receive_from_client((*c)))
                        (*c)->todc = true;
                }
                
                if (FD_ISSET((*c)->socket, &writefds)) {
                    // TODO: Send whatever data we have to the client.
                    
                }
                
                if (FD_ISSET((*c)->socket, &exceptfds))
                    (*c)->todc = true;
                
                if ((*c)->todc) {
                    // TODO: Send whatever remaining data we have to the client.
                    close((*c)->socket);
                    clients.erase(c++);
                    destroy_client(*c);
                }
            }
            
            // Check our connected ships.
            for (s = ships.begin(), s_end = ships.end(); s != s_end; ++c) {
                if (FD_ISSET((*s)->socket, &readfds)) {
                    // TODO: Read data from the ship.
                    
                    /* Code from original
                     if ( ( pkt_len = recv (workShip->shipSockfd, &tmprcv[0], PACKET_BUFFER_SIZE - 1, 0) ) <= 0 )
                     {
                     printf ("Lost connection with the %s ship...\n", workShip->name );
                     initialize_ship (workShip);
                     }
                     else
                     {
                     // Work with it.
                     for (pkt_c=0;pkt_c<pkt_len;pkt_c++)
                     {
                     workShip->rcvbuf[workShip->rcvread++] = tmprcv[pkt_c];
                     
                     if (workShip->rcvread == 4)
                     {
                     // Read out how much data we're expecting this packet.
                     workShip->expect = *(unsigned*) &workShip->rcvbuf[0];
                     
                     if ( workShip->expect > TCP_BUFFER_SIZE )
                     {
                     printf ("Lost connection with the %s ship...\n", workShip->name );
                     initialize_ship ( workShip ); // This shouldn't happen, lol.
                     }
                     }
                     
                     if ( ( workShip->rcvread == workShip->expect ) && ( workShip->expect != 0 ) )
                     {
                     decompressShipPacket ( workShip, &workShip->decryptbuf[0], &workShip->rcvbuf[0] );
                     
                     workShip->expect = *(unsigned *) &workShip->decryptbuf[0];
                     
                     if ( workShip->packetdata + workShip->expect < PACKET_BUFFER_SIZE )
                     {
                     memcpy ( &workShip->packet[workShip->packetdata], &workShip->decryptbuf[0], workShip->expect );
                     workShip->packetdata += workShip->expect;
                     }
                     else
                     {
                     initialize_ship ( workShip );
                     break;
                     }
                     workShip->rcvread = 0;
                     }
                     }
                     }
                     */
                    
                    /* TODO: Place in ship handler.
                     if (workShip->packetdata) {
                     ship_this_packet = *(unsigned *)&workShip->packet[workShip->packetread];
                     memcpy (&workShip->decryptbuf[0], &workShip->packet[workShip->packetread], ship_this_packet);
                     
                     ShipProcessPacket (workShip);
                     
                     workShip->packetread += ship_this_packet;
                     
                     if (workShip->packetread == workShip->packetdata)
                     workShip->packetread = workShip->packetdata = 0;
                     }
                     */
                    
                }
                
                if (FD_ISSET((*s)->socket, &writefds)) {
                    // TODO: Send data to the ship.
                    /*
                     // Write shit.
                     
                     bytes_sent = send (workShip->shipSockfd, &workShip->sndbuf[workShip->sndwritten],
                     workShip->snddata - workShip->sndwritten, 0);
                     if (bytes_sent == -1)
                     {
                     printf ("Lost connection with the %s ship...\n", workShip->name );
                     initialize_ship (workShip);
                     }
                     else
                     workShip->sndwritten += bytes_sent;
                     
                     if (workShip->sndwritten == workShip->snddata)
                     workShip->sndwritten = workShip->snddata = 0;
                     */
                }
                
                if (FD_ISSET((*s)->socket, &exceptfds)) {
                    // TODO: Remove the ship
                }
                
                /*
                 if (workShip->todc)
                 {
                 if ( workShip->snddata - workShip->sndwritten )
                 send (workShip->shipSockfd, &workShip->sndbuf[workShip->sndwritten],
                 workShip->snddata - workShip->sndwritten, 0);
                 printf ("Terminated connection with ship...\n" );
                 initialize_ship (workShip);
                 }
                 */
            }
            
        } else if (select_result == -1) {
            perror("select");
            exit(1);
        } else {
            // Timed out
        }
    }
}

/* Create and open a server socket to start listening on a particular port.
 * port: Port on which to listen.
 * hints: Populated struct for getaddrinfo.
 */
int create_socket(const char* port, const addrinfo *hints) {
    char c;
    int status = 0, sockfd;
    addrinfo *server;
    
    if ((status = getaddrinfo(server_config.server_ip, port, hints, &server)) != 0) {
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

/* Writes the contents of a JSON error to stdout.*/
void json_error(json_error_t* error) {
    printf("Error: %s\n", error->text);
    printf("Source: %s\n", error->source);
    printf("Line: %d, Column: %d\n", error->line, error->column);
}

/* Read the server configuration from login_config and populate the db_config and
 * server_config structures with their contents.
 */
int load_config() {
    json_error_t error;
    json_t *cfg_file = json_load_file(CFG_NAME, JSON_DECODE_ANY, &error);
    
    if (!cfg_file) {
        // Look in LOCAL_DIR in case the files were placed there instead.
        char config_dir[128];
        sprintf(config_dir, "%s%s", LOCAL_DIR, CFG_NAME);
        
        printf("ERROR.\nLoading config file in %s...", config_dir);
        cfg_file = json_load_file(config_dir, JSON_DECODE_ANY, &error);
        
        if (!cfg_file) {
            printf("Failed to load configuration file.\n");
            json_error(&error);
            return -1;
        }
    }
    char *global_color, *local_color, *normal_color;
    char config_dir[1024];
    int result = json_unpack_ex(cfg_file, &error, JSON_STRICT,
            "{s:{s:s, s:s, s:s, s:i, s:s}, s:s, s:i, s:i, s:s, s:s, s:i, s:i, "
            "s:{s:i, s:i, s:i, s:i, s:i, s:i, s:i, s:i}, s:s, s:s, s:s}",
            "mysql",
            "username", &db_config.username,
            "password", &db_config.password,
            "host", &db_config.host,
            "port", &db_config.port,
            "database", &db_config.database,
            "server_ip", &server_config.server_ip,
            "login_port", &server_config.login_port,
            "ship_port", &server_config.ship_port,
            "welcome_message", &server_config.welcome_message[0],
            "config_dir", &config_dir,
            "max_clients", &server_config.serverMaxConnections,
            "max_ships" , &server_config.serverMaxShips,
            "rare_appearance_rates",
            "hildebear", &mob_rate[0],
            "rappy", &mob_rate[1],
            "lilly", &mob_rate[2],
            "slime", &mob_rate[3],
            "merissa", &mob_rate[4],
            "panzuzu", &mob_rate[5],
            "dorphon_eclair", &mob_rate[6],
            "kondrieu", &mob_rate[7],
            "global_gm_color", &global_color,
            "local_gm_color", &local_color,
            "normal_color", &normal_color
            );
    if (result == -1) {
        json_error(&error);
        return -1;
    }
    
    inet_pton(AF_INET, server_config.server_ip, server_config.serverIPN);
    globalName = atoi(global_color);
    localName = atoi(global_color);
    normalName = atoi(normal_color);
    
    server_config.config_dir = (char*) malloc(strlen(config_dir) + 1);
    strcpy(server_config.config_dir, config_dir);
    
    return 0;
}

void print_programinfo() {
    printf("\nTethealla Login Server version 0.048 Copyright (C) 2008  Terry Chatman Jr.\n");
    printf("Modified version Copyright (C) 2014 Andrew Rodman.\n");
	printf("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n");
	printf("This program comes with ABSOLUTELY NO WARRANTY; for details\n");
	printf("see section 15 in gpl-3.0.txt\n");
    printf("This is free software, and you are welcome to redistribute it\n");
    printf("under certain conditions; see gpl-3.0.txt for details.\n");
	printf("\n\n");
}

int main(int argc, const char * argv[]) {
    print_programinfo();
    
    printf("Loading configuration file %s...", CFG_NAME);
    load_config();
    printf("OK\n");
    
    char start_dir[512];
    getcwd(start_dir, 512);
    chdir(server_config.config_dir);
    
    // TODO: Load player starting stats
    // TODO: Packet E2 config?
    // TODO: Packet E7 config?
    // TODO: Packet EB
    // TODO: Quest item allowances
    
    chdir(start_dir);
    
#ifdef DEBUG_OUTPUT
	printf ("\n---MySQL connection parameters---\n");
	printf ("Host: %s\n", db_config.host );
	printf ("Port: %u\n", db_config.port );
	printf ("Username: %s\n", db_config.username );
	printf ("Password: %s\n", db_config.password );
	printf ("Database: %s\n", db_config.database );
#endif
    
    // TODO: Packet A0 (default ship list)
    
    printf ("\nConnecting to the MySQL database ...");
    if ((db_config.myData = mysql_init(NULL)) == NULL){
        printf("mysql error: %s\n", mysql_error(db_config.myData));
        return 1;
    }
    
    if ((mysql_real_connect(db_config.myData, db_config.host, db_config.username,
            db_config.password, db_config.database, db_config.port, NULL, 0)) == NULL) {
        printf("mysql connection error: %s\n", mysql_error(db_config.myData));
        return 1;
    }
    printf ("OK\n");

    printf ("\n---Login server parameters---\n");
	printf ("IP: %s\n",  server_config.server_ip);
	printf ("Login Port: %u\n", server_config.login_port );
	printf ("Character Port: %u\n", server_config.login_port+1 );
	printf ("Maximum Connections: %u\n", server_config.serverMaxConnections );
	printf ("Maximum Ships: %u\n\n", server_config.serverMaxShips );
    
    /* Open our login, character, and ship transfer server ports. */
    int login_sockfd, character_sockfd, ship_sockfd;
    char port[5], dp[1];
    addrinfo hints;
    hints.ai_flags = AI_NUMERICHOST;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    
    sprintf(port, "%d", server_config.login_port);
    printf ("Opening server login port %s for connections...", port);
	login_sockfd = create_socket(port, &hints);
    printf("OK\n");
    
    sprintf(port, "%d", server_config.login_port + 1);
    printf ("Opening server character port %s for connections...", port);
    character_sockfd = create_socket(port, &hints);
    printf("OK\n");
    
    sprintf(port, "%d", server_config.ship_port);
    printf ("Opening ship port %s for connections...", port);
    ship_sockfd = create_socket(port, &hints);
    printf("OK\n");
    
	if ((login_sockfd<0) || (character_sockfd<0) || (ship_sockfd<0))
	{
		printf ("Failed to open ports for connections.\n");
		printf ("Hit [ENTER]");
		gets (&dp[0]);
        mysql_close(db_config.myData);
		exit (1);
	}
    
    printf("\nListening for client connections...\n\n");
    handle_connections(login_sockfd, character_sockfd, ship_sockfd);

    printf("\nClosing resources and shutting down server...\n");
    
    close(login_sockfd);
    close(character_sockfd);
    close(ship_sockfd);
    mysql_close(db_config.myData);
}

void MDString (char *inString, char *outString) {
    unsigned char c;
    MD5_CTX mdContext;
    unsigned int len = strlen (inString);

    MD5Init (&mdContext);
    MD5Update (&mdContext, (unsigned char*)inString, len);
    MD5Final (&mdContext);
    for (c=0;c<16;c++) {
        *outString = mdContext.digest[c];
        outString++;
    }
}
