#ifndef __tehealla_login_server_h__
#define __tehealla_login_server_h__

#define TCP_BUFFER_SIZE 64000
#define PACKET_BUFFER_SIZE ( TCP_BUFFER_SIZE * 16 )

#include <mysql.h>

extern "C" {
    #include "encryption.h"
}

struct login_config {
    unsigned char serverIPN[4]; // network-presentation of the IP
    char* server_ip;
    uint32_t server_ip_netp;
    uint16_t login_port;
    uint16_t character_port;
    uint16_t ship_port;
    char *config_dir;
    
    unsigned short serverMaxConnections;
    unsigned short serverMaxShips;
    unsigned serverNumConnections = 0;
    unsigned serverNumShips = 0;
    unsigned quest_numallows;
    unsigned* quest_allow;
    unsigned max_ship_keys = 0;
    char *welcome_message;
};

struct mysql_config {
    char *host;
    char *username;
    char *password;
    char *database;
    uint16_t port;
    MYSQL* myData;
};

enum server_session {
    LOGIN, CHARACTER
};

enum log_type {
    ERROR, WARNING, INFO
};

struct login_client {
    int socket;
    server_session session;
    unsigned char IP_address[16];
    int port;
    
    uint32_t guildcard;
    uint32_t team_id;
    bool is_gm;
    char hardware_info[18];
    
    CRYPT_SETUP client_cipher, server_cipher;
    
    unsigned char send_buffer[TCP_BUFFER_SIZE];
    unsigned int send_size;
    unsigned char recv_buffer[TCP_BUFFER_SIZE];
    unsigned int recv_size;
    unsigned int packet_sz;
    
    unsigned int connected;
    bool todc;
};

struct ship_server {
    int socket;
    unsigned char name[13];
    bool authenticated;
    
    unsigned char send_buffer[TCP_BUFFER_SIZE];
    unsigned int send_size;
    
    unsigned char recv_buffer[TCP_BUFFER_SIZE];
    unsigned int recv_size;
    unsigned int packet_sz;
    
    bool sent_ping;
    unsigned int last_ping;
    unsigned int connected;
    bool todc;
};

#endif