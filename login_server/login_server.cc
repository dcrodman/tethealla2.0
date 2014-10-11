#include <iostream>
#include <fstream>
#include <list>
#include <random>

#include <cassert>
#include <cstdlib>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h>
#include <unistd.h>

#include <iconv.h>

#include "login_server.h"
#include "packets.h"

extern "C" {
    #include <polarssl/sha256.h>
    #include <jansson.h>
    #include "sniffex.h"
}

#define DEBUG_OUTPUT
#define DEV_MODE
#define MAX_SIMULTANEOUS_CONNECTIONS 1

const int BACKLOG = 10;
const char *CFG_NAME = "login_config.json";
const char *LOCAL_DIR = "/usr/local/share/tethealla/config/";

const char *PSO_CLIENT_VER_STRING = "TethVer12510";
const int PSO_CLIENT_VER = 0x41;

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

int send_packet(login_client *client, int len);

/* Generates a timestamp of the current time in the form yyyy-dd-mm 00:00:00 AM/PM and
 * writes it to buffer. Intended for use with logging, not for any packet data.
 */
void timestamp(char *buffer, int len) {
    time_t rawtime;
    time(&rawtime);
    struct tm *tminfo = localtime(&rawtime);
    strftime(buffer, len, "%F %r", tminfo);
}

/* Write an entry to the specified log file. If the directory does not exist, it
 * will be created and the necessary files created. All in all not the cheapest
 * operation, but important if we're seeing MySQL errors.
 */
void log_mysql(log_type severity, const char *message) {
    static bool dir_exists = false;
    if (!dir_exists) {
        if (mkdir("log", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)) {
            if (errno != EEXIST) {
                printf("\n!!!WARNING!!!: Unable to create log directory.\n");
                perror("mkdir");
                return;
            }
        }
        dir_exists = true;
    }

    std::fstream mysql_log("log/mysql.log", std::ios::app);
    if (mysql_log.is_open()) {
        char timebuf[50];
        timestamp(timebuf, 50);

        log_type severity = ERROR;
        mysql_log << timebuf;
        if (severity == ERROR)
            mysql_log << " (ERROR) ";
        else if (severity == WARNING)
            mysql_log << " (WARNING) ";
        else
            mysql_log << " (INFO) ";
        mysql_log << "MySQL: Testing" << "\n";
        mysql_log.close();
    } else {
        printf("\n!!!WARNING!!!: Unable to create or open mysql.log.\n");
    }
}

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

/* Sends the packet that will display a large message box to the user. Intended
* to be sent before disconnecting a client in the case of some errors. Note that
* adding a period as the last character seems to make the client render some
* strange character, so either leave it off or include a space after it.
*/
bool send_bb_client_message(login_client* client, const char* message) {
    bb_client_msg_pkt *pkt = (bb_client_msg_pkt*) (client->send_buffer + client->send_size);
    memset(pkt, 0, sizeof(&pkt));
    pkt->header.type = LE16(BB_CLIENT_MSG);
    pkt->language_code = 0x00450009;

    // The message itself is expected to be encoded as UTF-16 little endian, so it needs to be converted.
    iconv_t conv = iconv_open("UTF-16LE", "UTF-8");
    if (conv == (iconv_t)-1) {
        perror("load_config:iconv_open");
        exit(1);
    }
    int message_len = strlen(message);
    char *inbuf = (char*) malloc(message_len), *inptr = inbuf;
    strcpy(inbuf, message);

    size_t inbytes = (size_t) message_len;
    size_t outbytes = inbytes * 2, avail = outbytes;
    char *outptr = pkt->message;
    memset(pkt->message, 0, outbytes);
    
    if (iconv(conv, &inptr, &inbytes, &outptr, &avail) == (size_t)-1) {
        perror("send_bb_client_message:iconv");
        exit(1);
    }
    iconv_close(conv);
    free(inbuf);
    
    // Pad the packet until its length is divisible by 8.
    int pkt_len = 0x0C + (outbytes - avail);
    while (pkt_len % 8) {
        client->send_buffer[pkt_len++] = 0x00;
    }

    pkt->header.length = LE16(pkt_len);
    client->send_size += pkt_len;

    printf("Sending BB Client Message\n");
    print_payload((u_char*)pkt, pkt_len);
    printf("\n");
    
    CRYPT_CryptData(&client->server_cipher, pkt, pkt_len, 1);
    int result = send_packet(client, pkt_len);
    return result;
}

/* Sends security data to the client. Note that the client's guildcard and team_id must be set
 * and error must be one of the constants from packets.h (or otherwise in the
 * range of 0x00-0x0B) or the packet will cause an error in the client. Security
 * is expected to be 8 randomly generated bytes and should be stores as the client's
 * security data in the db.
 */
bool send_bb_security(login_client* client, uint8_t security[8], uint32_t error) {
    bb_security_pkt* pkt = (bb_security_pkt*) client->send_buffer + client->send_size;
    memset(pkt, 0, BB_SECURITY_SZ);
    pkt->header.type = LE16(BB_SECURITY_TYPE);
    pkt->header.length = LE16(BB_SECURITY_SZ);

    pkt->error_code = error;
    pkt->player_tag = 0x00010000;
    pkt->team_id = client->team_id;
    pkt->guild_card = client->guildcard;
    pkt->capabilities = 0x00000101;
    
    /*
    static uint8_t fixed[] = { 0x38, 0x3F, 0x71, 0x8D, 0x34, 0x37, 0x7A, 0xBD,
        0x67, 0x39, 0x65, 0x6B, 0x2C, 0xB1, 0xA5, 0x7C, 0x17, 0x93, 0x93, 0x29,
        0x4A, 0x90, 0xE9, 0x11, 0xB8, 0xB5, 0x0E, 0x77, 0x41, 0x30, 0x9B, 0x88 };
    memcpy(pkt->security_data, fixed, 32);
     */
    static uint8_t fixed[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    memcpy(pkt->security_data, fixed, 4);
    
    if (security) {
        memcpy(pkt->security_data + 32, security, 8);
    }

    printf("Sending BB Security Info\n");
    print_payload((unsigned char*)pkt, BB_SECURITY_SZ);
    printf("\n");

    client->send_size += BB_SECURITY_SZ;
    
    CRYPT_CryptData(&client->server_cipher, pkt, BB_SECURITY_SZ, 1);
    return send_packet(client, BB_SECURITY_SZ);
}

/* Sends the redirect packet from the login server to indicate the IP
 * and port number of the character server.
 */
bool send_bb_redirect(login_client* client, uint32_t ip, uint16_t port) {
    bb_redirect_pkt *pkt = (bb_redirect_pkt*) client->send_buffer + client->send_size;
    memset(pkt, 0, BB_REDIRECT_SZ);
    pkt->header.type = LE16(BB_REDIRECT_TYPE);
    pkt->header.length = LE16(BB_REDIRECT_SZ);

    pkt->ip_addr = ip;
    pkt->port = LE16(port);
    client->send_size += BB_REDIRECT_SZ;

    printf("Sending BB Redirect\n");
    print_payload((u_char*) pkt, BB_REDIRECT_SZ);
    printf("\n");

    CRYPT_CryptData(&client->server_cipher, pkt, BB_REDIRECT_SZ, 1);
    return send_packet(client, BB_REDIRECT_SZ);
}

/* Packet sent between ships to tell the other ships that this user logged on and
 * to disconnect him/her if they're still active.
 */
bool send_ship_disconnect_client (unsigned gcn, ship_server* ship) {
    /*
	ship->encryptbuf[0x00] = 0x08;
	ship->encryptbuf[0x01] = 0x00;
	*(unsigned *) &ship->encryptbuf[0x02] = gcn;
	compressShipPacket ( ship, &ship->encryptbuf[0x00], 0x06 );
    */

    // TODO: Send this to all connected ships.
    assert(false);
}

/* Computes the SHA256 hash of the password and stores it in buffer, which must
 * have a length of at least 64. The output format is a hex string instead of raw bytes.
 * There's probably a better way to do this, but I couldn't find one and just came up
 * with a quick and dirty method.
 */
void sha_password(char *buffer, const char* password) {
    u_char sha_password[32];
    sha256((u_char*) password, strlen(password), sha_password, 0);
    // Expand the characters from two per byte to one per byte in order to properly
    // extract all 64.
    for (int i = 0, j = 0; i < 32; i++, j += 2) {
        sprintf(&buffer[j], "%1x", (sha_password[i] & 0xF0) >> 4);
        sprintf(&buffer[j + 1], "%1x", sha_password[i] & 0x0F);
    }
}

/* Handle account verification steps common to both login and character servers.
 * Returns 0 on success, -1 for MySQL error and 1 for account-related error (failure
 * to log the player in). Will send the appropriate message and security packets if
 * one of these errors occurs.
 */
int verify_account(login_client *client, bb_login_pkt *pkt) {
    char query[1024] = {0};
    MYSQL_ROW result_row;
    MYSQL_RES* result;
    char hwinfo[18] = {0};
    char password_hash[64], username[17] = {0};
    
    mysql_real_escape_string(db_config.myData, (char*) hwinfo, (const char*) pkt->hardware_info, 8);
    mysql_real_escape_string(db_config.myData, username, pkt->username, strlen(pkt->username));
    sprintf(query, "select * from account_data WHERE username ='%s'", username);
    
    if (mysql_query(db_config.myData, query)) {
        return -1;
    }
    if (!(result = mysql_store_result(db_config.myData))) {
        return -1;
    }

    // Does the account exist?
    if (!(result_row = mysql_fetch_row(result))) {
        mysql_free_result(result);
        send_bb_client_message(client, "Username or password is incorrect. ");
        send_bb_security(client, NULL, BB_LOGIN_ERROR_INVALID);
        return 1;
    }
    
    // Correct password?
    sha_password(password_hash, pkt->password);
    if (strcmp(password_hash, result_row[1])) {
        mysql_free_result(result);
        send_bb_client_message(client, "Username or password is incorrect. ");
        send_bb_security(client, NULL, BB_LOGIN_ERROR_LOCKED);
        return 1;
    }
    
    client->guildcard = atoi(result_row[6]);
    client->team_id = atoi(result_row[11]);
    client->is_gm = strcmp(result_row[6], "1") ? 0 : 1;
    
    // Account ban?
    if (strcmp(result_row[8], "0")) {
        mysql_free_result(result);
        send_bb_client_message(client, "You are banned from this server. ");
        send_bb_security(client, NULL, BB_LOGIN_ERROR_BANNED);
        return 2;
    }
    // Inactive?
    else if (strcmp(result_row[10], "0")) {
        mysql_free_result(result);
        send_bb_client_message(client, "Please complete the registration of this account "
                               "through\ne-mail validation.\n\nThank you. ");
        send_bb_security(client, NULL, BB_LOGIN_ERROR_UNREG);
        return 3;
    }
    // Client version up to date?
    if ((strcmp(pkt->version_string, PSO_CLIENT_VER_STRING) != 0) || pkt->client_version != PSO_CLIENT_VER) {
        mysql_free_result(result);
        send_bb_client_message(client, "Your client executable is too old.\nPlease update your client through the patch server.");
        send_bb_security(client, NULL, BB_LOGIN_ERROR_PATCH);
        return 5;
    }
    
    mysql_free_result(result);
    
    // Hardware ban?
    memcpy (client->hardware_info, hwinfo, 18);
    sprintf (query, "SELECT * from hw_bans WHERE hwinfo = '%s'", hwinfo );
    if (!mysql_query(db_config.myData, query)) {
        result = mysql_store_result(db_config.myData);
        int banned = (int) mysql_num_rows(result);
        mysql_free_result(result);
        if (banned) {
            send_bb_client_message(client, "You are banned from this server");
            send_bb_security(client, NULL, BB_LOGIN_ERROR_BANNED);
            return 2;
        }
    }
    else {
        return -1;
    }
    
    std::list<login_client*>::const_iterator c, c_end;
    std::list<ship_server*>::const_iterator s, s_end;
    
    // If guild card is connected to ships, disconnect it.
    for (s = ships.begin(), s_end = ships.end(); s != s_end; ++c)  {
        if ((*s)->authenticated == 1) {
            //send_ship_disconnect_client(gcn, tship);
            mysql_free_result(result);
            return 4;
        }
    }
    // If guild card is connected to the login server already, disconnect it.
    int connections = 0;
    for (c = clients.begin(), c_end = clients.end(); c != c_end; ++c) {
        if ((*c)->guildcard == client->guildcard) {
            connections++;
        }
        if (connections > MAX_SIMULTANEOUS_CONNECTIONS) {
            mysql_free_result(result);
            send_bb_client_message(client, "This account is already logged on.\n\nPlease wait 120 seconds and try again");
            send_bb_security(client, NULL, BB_LOGIN_ERROR_USERINUSE);
            return 4;
        }
    }

    return 0;
}

/* Process a login packet from the client once they receive their welcome packet.
 * We are only expecting packet 0x05 (disconnect) and 0x93 (login). Returns 0
 * on success, -1 for MySQL error and 1 for account-related error (failure to
 * log the player in).
 */
int handle_login(login_client* client) {
    bb_login_pkt *pkt = (bb_login_pkt*) client->recv_buffer;

    int status = verify_account(client, pkt);
    if (status) {
        if (status == -1) {
        mysqlbail:
            // MySQL error encountered; log an error and bail since there's not really a way to recover.
            log_mysql(ERROR, strerror(errno));
            send_bb_client_message(client, "There is a problem with the database.\n\nPlease contact the server administrator. ");
            send_bb_security(client, NULL, BB_LOGIN_ERROR_UNKNOWN);
            return -1;
        }
        return status;
    }
    
    // Make sure the version string is correct.
    if (strcmp(PSO_CLIENT_VER_STRING, pkt->version_string)) {
        send_bb_client_message(client, "Your client executable is too old, please update through the patch server. ");
        send_bb_security(client, NULL, BB_LOGIN_ERROR_PATCH);
        return 5;
    }
    
    // Generate the client's security data.
    char query[256] = {0};
    sprintf(query, "DELETE from security_data WHERE guildcard = '%u'", client->guildcard);
    mysql_query(db_config.myData, query);
    uint8_t security[8];
    char security_escaped[17];
    for (int i = 0; i < 8; i++) {
        security[i] = dist(rand_gen);
    }
    
    // Save the security data for the next time the client tries to log in.
    mysql_real_escape_string(db_config.myData, security_escaped, (char*)security, 8);
    sprintf(query, "INSERT INTO security_data (guildcard, thirtytwo, sixtyfour, isgm) VALUES ('%u','0','%s', '%u')",
            client->guildcard, security_escaped, client->is_gm);
    mysql_query(db_config.myData, query);
    if (mysql_errno(db_config.myData)) {
        goto mysqlbail;
    }

    /*
     TODO: Enable this?
    for (ch=0;ch<MAX_DRESS_FLAGS;ch++) {
        if ((dress_flags[ch].guildcard == gcn) || ((unsigned) servertime - dress_flags[ch].flagtime > DRESS_FLAG_EXPIRY))
           dress_flags[ch].guildcard = 0;
    }
    */
    send_bb_security(client, security, BB_LOGIN_ERROR_NONE);
    return 0;
}

/* Process a client packet sent to the CHARACTER server. Returns 0 on success,
 * 1 on error and -1 if the handler received an unrecognized packet type.
 * Side effect: will set client->todc = true where appropriate.
 */
int character_process_packet(login_client* client) {
    bb_packet_header* header = (bb_packet_header*) client->recv_buffer;
    header->type = LE16(header->type);
    header->length = LE16(header->length);
    
    int result = 0;
    switch (header->type) {
        case BB_LOGIN_DISCONNECT:
            result = 1;
            break;
        case BB_LOGIN_WELCOME_TYPE:
            result = handle_login(client);
            if (!result) {
                // send B1
                // send A0
                // send EE
            }
            break;
    }
    if (result) {
        client->todc = true;
    }
    return result;
}

/* Process a client packet sent to the LOGIN server. Returns 0 on success, 1
 * on error and -1 if the handler received an unrecognized packet type. 
 * Side effect: will set client->todc = true upon call.
 */
int login_process_packet(login_client* client) {
    bb_packet_header* header = (bb_packet_header*) client->recv_buffer;
    header->type = LE16(header->type);
    header->length = LE16(header->length);
    
    int result = 0;
    switch (header->type) {
        case BB_LOGIN_DISCONNECT:
            client->todc = true;
            break;
        case BB_LOGIN_TYPE:
            result = handle_login(client);
            if (!result) {
                result = send_bb_redirect(client, server_config.server_ip_netp, server_config.character_port);
            }
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
            // TODO: Rewrite once packing sending functions are implemented for ships.
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
                    if (receive_from_client((*c))) {
                        (*c)->todc = true;
                    }
                }
                
                if (FD_ISSET((*c)->socket, &writefds)) {
                    // TODO: Send whatever data we have to the client.
                    
                }
                
                if (FD_ISSET((*c)->socket, &exceptfds)) {
                    (*c)->todc = true;
                }
                
                if ((*c)->todc) {
                    // Send whatever we still have in the client's buffer.
                    if ((*c)->send_size > 0) {
                        send_packet((*c), (*c)->send_size);
                    }
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
        
        printf("MISSING.\nLoading config file in %s...", config_dir);
        cfg_file = json_load_file(config_dir, JSON_DECODE_ANY, &error);
        
        if (!cfg_file) {
            printf("Failed to load configuration file.\n");
            json_error(&error);
            return -1;
        }
    }
    char *global_color, *local_color, *normal_color;
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
            "welcome_message", &server_config.welcome_message,
            "config_dir", &server_config.config_dir,
            "max_client_connections", &server_config.serverMaxConnections,
            "max_ship_connections" , &server_config.serverMaxShips,
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
    
    server_config.server_ip_netp = inet_addr(server_config.server_ip);
    server_config.character_port = server_config.login_port + 1;
    globalName = atoi(global_color);
    localName = atoi(global_color);
    normalName = atoi(normal_color);
    
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
    if (load_config())
        exit(1);
    printf("OK\n");

    // Change the local directory for ease of loading files/folders.
    chdir(server_config.config_dir);
    
    // TODO: Load player starting stats
    // TODO: Packet E2 config?
    // TODO: Packet E7 config?
    // TODO: Packet EB
    // TODO: Quest item allowances

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
	printf ("Character Port: %u\n", server_config.character_port );
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
    printf ("Opening login port %s for connections...", port);
	login_sockfd = create_socket(port, &hints);
    printf("OK\n");
    
    sprintf(port, "%d", server_config.character_port);
    printf ("Opening character port %s for connections...", port);
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
