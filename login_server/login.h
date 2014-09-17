#ifndef tehealla_login_h
#define tehealla_login_h

#include <cstdint>
#include <list>
#include "login_server.h"
#include "packets.h"

// TODO: Get rid of this atrocity.
extern std::list<BANANA*> client_connections;
extern std::list<ORANGE*> ship_connections;
extern login_config server_config;
extern mysql_config db_config;

bool send_packet(BANANA *client, int len);
bool send_bb_login_welcome(BANANA* client, uint8_t s_seed[48], uint8_t c_seed[48]);

int handle_login(BANANA* client);
int login_process_packet(BANANA* client);

#endif