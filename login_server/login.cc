#include <cstring>
#include <cstdio>
#include <ctime>

extern "C" {
    #include "sniffex.h"
}

#include "login.h"
#include "common.h"
#include "packets.h"

const char *PSO_CLIENT_VER_STRING = "TethVer12510";

/* Process a login packet from the client once they receive their welcome packet.
 We are only expecting packet 0x05 (disconnect) and 0x93 (login). */
int handle_login(BANANA* client) {
	char password[34];
	long long security_sixtyfour_check;
	char hwinfo[18];
	char md5password[34] = {0};
	unsigned char MDBuffer[17] = {0};
	unsigned gcn;
	unsigned ch,connectNum,shipNum;
	ORANGE* tship;
	char security_sixtyfour_binary[18];
    char myQuery[0x10000] = {0};
    MYSQL_ROW myRow;
    MYSQL_RES * myResult;

    if (!client->sendCheck[RECEIVE_PACKET_93]) {
        bb_login_pkt *pkt = (bb_login_pkt*) client->recv_buffer;
        int fail_to_auth = 0;

        memcpy (&password[0], pkt->password, 17);
        memset (&hwinfo[0], 0, 18);

        mysql_real_escape_string ( db_config.myData, (char*)&hwinfo[0], (const char*) pkt->hardware_info, 8);
        memcpy (&client->hwinfo[0], &hwinfo[0], 18);

        sprintf (&myQuery[0], "SELECT * from account_data WHERE username='%s'", pkt->username);

        // Check to see if that account already exists.
        if ( ! mysql_query ( db_config.myData, &myQuery[0] ) )
        {
            int num_rows, max_fields;

            myResult = mysql_store_result ( db_config.myData );
            num_rows = (int) mysql_num_rows ( myResult );

            if (num_rows)
            {
                myRow = mysql_fetch_row ( myResult );
                max_fields = mysql_num_fields ( myResult );
                sprintf (&password[strlen(password)], "_%s_salt", myRow[3] );
                MDString ((char*)&password[0], (char*)&MDBuffer[0] );
                for (ch=0;ch<16;ch++)
                    sprintf (&md5password[ch*2], "%02x", (unsigned char) MDBuffer[ch]);
                md5password[32] = 0;
                if (!strcmp(&md5password[0],myRow[1]))
                {
                    if (!strcmp("1", myRow[8]))
                        fail_to_auth = 3;
                    if (!strcmp("1", myRow[9]))
                        fail_to_auth = 4;
                    if (!strcmp("0", myRow[10]))
                        fail_to_auth = 5;
                    if (!fail_to_auth)
                        gcn = atoi (myRow[6]);
                    if ((strcmp((char*)&client->decryptbuf[0x8C], PSO_CLIENT_VER_STRING) != 0) || (client->decryptbuf[0x10] != PSO_CLIENT_VER))
                        fail_to_auth = 7;
                    client->isgm = atoi (myRow[7]);
                }
                else
                    fail_to_auth = 2;
            }
            else
                fail_to_auth = 2;
            mysql_free_result ( myResult );
        }
        else
            fail_to_auth = 1; // MySQL error.

        // Hardware info ban check...

        sprintf (&myQuery[0], "SELECT * from hw_bans WHERE hwinfo='%s'", hwinfo );
        if ( ! mysql_query ( db_config.myData, &myQuery[0] ) )
        {
            myResult = mysql_store_result ( db_config.myData );
            if ((int) mysql_num_rows ( myResult ))
                fail_to_auth = 3;
            mysql_free_result ( myResult );
        }
        else
            fail_to_auth = 1;

        std::list<BANANA*>::const_iterator c, c_end;
        std::list<ORANGE*>::const_iterator s, s_end;
        time_t servertime = time(NULL);

        switch (fail_to_auth) {
			case 0x00:
				// If guild card is connected to the login server already, disconnect it.
                for (c = client_connections.begin(), c_end = client_connections.end(); c != c_end; ++c) {
                    if ((*c)->guildcard == gcn) {
                        send_bb_client_message(client,
                                "This account has just logged on.\n\nYou are now being disconnected.");
                        client->todc = true;
                        break;
                    }
                }

				// If guild card is connected to ships, disconnect it.
                for (s = ship_connections.begin(), s_end = ship_connections.end(); s != s_end; ++c)  {
                    if ((*s)->authed == 1)
                        send_ship_disconnect_client(gcn, tship);
                }

				send_bb_security(client, gcn, BB_LOGIN_ERROR_NONE);

                /*
				sprintf (&myQuery[0], "DELETE from security_data WHERE guildcard = '%u'", gcn );
				mysql_query ( db_config->myData, &myQuery[0] );
				mysql_real_escape_string ( db_config->myData, &security_sixtyfour_binary[0], (char*) &security_sixtyfour_check, 8);
				sprintf (&myQuery[0], "INSERT INTO security_data (guildcard, thirtytwo, sixtyfour, isgm) VALUES ('%u','0','%s', '%u')", gcn, (char*) &security_sixtyfour_binary, client->isgm );
                 */
				if ( mysql_query ( db_config.myData, &myQuery[0] ) )
				{
					send_bb_client_message(client,
                            "Couldn't update security information in MySQL database.\nPlease contact the server administrator.");
					client->todc = 1;
					return false;
				}

				for (ch=0;ch<MAX_DRESS_FLAGS;ch++)
				{
					//if ((dress_flags[ch].guildcard == gcn) || ((unsigned) servertime - dress_flags[ch].flagtime > DRESS_FLAG_EXPIRY))
                     //   dress_flags[ch].guildcard = 0;
				}

                //send_bb_redirect(client, server_config.serverIPN, server_config.serverPort);
				break;
			case 0x01:
				// MySQL error.
				send_bb_client_message(client,
                        "There is a problem with the MySQL database.\n\nPlease contact the server administrator.");
				break;
			case 0x02:
				// Username or password incorrect.
				send_bb_client_message(client, "Username or password is incorrect.");
                send_bb_security(client, gcn, BB_LOGIN_ERROR_INVALID);
				break;
			case 0x03:
				// Account is banned.
				send_bb_client_message(client, "You are banned from this server.");
                send_bb_security(client, gcn, BB_LOGIN_ERROR_BANNED);
				break;
			case 0x04:
				// Already logged on.
				send_bb_client_message(client, "This account is already logged on.\n\nPlease wait 120 seconds and try again.");
                send_bb_security(client, gcn, BB_LOGIN_ERROR_USERINUSE);
				break;
			case 0x05:
				// Account has not completed e-mail validation.
                send_bb_client_message(client,
                        "Please complete the registration of this account through\ne-mail validation.\n\nThank you.");
                send_bb_security(client, gcn, BB_LOGIN_ERROR_UNREG);
				break;
			case 0x07:
				// Client version too old.
				send_bb_client_message(client,
                        "Your client executable is too old.\nPlease update your client through the patch server.");
                send_bb_security(client, gcn, BB_LOGIN_ERROR_PATCH);
				break;
			default:
				send_bb_client_message(client, "Unknown error.");
                send_bb_security(client, gcn, BB_LOGIN_ERROR_UNKNOWN);
				break;
        }
        if (fail_to_auth > 0)
            client->todc = true;

        client->sendCheck[RECEIVE_PACKET_93] = 0x01;
    }
    return 0;
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
