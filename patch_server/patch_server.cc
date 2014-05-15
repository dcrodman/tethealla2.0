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
 
 Please note that
 
 */

#include "encryption.h"
#include "patch_server.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>

const char *PATCH_PORT = "11000";
const char *DATA_PORT = "11001";

// Allowed number of pending connections.
const int BACKLOG = 10;

#define MAX_PATCHES 4096
#define PATCH_COMPILED_MAX_CONNECTIONS 300
#define SERVER_VERSION "0.010"

#define SEND_PACKET_02 0x00
#define RECEIVE_PACKET_02 0x01
#define RECEIVE_PACKET_10 0x02
#define SEND_PACKET_0B 0x03
#define MAX_SENDCHECK 0x04

//#define USEADDR_ANY
//#define DEBUG_OUTPUT
#define TCP_BUFFER_SIZE 65530

struct timeval select_timeout = {
	0,
	5000
};

void send_to_server(int sock, char* packet);
int receive_from_server(int sock, char* packet);
void debug(char *fmt, ...);
void debug_perror(char * msg);
void tcp_listen (int sockfd);
int tcp_accept (int sockfd, struct sockaddr *client_addr, int *addr_len );
int tcp_sock_open(struct in_addr ip, int port);

/* "Welcome" Packet */

unsigned char Packet02[] = {
	0x4C, 0x00, 0x02, 0x00, 0x50, 0x61, 0x74, 0x63, 0x68, 0x20, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72,
	0x2E, 0x20, 0x43, 0x6F, 0x70, 0x79, 0x72, 0x69, 0x67, 0x68, 0x74, 0x20, 0x53, 0x6F, 0x6E, 0x69,
	0x63, 0x54, 0x65, 0x61, 0x6D, 0x2C, 0x20, 0x4C, 0x54, 0x44, 0x2E, 0x20, 0x32, 0x30, 0x30, 0x31,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x2D, 0x69, 0x06, 0x9E, 0xDC, 0xE0, 0x6F, 0xCA
};

const unsigned char Message02[] = { "Tethealla Patch" };

/* Populated by load_config_file(): */

unsigned char serverIP[4];
unsigned short serverPort;
int override_on = 0;
unsigned char overrideIP[4];
unsigned short serverMaxConnections;
unsigned serverNumConnections = 0;
unsigned serverConnectionList[PATCH_COMPILED_MAX_CONNECTIONS]; // One patch, one data.

char Welcome_Message[4096] = {0};
unsigned short Welcome_Message_Size = 0;
time_t servertime;
time_t sendtime;
int maxbytes  = 0;

/* Client Structure */

typedef struct st_patch_data {
	unsigned file_size;
	unsigned checksum;
	char full_file_name[FILENAME_MAX+48];
	char file_name[48];
	char folder[FILENAME_MAX];
	unsigned char patch_folders[128]; // Command to get to the folder this file resides in...
	unsigned patch_folders_size;
	unsigned patch_steps; // How many steps from the root folder this file is...
} patch_data;

typedef struct st_client_data {
	unsigned file_size;
	unsigned checksum;
} client_data;

typedef struct st_banana {
	int patch;
	int plySockfd;
	unsigned char peekbuf[8];
	unsigned char rcvbuf [TCP_BUFFER_SIZE];
	unsigned short rcvread;
	unsigned short expect;
	unsigned char decryptbuf [TCP_BUFFER_SIZE];
	unsigned char sndbuf [TCP_BUFFER_SIZE];
	unsigned char encryptbuf [TCP_BUFFER_SIZE];
	int snddata,
    sndwritten;
	unsigned char packet [TCP_BUFFER_SIZE];
	unsigned short packetdata;
	unsigned short packetread;
	int crypt_on;
	CRYPT_SETUP server_cipher, client_cipher;
	client_data p_data[MAX_PATCHES];
	int sending_files;
	unsigned files_to_send;
	unsigned bytes_to_send;
	unsigned s_data[MAX_PATCHES];
	char username[17];
	unsigned current_file;
	unsigned cfile_index;
	unsigned lastTick;		// The last second
	unsigned toBytesSec;	// How many bytes per second the server sends to the client
	unsigned fromBytesSec;	// How many bytes per second the server receives from the client
	unsigned packetsSec;	// How many packets per second the server receives from the client
	unsigned connected;
	unsigned char sendCheck[MAX_SENDCHECK+2];
	int todc;
	char patch_folder[FILENAME_MAX];
	unsigned patch_steps;
	unsigned chunk;
	unsigned char IP_Address[16];
	unsigned connection_index;
} BANANA;

#define MAX_SIMULTANEOUS_CONNECTIONS 6

BANANA * connections[PATCH_COMPILED_MAX_CONNECTIONS];
BANANA * workConnect;

unsigned char dp[TCP_BUFFER_SIZE*4];
char PacketData[TCP_BUFFER_SIZE];

unsigned char patch_packet[TCP_BUFFER_SIZE];
unsigned patch_size = 0;
patch_data s_data[MAX_PATCHES];
unsigned serverNumPatches = 0;

void decryptcopy ( void* dest, void* source, unsigned size );
void encryptcopy ( BANANA* client, void* source, unsigned size );

CRYPT_SETUP *cipher_ptr;

#define MYWM_NOTIFYICON (WM_USER+2)

void display_packet ( unsigned char* buf, int len )
{
	int c, c2, c3, c4;
    
	c = c2 = c3 = c4 = 0;
    
	for (c=0;c<len;c++)
	{
		if (c3==16)
		{
			for (;c4<c;c4++)
				if (buf[c4] >= 0x20)
					dp[c2++] = buf[c4];
				else
					dp[c2++] = 0x2E;
			c3 = 0;
			sprintf (&dp[c2++], "\n" );
		}
        
		if ((c == 0) || !(c % 16))
		{
			sprintf (&dp[c2], "(%04X) ", c);
			c2 += 7;
		}
        
		sprintf (&dp[c2], "%02X ", buf[c]);
		c2 += 3;
		c3++;
	}
    
	if ( len % 16 )
	{
		c3 = len;
		while (c3 % 16)
		{
			sprintf (&dp[c2], "   ");
			c2 += 3;
			c3++;
		}
	}
    
	for (;c4<c;c4++)
		if (buf[c4] >= 0x20)
			dp[c2++] = buf[c4];
		else
			dp[c2++] = 0x2E;
    
	dp[c2] = 0;
	printf ("%s\n\n", &dp[0]);
}

long CalculateChecksum(void* data,unsigned long size)
{
    long offset,y,cs = 0xFFFFFFFF;
    for (offset = 0; offset < (long)size; offset++)
    {
        cs ^= *(unsigned char*)((long)data + offset);
        for (y = 0; y < 8; y++)
        {
            if (!(cs & 1)) cs = (cs >> 1) & 0x7FFFFFFF;
            else cs = ((cs >> 1) & 0x7FFFFFFF) ^ 0xEDB88320;
        }
    }
    return (cs ^ 0xFFFFFFFF);
}


void load_config_file() {
    
}

unsigned free_connection()
{
	unsigned fc;
	BANANA* wc;
    
	for (fc=0;fc<serverMaxConnections;fc++)
	{
		wc = connections[fc];
		if (wc->plySockfd<0)
			return fc;
	}
	return 0xFFFF;
}


void initialize_connection (BANANA* connect)
{
	unsigned ch, ch2;
    
	if (connect->plySockfd >= 0)
	{
		ch2 = 0;
		for (ch=0;ch<serverNumConnections;ch++)
		{
			if (serverConnectionList[ch] != connect->connection_index)
				serverConnectionList[ch2++] = serverConnectionList[ch];
		}
		serverNumConnections = ch2;
		closesocket (connect->plySockfd);
	}
	memset (connect, 0, sizeof (BANANA));
	connect->plySockfd = -1;
	connect->lastTick = 0xFFFFFFFF;
	connect->connected = 0xFFFFFFFF;
}


void start_encryption(BANANA* connect)
{
	unsigned c, c3, c4, connectNum;
	BANANA *workConnect, *c5;
    
	// Limit the number of connections from an IP address to MAX_SIMULTANEOUS_CONNECTIONS.
    
	c3 = 0;
    
	for (c=0;c<serverNumConnections;c++)
	{
		connectNum = serverConnectionList[c];
		workConnect = connections[connectNum];
		//debug ("%s comparing to %s", (char*) &workConnect->IP_Address[0], (char*) &connect->IP_Address[0]);
		if ((!strcmp(&workConnect->IP_Address[0], &connect->IP_Address[0])) &&
			(workConnect->plySockfd >= 0))
			c3++;
	}
    
	if (c3 > MAX_SIMULTANEOUS_CONNECTIONS)
	{
		// More than MAX_SIMULTANEOUS_CONNECTIONS connections from a certain IP address...
		// Delete oldest connection to server.
		c4 = 0xFFFFFFFF;
		c5 = NULL;
		for (c=0;c<serverNumConnections;c++)
		{
			connectNum = serverConnectionList[c];
			workConnect = connections[connectNum];
			if ((!strcmp(&workConnect->IP_Address[0], &connect->IP_Address[0])) &&
				(workConnect->plySockfd >= 0))
			{
				if (workConnect->connected < c4)
				{
					c4 = workConnect->connected;
					c5 = workConnect;
				}
			}
		}
		if (c5)
		{
			workConnect = c5;
			initialize_connection (workConnect);
		}
	}
	memcpy (&connect->sndbuf[0], &Packet02[0], sizeof (Packet02));
	for (c=0;c<8;c++)
		connect->sndbuf[0x44+c] = (unsigned char) rand() % 255;
	connect->snddata += sizeof (Packet02);
    
	memcpy (&c, &connect->sndbuf[0x44], 4);
	CRYPT_PC_CreateKeys(&connect->server_cipher,c);
	memcpy (&c, &connect->sndbuf[0x48], 4);
	CRYPT_PC_CreateKeys(&connect->client_cipher,c);
	connect->crypt_on = 1;
	connect->sendCheck[SEND_PACKET_02] = 1;
	connect->connected = (unsigned) servertime;
}

void change_client_folder (unsigned patchNum, BANANA* client);

void Send11 (BANANA* client)
{
	unsigned ch;
    
	client->sendCheck[RECEIVE_PACKET_10] = 1;
    
	for (ch=0;ch<serverNumPatches;ch++)
	{
		if ((client->p_data[ch].file_size != s_data[ch].file_size) ||
			(client->p_data[ch].checksum  != s_data[ch].checksum))
		{
			//debug ("%s mismatch", s_data[ch].file_name);
			client->s_data[client->files_to_send++] = ch;
			client->bytes_to_send += s_data[ch].file_size;
		}
	}
    
	if (client->files_to_send)
	{
		memset (&client->encryptbuf[0x00], 0, 0x0C);
		memcpy (&client->encryptbuf[0x04], &client->bytes_to_send, 4);
		memcpy (&client->encryptbuf[0x08], &client->files_to_send, 4);
		client->encryptbuf[0x00] = 0x0C;
		client->encryptbuf[0x02] = 0x11;
		cipher_ptr = &client->server_cipher;
		encryptcopy (client, &client->encryptbuf[0x00], 0x0C);
		change_client_folder (client->s_data[0], client);
		client->sending_files = 1; // We're in send mode!
		printf ("(%s) Sending %u files, total bytes: %u\n", client->username, client->files_to_send, client->bytes_to_send);
	}
	else
	{
		workConnect->encryptbuf[0x00] = 0x04;
		workConnect->encryptbuf[0x01] = 0x00;
		workConnect->encryptbuf[0x02] = 0x12;
		workConnect->encryptbuf[0x03] = 0x00;
		cipher_ptr = &workConnect->server_cipher;
		encryptcopy (workConnect, &workConnect->encryptbuf[0x00], 4);
	}
}

void Send0B (BANANA* client)
{
	if (!client->sendCheck[SEND_PACKET_0B])
	{
		client->sendCheck[SEND_PACKET_0B] = 1;
		client->encryptbuf[0x00] = 0x04;
		client->encryptbuf[0x01] = 0x00;
		client->encryptbuf[0x02] = 0x0B;
		client->encryptbuf[0x03] = 0x00;
		cipher_ptr = &client->server_cipher;
		encryptcopy (client, &client->encryptbuf[0x00], 4);
		cipher_ptr = &client->server_cipher;
		encryptcopy (client, &patch_packet[0], patch_size);
	}
}

void Send13 (BANANA* client)
{
	unsigned short Welcome_Size;
	unsigned char port[2];
    
	Welcome_Size = Welcome_Message_Size + 4;
	memcpy (&client->encryptbuf[0x04], &Welcome_Message[0], Welcome_Message_Size);
	client->encryptbuf[0x02] = 0x13;
	client->encryptbuf[0x03] = 0x00;
	client->encryptbuf[Welcome_Size++] = 0x00;
	client->encryptbuf[Welcome_Size++] = 0x00;
	while (Welcome_Size % 4)
		client->encryptbuf[Welcome_Size++] = 0x00;
	memcpy (&client->encryptbuf[0x00], &Welcome_Size, 2);
	cipher_ptr = &client->server_cipher;
	encryptcopy (client, &client->encryptbuf[0x00], Welcome_Size);
	memset (&client->encryptbuf[0x00], 0, 0x0C);
	client->encryptbuf[0x00] = 0x0C;
	client->encryptbuf[0x02] = 0x14;
	memcpy (&client->encryptbuf[0x04], &serverIP, 4);
	Welcome_Size = serverPort;
	Welcome_Size -= 999;
	memcpy (&port, &Welcome_Size, 2);
	client->encryptbuf[0x08] = port[1];
	client->encryptbuf[0x09] = port[0];
	cipher_ptr = &client->server_cipher;
	encryptcopy (client, &client->encryptbuf[0x00], 0x0C);
}

void DataProcessPacket (BANANA* client)
{
	unsigned patch_index;
    
	switch (client->decryptbuf[0x02])
	{
        case 0x02:
            // Acknowledging welcome packet
            client->encryptbuf[0x00] = 0x04;
            client->encryptbuf[0x01] = 0x00;
            client->encryptbuf[0x02] = 0x04;
            client->encryptbuf[0x03] = 0x00;
            cipher_ptr = &client->server_cipher;
            encryptcopy (client, &client->encryptbuf[0x00], 4);
            break;
        case 0x04:
            // Client sending user name to begin downloading patch data
            memcpy (&client->username[0], &client->decryptbuf[0x10], 16);
            Send0B (client); // Data time...
            break;
        case 0x0F:
            // Client sending status of current patch file
            memcpy (&patch_index, &client->decryptbuf[0x04], 4);
            if (patch_index < MAX_PATCHES)
            {
                memcpy (&client->p_data[patch_index].checksum,  &client->decryptbuf[0x08], 4);
                memcpy (&client->p_data[patch_index].file_size, &client->decryptbuf[0x0C], 4);
            }
            break;
        case 0x10:
            // Client done sending all patch file status
            if (!client->sendCheck[RECEIVE_PACKET_10])
                Send11 (client);
            break;
	}
}

void PatchProcessPacket (BANANA* client)
{
	switch (client->decryptbuf[0x02])
	{
        case 0x02:
            // Acknowledging welcome packet
            client->encryptbuf[0x00] = 0x04;
            client->encryptbuf[0x01] = 0x00;
            client->encryptbuf[0x02] = 0x04;
            client->encryptbuf[0x03] = 0x00;
            cipher_ptr = &client->server_cipher;
            encryptcopy (client, &client->encryptbuf[0x00], 4);
            break;
        case 0x04:
            // Client sending user name to begin downloading patch data
            memcpy (&client->username[0], &client->decryptbuf[0x10], 16);
            Send13 (client); // Welcome packet
            break;
        default:
            break;
	}
}

char patch_folder[FILENAME_MAX] = {0};
unsigned patch_steps = 0;
int now_folder = -1;

int	scandir(char *path, BOOL recursive);
int	fixpath(char *inpath, char *outpath);

void change_client_folder (unsigned patchNum, BANANA* client)
{
	unsigned ch, ch2, ch3;
    
	if (strcmp(&client->patch_folder[0], &s_data[patchNum].folder[0]) != 0)
	{
		// Client not in the right folder...
        
		while (client->patch_steps)
		{
			client->encryptbuf[0x00] = 0x04;
			client->encryptbuf[0x01] = 0x00;
			client->encryptbuf[0x02] = 0x0A;
			client->encryptbuf[0x03] = 0x00;
			cipher_ptr = &client->server_cipher;
			encryptcopy (client, &client->encryptbuf[0x00], 4);
			client->patch_steps--;
		}
        
		if (s_data[patchNum].patch_folders[0] != 0x2E)
		{
			ch = 0;
			while (ch<s_data[patchNum].patch_folders_size)
			{
				memset (&client->encryptbuf[0x00], 0, 0x44);
				client->encryptbuf[0x00] = 0x44;
				client->encryptbuf[0x02] = 0x09;
				ch3 = 0;
				for (ch2=ch;ch2<s_data[patchNum].patch_folders_size;ch2++)
				{
					if (s_data[patchNum].patch_folders[ch2] == 0x00)
						break;
					ch3++;
				}
				strcat (&client->encryptbuf[0x04], &s_data[patchNum].patch_folders[ch]);
				ch += (ch3 + 1);
				cipher_ptr = &client->server_cipher;
				encryptcopy (client, &client->encryptbuf[0x00], 0x44);
			}
		}
		memcpy (&client->patch_folder[0], &s_data[patchNum].folder, FILENAME_MAX);
		client->patch_steps = s_data[patchNum].patch_steps;
	}
	// Now let's send the information about the file coming in...
	memset (&client->encryptbuf[0x00], 0, 0x3C);
	client->encryptbuf[0x00] = 0x3C;
	client->encryptbuf[0x02] = 0x06;
	memcpy (&client->encryptbuf[0x08], &s_data[patchNum].file_size, 4);
	strcat (&client->encryptbuf[0x0C], &s_data[patchNum].file_name[0]);
	cipher_ptr = &client->server_cipher;
	encryptcopy (client, &client->encryptbuf[0x00], 0x3C);
}

void change_patch_folder (unsigned patchNum)
{
	unsigned ch, ch2, ch3;
    
	if (strcmp(&patch_folder[0], &s_data[patchNum].folder[0]) != 0)
	{
		// Not in the right folder...
        
		while (patch_steps)
		{
			patch_packet[patch_size++] = 0x04;
			patch_packet[patch_size++] = 0x00;
			patch_packet[patch_size++] = 0x0A;
			patch_packet[patch_size++] = 0x00;
			patch_steps--;
		}
        
		if (s_data[patchNum].patch_folders[0] != 0x2E)
		{
			ch = 0;
			while (ch<s_data[patchNum].patch_folders_size)
			{
				memset (&patch_packet[patch_size], 0, 0x44);
				patch_packet[patch_size+0x00] = 0x44;
				patch_packet[patch_size+0x02] = 0x09;
				ch3 = 0;
				for (ch2=ch;ch2<s_data[patchNum].patch_folders_size;ch2++)
				{
					if (s_data[patchNum].patch_folders[ch2] == 0x00)
						break;
					ch3++;
				}
				strcat (&patch_packet[patch_size+0x04], &s_data[patchNum].patch_folders[ch]);
				ch += (ch3 + 1);
				patch_size += 0x44;
			}
		}
		memcpy (&patch_folder[0], &s_data[patchNum].folder, FILENAME_MAX);
		patch_steps = s_data[patchNum].patch_steps;
	}
}

int scandir(char *_path, BOOL recursive)
{
	HANDLE fh;
	char	 path[FILENAME_MAX];
	char	 tmppath[FILENAME_MAX];
	WIN32_FIND_DATA *fd;
	void *pd;
	FILE* pf;
	unsigned f_size, f_checksum, ch, ch2, ch3;
    
	now_folder ++;
    
	fd = malloc(sizeof(WIN32_FIND_DATA));
    
	fixpath(_path,path);
	strcat(path,"*");
    
	printf("Scanning: %s\n",path);
    
	fh = FindFirstFile((LPCSTR) path,fd);
    
	if(fh != INVALID_HANDLE_VALUE)
	{
		do
		{
			if(fd->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				if((0 != strcmp(fd->cFileName,".")) && (0 != strcmp(fd->cFileName,"..")))
				{
					fixpath(_path,tmppath);
					strcat(tmppath,fd->cFileName);
					fixpath(tmppath,tmppath);
					if(recursive)
						scandir(tmppath,recursive);
				}
			}
			else
			{
				fixpath(_path,tmppath);
				s_data[serverNumPatches].full_file_name[0] = 0;
				strcat (&s_data[serverNumPatches].full_file_name[0],&tmppath[0]);
				strcat (&s_data[serverNumPatches].full_file_name[0],fd->cFileName);
				f_size = ((fd->nFileSizeHigh * MAXDWORD)+fd->nFileSizeLow);
				pd = malloc (f_size);
				pf = fopen (&s_data[serverNumPatches].full_file_name[0], "rb");
				fread ( pd, 1, f_size, pf );
				fclose ( pf );
				f_checksum = CalculateChecksum ( pd, f_size );
				free ( pd );
				printf ("%s  Bytes: %u  Checksum: %08x\n", fd->cFileName, f_size, f_checksum );
				s_data[serverNumPatches].file_size	= f_size;
				s_data[serverNumPatches].checksum	= f_checksum;
				s_data[serverNumPatches].file_name[0] = 0;
				strcat (&s_data[serverNumPatches].file_name[0],fd->cFileName);
				s_data[serverNumPatches].folder[0] = 0;
				strcat (&s_data[serverNumPatches].folder[0],&tmppath[0]);
				ch2 = 0;
				ch3 = 0;
				if (now_folder)
				{
					for (ch=0;ch<strlen(&tmppath[0]);ch++)
					{
						if (tmppath[ch] != 92)
							s_data[serverNumPatches].patch_folders[ch2++] = tmppath[ch];
						else
						{
							s_data[serverNumPatches].patch_folders[ch2++] = 0;
							_strlwr (&s_data[serverNumPatches].patch_folders[ch3]);
							if (strcmp(&s_data[serverNumPatches].patch_folders[ch3],"patches") == 0)
							{
								ch2 = ch3;
								s_data[serverNumPatches].patch_folders[ch2] = 0;
							}
							else
								ch3 = ch2;
						}
					}
					s_data[serverNumPatches].patch_folders_size = ch2;
				}
				else
				{
					s_data[serverNumPatches].patch_folders[0] = 0x2E;
					s_data[serverNumPatches].patch_folders[1] = 0;
					s_data[serverNumPatches].patch_folders_size = 1;
				}
                
				/*
                 
                 printf ("file patch\n\nfile_size: %u\n", s_data[serverNumPatches].file_size);
                 printf ("checksum: %08x\n", s_data[serverNumPatches].checksum);
                 printf ("full file name: %s\n", s_data[serverNumPatches].full_file_name);
                 printf ("file name: %s\n", s_data[serverNumPatches].file_name);
                 printf ("folder: %s\n", s_data[serverNumPatches].folder);
                 printf ("patch_folders_size: %u\n", s_data[serverNumPatches].patch_folders_size);
                 printf ("patch_steps: %u\n", s_data[serverNumPatches].patch_steps);
                 
                 */
                
				s_data[serverNumPatches++].patch_steps = now_folder;
				change_patch_folder (serverNumPatches - 1);
				ch = serverNumPatches - 1;
				memset (&patch_packet[patch_size], 0, 0x28);
				memcpy (&patch_packet[patch_size+4], &ch, 4);
				strcat (&patch_packet[patch_size+8], fd->cFileName);
				patch_packet[patch_size]   = 0x28;
				patch_packet[patch_size+2] = 0x0C;
				patch_size += 0x28;
			}
		}
		while(FindNextFile(fh,fd));
	}
    
	FindClose(fh);
    
	free (fd);
    
	now_folder--;

	return 1;
}

int fixpath(char *inpath, char *outpath)
{
    int   n=0;
    
    strcpy(outpath,inpath);
    
    while(inpath[n]) n++;
    
    if(inpath[n-1] != '\\')
    {
        strcat(outpath,"\\");
        return 1;
    }
    
    return 0;
}

void print_copyright() {
    printf("\nTethealla Patch Server version %s  Copyright (C) 2008  Terry Chatman Jr.\n", SERVER_VERSION);
    printf("Modified version Copyright 2014 Andrew Rodman.\n");
	printf("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n");
	printf("This program comes with ABSOLUTELY NO WARRANTY; for details\n");
	printf("see section 15 in gpl-3.0.txt\n");
    printf("This is free software, and you are welcome to redistribute it\n");
    printf("under certain conditions; see gpl-3.0.txt for details.\n");
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

/********************************************************
 **
 **		main  :-
 **
 ********************************************************/

int main( int argc, char * argv[] )
{
	unsigned ch,ch2;
	struct in_addr patch_in;
	struct in_addr data_in;
	struct sockaddr_in listen_in;
	unsigned listen_length;
	int patch_sockfd = -1, data_sockfd;
	int pkt_len, pkt_c, bytes_sent;
	unsigned short this_packet;
	unsigned short *w;
	unsigned short *w2;
	unsigned num_sends = 0;
	patch_data *pd;
	MSG msg;
    
    fd_set ReadFDs, WriteFDs, ExceptFDs;
	//int wserror;
	unsigned char tmprcv[TCP_BUFFER_SIZE];
	unsigned connectNum;
	unsigned to_send, checksum;
	int data_send, data_remaining;
	WSADATA winsock_data;
    
	dp[0] = 0;
    
	data_remaining = 0;
    
	srand ( (unsigned) time(NULL) );
    
    print_copyright();
    
	printf ("Loading configuration from tethealla.ini ...");
	load_config_file();
	if (maxbytes)
		data_remaining = maxbytes;
	printf ("  OK!\n");
	printf ("\nPatch server parameters\n");
	printf ("///////////////////////\n");
	if (override_on)
		printf ("NOTE: IP override feature is turned on.\nThe server will bind to %u.%u.%u.%u but will send out the IP listed below.\n", overrideIP[0], overrideIP[1], overrideIP[2], overrideIP[3] );
	printf ("IP: %u.%u.%u.%u\n", serverIP[0], serverIP[1], serverIP[2], serverIP[3] );
	printf ("Patch Port: %u\n", serverPort - 1000 );
	printf ("Data Port: %u\n", serverPort - 999 );
	printf ("Maximum Connections: %u\n", serverMaxConnections );
	printf ("Upload speed: ");
	if (maxbytes)
		printf ("%u KB/s\n", maxbytes / 1024L);
	else
		printf ("Max\n");
	printf ("Allocating %u bytes of memory for connections...", sizeof (BANANA) * serverMaxConnections );
	for (ch=0;ch<serverMaxConnections;ch++)
	{
		connections[ch] = malloc ( sizeof (BANANA) );
		if ( !connections[ch] )
		{
			printf ("Out of memory!\n");
			exit (1);
		}
		initialize_connection (connections[ch]);
	}
	printf (" OK!\n\n");
    
	printf ("Preparing patch data...\n");
	printf ("Reading from folder \"patches\"...\n");
    
	memset (&patch_packet[patch_size], 0, 0x44);
	patch_packet[patch_size+0x00] = 0x44;
	patch_packet[patch_size+0x02] = 0x09;
	patch_packet[patch_size+0x04] = 0x2E;
	patch_size += 0x44;
	scandir ("patches",1);
	patch_packet[patch_size++] = 0x04;
	patch_packet[patch_size++] = 0x00;
	patch_packet[patch_size++] = 0x0A;
	patch_packet[patch_size++] = 0x00;
	patch_packet[patch_size++] = 0x04;
	patch_packet[patch_size++] = 0x00;
	patch_packet[patch_size++] = 0x0D;
	patch_packet[patch_size++] = 0x00;
	printf ("\nDone!\n\n");
    
	if (!serverNumPatches)
	{
		printf ("There are no patches to send.\nYou need at least one patch file to send or check.\n");
		printf ("Hit [ENTER]");
		exit (1);
	}
    
	printf ("Loading welcome.txt ...");
	printf ("  (%u bytes) OK!\n\n", Welcome_Message_Size);
    
	/* Open the PSO BB Patch Server Ports... */
    
    addrinfo hints;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    
    printf ("Opening server PATCH port %s for connections.\n", PATCH_PORT);
	int patch_sockfd = create_socket(PATCH_PORT, &hints);
    
	printf ("Opening server data port %u for connections.\n", serverPort - 999);
    int data_sockfd = create_socket(DATA_PORT, &hints);
    
	printf ("\nListening for connections...\n");
    
	for (;;)
	{
		int nfds = 0;
        
        /* Ping pong?! */
        
		servertime = time(NULL);
        
		if ((maxbytes) && (sendtime != (unsigned) servertime))
		{
			sendtime  = (unsigned) servertime;
			data_remaining = maxbytes;
		}
        
		/* Clear socket activity flags. */
        
		FD_ZERO (&ReadFDs);
		FD_ZERO (&WriteFDs);
		FD_ZERO (&ExceptFDs);
        
		num_sends = 0;
        
		for (ch=0;ch<serverNumConnections;ch++)
		{
			connectNum = serverConnectionList[ch];
			workConnect = connections[connectNum];
            
			if (workConnect->plySockfd >= 0)
			{
				if (workConnect->packetdata)
				{
					memcpy (&this_packet, &workConnect->packet[workConnect->packetread], 2);
					memcpy (&workConnect->decryptbuf[0], &workConnect->packet[workConnect->packetread], this_packet);
                    
					//debug ("Received from client:%u", this_packet);
					//display_packet (&workConnect->decryptbuf[0], this_packet);
                    
					if (workConnect->patch)
						DataProcessPacket (workConnect);
					else
						PatchProcessPacket (workConnect);
                    
					workConnect->packetread += this_packet;
					if (workConnect->packetread == workConnect->packetdata)
						workConnect->packetread = workConnect->packetdata = 0;
				}
                
				if (workConnect->lastTick != (unsigned) servertime)
				{
					if (workConnect->lastTick > (unsigned) servertime)
						ch2 = 1;
					else
						ch2 = 1 + ((unsigned) servertime - workConnect->lastTick);
                    workConnect->lastTick = (unsigned) servertime;
                    workConnect->packetsSec /= ch2;
                    workConnect->toBytesSec /= ch2;
                    workConnect->fromBytesSec /= ch2;
				}
                
				FD_SET (workConnect->plySockfd, &ReadFDs);
				nfds = max (nfds, workConnect->plySockfd);
				FD_SET (workConnect->plySockfd, &ExceptFDs);
				nfds = max (nfds, workConnect->plySockfd);
                
				if ((!maxbytes) || (data_remaining))
				{
					if (workConnect->snddata - workConnect->sndwritten)
					{
						FD_SET (workConnect->plySockfd, &WriteFDs);
						nfds = max (nfds, workConnect->plySockfd);
					}
					else
					{
						// Send remaining patch data here...
						// if sending_files and stuff left to go
						if (workConnect->sending_files)
						{
							num_sends++;
							pd = &s_data[workConnect->s_data[workConnect->current_file]];
							fp = fopen (&pd->full_file_name[0], "rb");
							fseek (fp, workConnect->cfile_index, SEEK_SET);
							to_send = pd->file_size - workConnect->cfile_index;
							if (to_send > 24576)
								to_send = 24576;
							fread (&PacketData[0x10], 1, to_send, fp);
							fclose (fp);
							workConnect->cfile_index += to_send;
							checksum = CalculateChecksum ( &PacketData[0x10], to_send);
							memset (&PacketData[0x00], 0, 0x10);
							PacketData[0x02] = 0x07;
							memcpy (&PacketData[0x04], &workConnect->chunk, 4);
							memcpy (&PacketData[0x08], &checksum, 4);
							memcpy (&PacketData[0x0C], &to_send,  4);
							to_send += 0x10;
							while (to_send % 4)
								PacketData[to_send++] = 0x00;
							memcpy (&PacketData[0x00], &to_send, 2);
							cipher_ptr = &workConnect->server_cipher;
							encryptcopy (workConnect, &PacketData[0x00], to_send);
							workConnect->chunk++;
							if (workConnect->cfile_index == pd->file_size)
							{
								// File's done...
								memset (&workConnect->encryptbuf[0x00], 0, 8);
								workConnect->encryptbuf[0x00] = 0x08;
								workConnect->encryptbuf[0x02] = 0x08;
								cipher_ptr = &workConnect->server_cipher;
								encryptcopy (workConnect, &workConnect->encryptbuf[0x00], 8);
								workConnect->chunk = 0;
								workConnect->cfile_index = 0;
								// Are we completely done?
								workConnect->current_file++;
								if (workConnect->current_file == workConnect->files_to_send)
								{
									// Hell yeah we are!
									while (workConnect->patch_steps)
									{
										workConnect->encryptbuf[0x00] = 0x04;
										workConnect->encryptbuf[0x01] = 0x00;
										workConnect->encryptbuf[0x02] = 0x0A;
										workConnect->encryptbuf[0x03] = 0x00;
										cipher_ptr = &workConnect->server_cipher;
										encryptcopy (workConnect, &workConnect->encryptbuf[0x00], 4);
										workConnect->patch_steps--;
									}
									workConnect->sending_files = 0;
									workConnect->encryptbuf[0x00] = 0x04;
									workConnect->encryptbuf[0x01] = 0x00;
									workConnect->encryptbuf[0x02] = 0x0A;
									workConnect->encryptbuf[0x03] = 0x00;
									cipher_ptr = &workConnect->server_cipher;
									encryptcopy (workConnect, &workConnect->encryptbuf[0x00], 4);
									workConnect->encryptbuf[0x00] = 0x04;
									workConnect->encryptbuf[0x01] = 0x00;
									workConnect->encryptbuf[0x02] = 0x12;
									workConnect->encryptbuf[0x03] = 0x00;
									cipher_ptr = &workConnect->server_cipher;
									encryptcopy (workConnect, &workConnect->encryptbuf[0x00], 4);
								}
								else
									change_client_folder (workConnect->s_data[workConnect->current_file], workConnect);
							}
						}
					}
				}
			}
		}
        
		FD_SET (patch_sockfd, &ReadFDs);
		nfds = max (nfds, patch_sockfd);
		FD_SET (data_sockfd, &ReadFDs);
		nfds = max (nfds, data_sockfd);
        
		/* Check sockets for activity. */
        
		if ( select ( nfds + 1, &ReadFDs, &WriteFDs, &ExceptFDs, &select_timeout ) > 0 )
		{
			if (FD_ISSET (patch_sockfd, &ReadFDs))
			{
				// Someone's attempting to connect to the patch server.
				ch = free_connection();
				if (ch != 0xFFFF)
				{
					listen_length = sizeof (listen_in);
					workConnect = connections[ch];
					if ( ( workConnect->plySockfd = tcp_accept ( patch_sockfd, (struct sockaddr*) &listen_in, &listen_length ) ) >= 0 )
					{
						workConnect->connection_index = ch;
						serverConnectionList[serverNumConnections++] = ch;
						memcpy ( &workConnect->IP_Address[0], inet_ntoa (listen_in.sin_addr), 16 );
						printf ("Accepted PATCH connection from %s:%u\n", workConnect->IP_Address, listen_in.sin_port );
						workConnect->patch = 0;
						start_encryption (workConnect);
					}
				}
			}
            
            
			if (FD_ISSET (data_sockfd, &ReadFDs))
			{
				// Someone's attempting to connect to the patch server.
				ch = free_connection();
				if (ch != 0xFFFF)
				{
					listen_length = sizeof (listen_in);
					workConnect = connections[ch];
					if ( ( workConnect->plySockfd = tcp_accept ( data_sockfd, (struct sockaddr*) &listen_in, &listen_length ) ) >= 0 )
					{
						workConnect->connection_index = ch;
						serverConnectionList[serverNumConnections++] = ch;
						memcpy ( &workConnect->IP_Address[0], inet_ntoa (listen_in.sin_addr), 16 );
						printf ("Accepted DATA connection from %s:%u\n", workConnect->IP_Address, listen_in.sin_port );
						workConnect->patch = 1;
						start_encryption (workConnect);
					}
				}
			}
            
            
			// Process client connections
            
			for (ch=0;ch<serverNumConnections;ch++)
			{
				connectNum = serverConnectionList[ch];
				workConnect = connections[connectNum];
                
				if (workConnect->plySockfd >= 0)
				{
					if (FD_ISSET(workConnect->plySockfd, &ExceptFDs)) // Exception?
						initialize_connection (workConnect);
                    
					if (FD_ISSET(workConnect->plySockfd, &ReadFDs))
					{
						// Read shit.
						if ( ( pkt_len = recv (workConnect->plySockfd, &tmprcv[0], TCP_BUFFER_SIZE - 1, 0) ) <= 0 )
						{
							/*
                             wserror = WSAGetLastError();
                             printf ("Could not read data from client...\n");
                             printf ("Socket Error %u.\n", wserror );
                             */
							initialize_connection (workConnect);
						}
						else
						{
							workConnect->fromBytesSec += (unsigned) pkt_len;
							// Work with it.
							for (pkt_c=0;pkt_c<pkt_len;pkt_c++)
							{
								workConnect->rcvbuf[workConnect->rcvread++] = tmprcv[pkt_c];
                                
								if (workConnect->rcvread == 4)
								{
									/* Decrypt the packet header after receiving 8 bytes. */
                                    
									cipher_ptr = &workConnect->client_cipher;
                                    
									decryptcopy ( &workConnect->peekbuf[0], &workConnect->rcvbuf[0], 4 );
                                    
									/* Make sure we're expecting a multiple of 8 bytes. */
                                    
									memcpy ( &workConnect->expect, &workConnect->peekbuf[0], 2 );
                                    
									if ( workConnect->expect % 4 )
										workConnect->expect += ( 4 - ( workConnect->expect % 4 ) );
                                    
									if ( workConnect->expect > TCP_BUFFER_SIZE )
									{
										initialize_connection ( workConnect );
										break;
									}
								}
                                
								if ( ( workConnect->rcvread == workConnect->expect ) && ( workConnect->expect != 0 ) )
								{
									if ( workConnect->packetdata + workConnect->expect > TCP_BUFFER_SIZE )
									{
										initialize_connection ( workConnect );
										break;
									}
									else
									{
										/* Decrypt the rest of the data if needed. */
                                        
										cipher_ptr = &workConnect->client_cipher;
                                        
										memcpy ( &workConnect->packet[workConnect->packetdata], &workConnect->peekbuf[0], 4 );
                                        
										if ( workConnect->rcvread > 4 )
											decryptcopy ( &workConnect->packet[workConnect->packetdata + 4], &workConnect->rcvbuf[4], workConnect->expect - 4 );
                                        
										memcpy ( &this_packet, &workConnect->peekbuf[0], 2 );
										workConnect->packetdata += this_packet;
                                        
										workConnect->packetsSec ++;
                                        
										workConnect->rcvread = 0;
									}
								}
							}
						}
					}
                    
					if (FD_ISSET(workConnect->plySockfd, &WriteFDs))
					{
						// Write shit
                        
						data_send = workConnect->snddata - workConnect->sndwritten;
                        
						if ((maxbytes) && (workConnect->sending_files)) // We throttling?
						{
							if ( num_sends )
								data_send /= num_sends;
                            
							if ( data_send > data_remaining )
                                data_send = data_remaining;
                            
							if ( data_send )
								data_remaining -= data_send;
						}
                        
						if ( data_send )
						{
							bytes_sent = send (workConnect->plySockfd, &workConnect->sndbuf[workConnect->sndwritten],
                                               data_send, 0);
							if (bytes_sent == SOCKET_ERROR)
							{
								/*
                                 wserror = WSAGetLastError();
                                 printf ("Could not send data to client...\n");
                                 printf ("Socket Error %u.\n", wserror );
                                 */
								initialize_connection (workConnect);
							}
							else
							{
								workConnect->sndwritten += bytes_sent;
								workConnect->toBytesSec += (unsigned) bytes_sent;
							}
                            
							if (workConnect->sndwritten == workConnect->snddata)
								workConnect->sndwritten = workConnect->snddata = 0;
                            
						}
					}
                    
					if (workConnect->todc)
						initialize_connection (workConnect);
				}
			}
		}
	}
	return 0;
}


void send_to_server(int sock, char* packet)
{
    int pktlen;
    
    pktlen = strlen (packet);
    display_packet(packet, pktlen);
    
	if (send(sock, packet, pktlen, 0) != pktlen)
	{
        printf ("send_to_server(): failure");
        exit(1);
	}
    
}

int receive_from_server(int sock, char* packet)
{
    int pktlen;
    
    if ((pktlen = recv(sock, packet, TCP_BUFFER_SIZE - 1, 0)) <= 0)
	{
        printf ("receive_from_server(): failure");
        exit(1);
	}
    packet[pktlen] = 0;
    return pktlen;
}

int tcp_accept (int sockfd, struct sockaddr *client_addr, int *addr_len )
{
	int fd;
    
	if ((fd = accept (sockfd, client_addr, addr_len)) < 0)
		debug_perror ("Could not accept connection");
    
	return (fd);
}


/*****************************************************************************
 * same as debug_perror but writes to debug output.
 * 
 *****************************************************************************/
void debug_perror( char * msg ) {
	debug( "%s : %s\n" , msg , strerror(errno) );
}
/*****************************************************************************/
void debug(char *fmt, ...)
{
#define MAX_MESG_LEN 1024
    
	va_list args;
	char text[ MAX_MESG_LEN ];
    
	va_start (args, fmt);
	strcpy (text + vsprintf( text,fmt,args), "\r\n"); 
	va_end (args);
    
	fprintf( stderr, "%s", text);
}


void decryptcopy ( void* dest, void* source, unsigned size )
{
	CRYPT_PC_CryptData(cipher_ptr,source,size);
	memcpy (dest,source,size);
}

void encryptcopy ( BANANA* client, void* source, unsigned size )
{
	unsigned char* dest;
    
	if (TCP_BUFFER_SIZE - client->snddata < ( (int) size + 7 ) )
		client->todc = 1;
	else
	{
		dest = &client->sndbuf[client->snddata];
		memcpy (dest,source,size);
		while (size % 4)
			dest[size++] = 0x00;
		client->snddata += (int) size;
        
		CRYPT_PC_CryptData(cipher_ptr,dest,size);
	}
}