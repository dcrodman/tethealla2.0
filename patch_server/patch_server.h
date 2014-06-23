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

#ifndef __tethealla2_0__patch_server__
#define __tethealla2_0__patch_server__

#include <iostream>
#include <sys/socket.h>
#include <list>

extern "C" {
    #include "encryption.h"
    #include "sniffex.h"
}

const int TCP_BUFFER_SIZE = 65530;

enum server {
    PATCH,
    DATA
};

/* Structure for holding the configuration data specified by the user. */
struct patch_config {
    char *serverIPStr;
    uint32_t serverIP;
    char *patch_port;
    char *data_port;

    char *patch_directory;
    bool enable_ipv6;

    char *welcome_message;
    uint32_t welcome_size;
};

/* Patch information associated with each file in the patches directory. */
struct patch_file {
    char filename[NAME_MAX];
    char relative_path[PATH_MAX + NAME_MAX];
    char full_path[PATH_MAX + NAME_MAX];
    uint32_t file_size;
    uint32_t checksum;
    uint32_t index;
    // Depth of enclosing folder relative to patches (and thus psobb) directory.
    int patch_steps;
    // Array containing the path directory components of the file.
    char **path_dirs;
};

/* Structure for representing connected clients. */
struct patch_client {
    int socket;
    int port;
    bool ipv6;
    server session;

    char* ip_addr_str;
    sockaddr_storage ip_addr;
    
    CRYPT_SETUP client_cipher;
    CRYPT_SETUP server_cipher;
    
    unsigned char send_buffer[TCP_BUFFER_SIZE];
    unsigned int send_size;

    unsigned char recv_buffer[TCP_BUFFER_SIZE];
    unsigned int recv_size;
    unsigned int packet_sz;

    int dir_steps;
    std::list<patch_file*> *patch_list;
    bool sending_files;
    uint32_t cur_chunk;
    uint32_t patch_sent;

    bool disconnected;
};

#endif
