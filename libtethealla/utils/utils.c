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

#include <stdio.h>
#include <string.h>
#include <iconv.h>

#include "utils.h"


long calculate_checksum(void* data, unsigned long size)
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

/* Converts the string pointed to by from from UTF-8 format into UTF-16LE format
 * and returns a pointer to the newly allocated buffer.
 */
const char* utf8ToUtf16LE(char *from) {
    iconv_t conv = iconv_open("UTF-16LE", "UTF-8");
    if (conv == (iconv_t)-1) {
        perror("load_config:iconv_open");
        exit(1);
    }

    size_t inbytes = (size_t) strlen(from);
    size_t outbytes = inbytes * 2, avail = outbytes;
    char *outbuf = (char*) malloc(outbytes), *outptr = outbuf;
    memset(outbuf, 0, outbytes);

    if (iconv(conv, &from, &inbytes, &outptr, &avail) == (size_t)-1) {
        perror("load_config:iconv");
        exit(1);
    }
    iconv_close(conv);

    return outbuf;
}

unsigned RleEncode(unsigned char *src, unsigned char *dest, unsigned src_size)
{
    unsigned char currChar, prevChar;             /* current and previous characters */
    unsigned short count;                /* number of characters in a run */
    unsigned src_end, dest_start;

    dest_start = (unsigned)dest;
    src_end = (unsigned)src + src_size;

    prevChar  = 0xFF - *src;

    while ((unsigned) src < src_end)
    {
        currChar = *(dest++) = *(src++);

        if ( currChar == prevChar )
        {
            if ( (unsigned) src == src_end )
            {
                *(dest++) = 0;
                *(dest++) = 0;
            }
            else
            {
                count = 0;
                while (((unsigned)src < src_end) && (count < 0xFFF0))
                {
                    if (*src == prevChar)
                    {
                        count++;
                        src++;
                        if ( (unsigned) src == src_end )
                        {
                            *(unsigned short*) dest = count;
                            dest += 2;
                        }
                    }
                    else
                    {
                        *(unsigned short*) dest = count;
                        dest += 2;
                        prevChar = 0xFF - *src;
                        break;
                    }
                }
            }
        }
        else
            prevChar = currChar;
    }
    return (unsigned)dest - dest_start;
}

void RleDecode(unsigned char *src, unsigned char *dest, unsigned src_size)
{
    unsigned char currChar, prevChar;             /* current and previous characters */
    unsigned short count;                /* number of characters in a run */
    unsigned src_end;

    src_end = (unsigned) src + src_size;

    /* decode */

    prevChar = 0xFF - *src;     /* force next char to be different */

    /* read input until there's nothing left */

    while ((unsigned) src < src_end)
    {
        currChar = *(src++);

        *(dest++) = currChar;

        /* check for run */
        if (currChar == prevChar)
        {
            /* we have a run.  write it out. */
            count = *(unsigned short*) src;
            src += 2;
            while (count > 0)
            {
                *(dest++) = currChar;
                count--;
            }

            prevChar = 0xFF - *src;     /* force next char to be different */
        }
        else
        {
            /* no run */
            prevChar = currChar;
        }
    }
}
