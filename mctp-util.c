#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>

#include "mctp-util.h"

void mctp_hexdump(void *b, int len, const char *indent) {
    char* buf = b;
    const int row_len = 16;
    int i, j;

    for (i = 0; i < len; i += row_len) {
        char hbuf[row_len * strlen("00 ") + 1];
        char cbuf[row_len + strlen("|") + 1];

        for (j = 0; (j < row_len) && ((i+j) < len); j++) {
            unsigned char c = buf[i + j];

            sprintf(hbuf + j * 3, "%02x ", c);

            if (!isprint(c))
                c = '.';

            sprintf(cbuf + j, "%c", c);
        }

        strcat(cbuf, "|");

        printf("%s%08x  %*s |%s\n", indent, i,
                (int)(0 - sizeof(hbuf) + 1), hbuf, cbuf);
    }
}

void print_hex_addr(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (i > 0) {
            putchar(':');
        }
        printf("%02x", data[i]);
    }
}

int write_hex_addr(const uint8_t *data, size_t len, char* dest, size_t dest_len)
{
    size_t l;
    if (dest_len < len*3) {
        snprintf(dest, dest_len, "XXXX");
        return -EINVAL;
    }

    dest[0] = '\0';
    for (size_t i = 0; i < len; i++) {
        if (i > 0) {
            l = snprintf(dest, dest_len, ":");
            if (l >= dest_len)
                return -EPROTO;
            dest_len -= l;
            dest += l;
        }
        l = snprintf(dest, dest_len, "%02x", data[i]);
        if (l >= dest_len)
            return -EPROTO;
        dest_len -= l;
        dest += l;
    }
    return 0;
}

// Accepts colon separated hex bytes
int parse_hex_addr(const char* in, uint8_t *out, size_t *out_len)
{
    int rc = -1;
    size_t out_pos = 0;
    while (1) {
        if (*in == '\0') {
            rc = 0;
            break;
        }
        else if (*in == ':') {
            in++;
            if (*in == ':' || *in == '\0' || out_pos == 0) {
                // can't have repeated ':' or ':' at start or end.
                break;
            }
        } else {
            char* endp;
            int tmp;
            tmp = strtoul(in, &endp, 16);
            if (endp == in || tmp > 0xff) {
                break;
            }
            if (out_pos >= *out_len) {
                break;
            }
            *out = tmp & 0xff;
            out++;
            out_pos++;
            in = endp;
        }
    }

    if (rc) {
        *out_len = 0;
    } else {
        *out_len = out_pos;
    }
    return rc;
}

