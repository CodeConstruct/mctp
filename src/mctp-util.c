#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>
#include "mctp-util.h"

void mctp_hexdump(const void *b, int len, const char *indent)
{
	const char *buf = b;
	const int row_len = 16;
	int i, j;

	for (i = 0; i < len; i += row_len) {
		char hbuf[row_len * strlen("00 ") + 1];
		char cbuf[row_len + strlen("|") + 1];

		for (j = 0; (j < row_len) && ((i + j) < len); j++) {
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

int write_hex_addr(const uint8_t *data, size_t len, char *dest, size_t dest_len)
{
	size_t l;
	if (dest_len < len * 3) {
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
int parse_hex_addr(const char *in, uint8_t *out, size_t *out_len)
{
	int rc = -1;
	size_t out_pos = 0;
	while (1) {
		if (*in == '\0') {
			rc = 0;
			break;
		} else if (*in == ':') {
			in++;
			if (*in == ':' || *in == '\0' || out_pos == 0) {
				// can't have repeated ':' or ':' at start or end.
				break;
			}
		} else {
			char *endp;
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

int parse_uint32(const char *str, uint32_t *out)
{
	unsigned long v;
	char *endp;
	v = strtoul(str, &endp, 0);
	if (endp == str || *endp != '\0')
		return -EINVAL;
	if (v > UINT32_MAX)
		return -EOVERFLOW;
	*out = v;
	return 0;
}

int parse_int32(const char *str, int32_t *out)
{
	long v;
	char *endp;
	v = strtol(str, &endp, 0);
	if (endp == str || *endp != '\0')
		return -EINVAL;
	if (v > INT32_MAX || v < INT32_MIN)
		return -EOVERFLOW;
	*out = v;
	return 0;
}

/* Returns a malloced pointer */
char *bytes_to_uuid(const uint8_t u[16])
{
	char *buf = malloc(37);
	if (!buf) {
		return NULL;
	}
	snprintf(buf, 37,
		 "%02x%02x%02x%02x"
		 "-"
		 "%02x%02x"
		 "-"
		 "%02x%02x"
		 "-"
		 "%02x%02x"
		 "-"
		 "%02x%02x%02x%02x%02x%02x",
		 u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9],
		 u[10], u[11], u[12], u[13], u[14], u[15]);
	return buf;
}

bool mctp_eid_is_valid_unicast(mctp_eid_t eid)
{
	return eid >= 8 && eid < 0xff;
}
