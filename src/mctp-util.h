#include <stdbool.h>
#include <stdint.h>

#include "mctp.h"

#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

void mctp_hexdump(const void *b, int len, const char *indent);
void print_hex_addr(const uint8_t *data, size_t len);
int write_hex_addr(const uint8_t *data, size_t len, char *dest,
		   size_t dest_len);
int parse_hex_addr(const char *in, uint8_t *out, size_t *out_len);
int parse_uint32(const char *str, uint32_t *out);
int parse_int32(const char *str, int32_t *out);
/* Returns a malloced pointer */
char *bytes_to_uuid(const uint8_t u[16]);
bool mctp_eid_is_valid_unicast(mctp_eid_t eid);
