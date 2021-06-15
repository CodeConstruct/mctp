#include <stdint.h>

void mctp_hexdump(void *b, int len, const char *indent);
void print_hex_addr(const uint8_t *data, size_t len);
int write_hex_addr(const uint8_t *data, size_t len, char* dest, size_t dest_len);
int parse_hex_addr(const char* in, uint8_t *out, size_t *out_len);
int parse_uint32(const char *str, uint32_t *out);
int parse_int32(const char *str, int32_t *out);
