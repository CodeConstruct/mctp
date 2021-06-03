#include <stdint.h>

void mctp_hexdump(void *b, int len, const char *indent);
void print_hex_addr(const uint8_t *data, size_t len);
int parse_hex_addr(const char* in, uint8_t *out, size_t *out_len);
