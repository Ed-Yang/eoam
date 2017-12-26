#include <stdio.h>
#include <stdint.h>

#ifndef __XUTL_STR_H
#define __XUTL_STR_H

#ifdef __cplusplus
extern "C" {
#endif

int xstr_hex2bin(uint8_t *dst_bin, const char *hexstr, size_t hsize);
char *xstr_bin2hex(char *dst_hex, const uint8_t *bin, size_t bsize);
void xstr_dump(const uint8_t *bin, size_t bsize, size_t column);
int xstr_ipstr(char *ip_str, int buf_size, const char *ip);

#ifdef __cplusplus
}
#endif

#endif /* __XUTL_STR_H */

