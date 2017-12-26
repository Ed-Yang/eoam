#include <stdio.h>
#include <stdint.h>

#ifndef __XUTL_OS_H
#define __XUTL_OS_H

#ifdef __cplusplus
extern "C" {
#endif

int xos_get_mac(char *dev, char *mac);
uint32_t xos_get_uptime();
char *xos_eth_dev(void);
void xos_delay(uint32_t msec);

#ifdef __cplusplus
}
#endif

#endif /* __XUTL_OS_H */

