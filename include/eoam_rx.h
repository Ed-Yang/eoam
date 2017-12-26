#include "oam_defs.h"

#ifndef __EOAM_RX_H
#define __EOAM_RX_H

#ifdef __cplusplus
extern "C" {
#endif

BOOLEAN eoam_rx_init(char *xipc_path);
BOOLEAN eoam_rx_terminate(void);
BOOLEAN eoam_rx_indication(ifindex_s ifindex, const uint8_t *packet, size_t length);

#ifdef __cplusplus
}
#endif

#endif /* __EOAM_RX_H */

