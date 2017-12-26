#include "oam_defs.h"
#include "eoam_mib.h"

#ifndef __EOAM_SM_H
#define __EOAM_SM_H

#ifdef __cplusplus
extern "C" {
#endif

BOOLEAN eoam_sm_init(uint32_t max_sm_ports);
BOOLEAN eoam_sm_terminate();
BOOLEAN eoam_sm_timer_handler();

BOOLEAN eoam_sm_set_mode(ifindex_s ifindex, oam_admin_e admin, oam_mode_e mode);
BOOLEAN eoam_sm_rx_packet(ifindex_s ifindex, void *packet, size_t size);
BOOLEAN eoam_sm_set_lpbk(ifindex_s ifindex, void *packet, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* __EOAM_SM_H */

