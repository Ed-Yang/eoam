#include "oam_defs.h"
#include "eoam_mib.h"


#ifndef __EOAM_COUT_H
#define __EOAM_COUT_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct eoam_dev eoam_dev_s;

/* device functions */
BOOLEAN eoam_cout_init(char *dev_name, uint8_t *dev_mac, void *dev_filter);
void eoam_cout_terminate(void);

void eoam_cout_get_pmac(ifindex_s ifindex, uint8_t *pmac);

BOOLEAN eoam_cout_link_status(ifindex_s ifindex);
BOOLEAN eoam_cout_send(ifindex_s ifindex,
                       uint8_t *buf, size_t len);
BOOLEAN eoam_cout_recv(ifindex_s *ifindex,
                       uint8_t **buf, size_t *len);
BOOLEAN eoam_cout_start_rx();
BOOLEAN eoam_cout_stop_rx();

/* statistics */
BOOLEAN eoam_cout_get_stats(ifindex_s ifindex);

/* misc state information callouts */
BOOLEAN eoam_cout_state_change(ifindex_s ifindex,
                               oam_state_e prev, oam_state_e now);
BOOLEAN eoam_cout_peer_capability(ifindex_s ifindex,
                                  uint8_t config, uint8_t state);
BOOLEAN eoam_cout_lpbk_req(ifindex_s ifindex,
                           oam_lpbk_e lpbk_status);

/**
 * eoam_cout_report_evt
 * 
 * @param cevt 
 * @return BOOLEAN 
 * @comment
 *      dot3OamEventLogRunningTotal, dot3OamEventLogEventTotal (local only)
 *      Each Event Notification TLV contains a running total of thenumber of 
 *      times an event has occurred, as well as the number of times an Event 
 *      Notification for the event has been transmitted. 
 */
BOOLEAN eoam_cout_report_evt(dot3_evt_log_s *cevt);

#ifdef __cplusplus
}
#endif

#endif /* __EOAM_COUT_H */
