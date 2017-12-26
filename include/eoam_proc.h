#include "oam_defs.h"
#include "eoam_mib.h"

#ifndef __EOAM_PROC_H
#define __EOAM_PROC_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * pdu indications
 */
oam_err_e eoam_proc_info_pdu_indication(ifindex_s ifindex,
                                       oam_pdu_hdr_t *p_pdu, size_t pdu_size);
oam_err_e eoam_proc_lpbk_pdu_indication(ifindex_s ifindex,
                                       oam_pdu_hdr_t *p_pdu, size_t pdu_size);
oam_err_e eoam_proc_evt_pdu_indication(ifindex_s ifindex,
                                      oam_pdu_hdr_t *p_pdu, size_t pdu_size);
oam_err_e eoam_proc_other_pdu_indication(ifindex_s ifindex,
                                        oam_pdu_hdr_t *p_pdu, size_t pdu_size);

/*
 * process client reqeust
 */

/* port config */
oam_err_e eoam_proc_set_port_cfg(dot3_oam_cfg_s *oam_cfg);
oam_err_e eoam_proc_get_port_cfg(dot3_oam_cfg_s *oam_cfg);

/* peer table */
oam_err_e eoam_proc_get_peer(dot3_peer_s *peer_info);

/* loopback cnotrol */
oam_err_e eoam_proc_set_lpbk(dot3_lpbk_cfg_s *lpbk_cfg);
oam_err_e eoam_proc_get_lpbk(dot3_lpbk_cfg_s *lpbk_cfg);

/* statistics */
oam_err_e eoam_proc_get_stats(dot3_oam_stats_s *stats);
oam_err_e eoam_proc_clear_stats(ifindex_s ifindex);

/* generate oam events and log */
oam_err_e eoam_proc_report_event(eoam_rpt_evt_s *p_rpt);

/* events */
oam_err_e eoam_proc_set_evt_cfg(dot3_evt_cfg_s *p_evtcfg);
oam_err_e eoam_proc_get_evt_cfg(dot3_evt_cfg_s *p_evtcfg);

oam_err_e eoam_proc_quit(uint32_t dummy);
oam_err_e eoam_proc_debug(uint32_t priority);


#ifdef __cplusplus
}
#endif

#endif /* __EOAM_PROC_H */

