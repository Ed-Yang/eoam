
#include <stdio.h>
#include <stdint.h>
#include <pthread.h>

#include "oam_defs.h"
#include "oam_tlv.h"
#include "eoam_mib.h"
#include "eoam_xipc.h"


#ifndef __EOAM_FSM_H
#define __EOAM_FSM_H

#ifdef __cplusplus
extern "C" {
#endif

#define FSM_DEBUG   1

typedef enum
{
    EV_LINK_STATUS,
    EV_OAM_MODE,
    EV_REMOTE_STATE_VALID,
    EV_LOCAL_SATISFIED,
    EV_REMOTE_STABLE
} oam_fsm_evt_e;

typedef struct
{
    /* TURE to indicate the rising of critical events */
    BOOLEAN local_link_status;
    BOOLEAN local_dying_gasp;
    BOOLEAN local_critical_event;
} oam_port_cevt_t;

typedef struct
{
    /* transmit state machine */
    BOOLEAN pdu_timer_done; /* start on oam_enable, and run periodically */
    uint8_t pdu_cnt; /* default: OAM_PDU_REFRESH_CNT */
} oam_port_mux_s;

typedef struct
{
    oam_gauge64_s err_run_total;
    uint32_t err_evt_total;
} oam_evt_sum_s;


/**
 *  @param last_lpbk update when:
 *  active
 *      - (X) send lpbk pdu <-- no need
 *      - rx STATE_LCL_LPBK flag
 *  passive
 *      - rx STATE_RMT_LPBK flag
 */
typedef struct fsm_port
{
    /* variable of state machine */
    oam_state_e cur_state;
    dot3_oam_cfg_s cfg;
    dot3_lpbk_cfg_s lpbk;
    dot3_peer_s peer;
    BOOLEAN remote_state_valid;
    char pmac[MAC_ADRS_SIZE];
    BOOLEAN local_satisfied;
    BOOLEAN local_stable;
    BOOLEAN remote_stable;

    uint8_t send_flags; /* FIXME */
    /* mux: // STATE_MUX_FWD, STATE_MUX_DISCARD
     * par: STATE_PAR_FWD, STATE_PAR_LPBK, STATE_PAR_DISCARD
     */
    uint8_t state; /* par: 0-1, mux: 2 */
    uint8_t local_pdu;
    struct timeval last_rx;

    /* last_lpbk: if the peer exit loopback mode, we shall stop loopback also */
    struct timeval last_lpbk; /* FIXME:lpbk last tx lpbk pdu */

    /* info tlv cache */

    oam_pdu_info_t local_tlv;
    oam_pdu_info_t peer_tlv; /* remote - valid only if disc.remote_valid is TRUE */
    uint8_t remote_flags; /* peer's flags */

    oam_port_mux_s mux;

    /* counters */
    dot3_oam_stats_s stats;

    /* event */
    dot3_evt_cfg_s evt_cfg;
    uint16_t evt_rx_seq; /* record the last received sequence number */
    uint16_t evt_tx_seq; /* event pdu */
    oam_evt_sum_s link_evt_sum[4]; /* accumulative link event counters */
    oam_evt_sum_s c_evt_sum[3]; /* accumulative critical event counters */
} fsm_port_s;

typedef struct
{
    char dev_name[OAM_MAX_STR_LEN+1];
    BOOLEAN filter_flag; /* if filter_flag is TRUE, dev_filter is valid */
    char dev_filter[OAM_MAX_STR_LEN+1];
    uint32_t max_oam_ports;
    char pkt_sock_path[OAM_MAX_STR_LEN+1];
    char cfg_sock_path[OAM_MAX_STR_LEN+1];
    oam_admin_e admin_state; /* mib */
    dot3_rx_lpbk_e rx_mode;  /* mib */

    uint32_t oam_timeout; /* in ms, cisco 2~30s */
    uint32_t lpbk_timeout; /* in ms, cisco 1~10s */

    /* info tlv */
    uint8_t oam_version;
    oam_mode_e oam_mode; /* oam config */
    BOOLEAN support_unidirectional; /* oam config */
    BOOLEAN support_lpbk; /* oam config */
    BOOLEAN support_link_event; /* oam config */
    BOOLEAN support_var_retrieval; /* oam config */
    uint16_t max_pdu_size; /* oam config */
    uint8_t dev_mac[MAC_ADRS_SIZE]; 
    uint8_t oui[3]; /* oui */
    uint32_t vendor_info;/* vendor specific info */
    uint16_t log_table_size; /* maxinmum number of log entries */
} eoam_params_s;


/* init */
BOOLEAN eoam_fsm_init(eoam_params_s *oam_params);
BOOLEAN eoam_fsm_terminate(void);
BOOLEAN eoam_fsm_quit(void);
void *eoam_fsm_loop(void *);

/* protocol parameters */
BOOLEAN eoam_fsm_set_params(eoam_params_s *oam_params);
BOOLEAN eoam_fsm_get_params(eoam_params_s *oam_params);

uint32_t eoam_max_ports(void);
fsm_port_s *eoam_fsm_port(ifindex_s ifindex);


/* transit fsm */
oam_state_e eoam_fsm_step(ifindex_s ifindex, oam_fsm_evt_e evt, void *param);

/* eoam_xipc xnet user init */
void eoam_fsm_usr_init(void *xnet, void *param);

/* for eoam_timer */
oam_state_e eoam_fsm_pdu_timeout(ifindex_s ifindex);

/* fsm send pdu */
void eoam_fsm_send_info_pdu(ifindex_s ifindex, oam_state_e next_state);
void eoam_fsm_send_lpbk_pdu(ifindex_s ifindex, uint8_t cmd);
void eoam_fsm_send_event_pdu(dot3_evt_log_s *p_evtlog);

#ifdef __cplusplus
}
#endif

#endif /* __EOAM_FSM_H */

