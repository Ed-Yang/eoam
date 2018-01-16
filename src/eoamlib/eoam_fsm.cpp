
#include <assert.h>
#include <arpa/inet.h> /* ntohs */

#include "xutl_net.h"
#include "xutl_bits.h"
#include "xutl_os.h"

#include "xutl_bits.h"
#include "xutl_ipc.h"
#include "xutl_mem.h"

#include "eoam_mib.h"
#include "eoam_str.h"
#include "eoam_fsm.h"
#include "eoam_cout.h"
#include "eoam_pdu.h"

#include "eoam_log.h"

/**
 *--------------------------------------------------------------------------
 * globals
 *--------------------------------------------------------------------------
 */

static eoam_params_s g_fsm_init_params;

static fsm_port_s *g_fsm_port = NULL;


/**
 *--------------------------------------------------------------------------
 * local functions
 *--------------------------------------------------------------------------
 */


void fill_local_info_tlv(ifindex_s ifindex, oam_info_tlv_s *p_tlv)
{
    fsm_port_s *p;

    p = eoam_fsm_port(ifindex);

    memset(p_tlv, 0, sizeof(oam_info_tlv_s));

    p_tlv->hdr.type = INFO_TLV_TYPE_LOCAL;
    p_tlv->hdr.length = sizeof(oam_info_tlv_s); /* NOTE, one byte field */
    p_tlv->version = g_fsm_init_params.oam_version;

    p_tlv->tlv_revision = htons(p->cfg.oamConfigRevision);

    p_tlv->state = p->state; /* FIXNE */

    /* oam mode is a per-interface config */
    if (p->cfg.oamMode == OAM_MODE_ACTIVE)
        p_tlv->config |= CFG_MODE_ACTIVE;

    /* FIXME:cap */
    if (XBITS_CHECK_BIT(p->cfg.oamFunctionsSupported, UNIDIRETIONAL_SUPPORT))
        p_tlv->config |= CFG_UNIDIRECTIONAL;

    if (XBITS_CHECK_BIT(p->cfg.oamFunctionsSupported, LOOPBACK_SUPPORT) &&
        p->lpbk.oamLoopbackIgnoreRx == PROCESS_LPBK)
        p_tlv->config |= CFG_LPBK;

    /* the following (link event, lpbk, etc. is referred to global config */
    if (XBITS_CHECK_BIT(p->cfg.oamFunctionsSupported, EVENT_SUPPORT))
        p_tlv->config |= CFG_LINK_EVENTS;

    if (XBITS_CHECK_BIT(p->cfg.oamFunctionsSupported, VARIABLE_SUPPORT))
        p_tlv->config |= CFG_VAR_REQ;

#if 1 /* FIXME:lib */
    p_tlv->max_pdu_size = htons(g_fsm_init_params.max_pdu_size);
#else
    p_tlv->max_pdu_size = htons(OAM_PARAM_PDU_SIZE);
#endif

    memcpy(p_tlv->oui, g_fsm_init_params.oui, 3);
    p_tlv->vendor_spec = htonl(g_fsm_init_params.vendor_info);

    return;
}

/**
 * eoam_fsm_send_info_pdu
 * depens on current state to send info oam pdu
 */
void eoam_fsm_send_info_pdu(ifindex_s ifindex)
{
    fsm_port_s *p = eoam_fsm_port(ifindex);
    oam_info_tlv_s tlv[2];
    char buf[128];
    BOOLEAN info_sent = FALSE;

    fill_local_info_tlv(ifindex, &tlv[0]); /* TBD */

    xdbg_log(XDBG_DEBUG, "[%2d] send info pdu: %s->%s (rev:%d -%s)", ifindex,
             eoam_str_fsm_state(p->cur_state), eoam_str_fsm_state(p->cur_state),
             ntohs(tlv[0].tlv_revision),
             eoam_str_info_flags(p->send_flags, buf));

    switch (p->cur_state)
    {
    case ST_ACTIVE_SEND_LOCAL:

        eoam_pdu_send(ifindex, PDU_CODE_INFO, p->send_flags,
                      (uint8_t *)tlv, sizeof(oam_info_tlv_s));
        info_sent = TRUE;
        break;
    case ST_PASSIVE_WAIT:
        break;

    case ST_SEND_LOCAL_REMOTE:
    case ST_SEND_LOCAL_REMOTE_OK:
    case ST_SEND_ANY:

        memcpy(&tlv[1], &p->peer_tlv, sizeof(oam_info_tlv_s));

        if ((p->send_flags &
             (PDU_FLAGS_R_EVAL | PDU_FLAGS_R_STABLE)) == 0)
        {
            char buf[32];

            xdbg_log(XDBG_INFO, "[%2d] no remote send flags state: %s, flags: %s !!!",
                     ifindex,
                     eoam_str_fsm_state(p->cur_state),
                     eoam_str_info_flags(p->send_flags, buf));
        }

        eoam_pdu_send(ifindex, PDU_CODE_INFO, p->send_flags,
                      (uint8_t *)&tlv[0], sizeof(tlv));
        info_sent = TRUE;
        break;
    default:
        xdbg_log(XDBG_ERR, "[%2d] state %s not allowed to send info pdu !!",
                 ifindex, eoam_str_fsm_state(p->cur_state));
        break;
    }

    /* save local tlv and update counter */
    memcpy(&p->local_tlv, &tlv[0], sizeof(oam_info_tlv_s));

    if (info_sent)
    {
        p->stats.oamInformationTx++;
        p->mux.pdu_cnt--;
    }

    return;
}

void _set_lpbk_timer(ifindex_s ifindex, struct timeval *tv)
{
    fsm_port_s *p = eoam_fsm_port(ifindex);

    gettimeofday(tv, NULL);

    xdbg_log(XDBG_DEBUG, "[%2d] set/update lpbk timer (%s)",
             ifindex, eoam_str_lpbk_status(p->lpbk.oamLoopbackStatus));

    return;
}

/**
 * eoam_fsm_send_lpbk_pdu
 *
 */
void eoam_fsm_send_lpbk_pdu(ifindex_s ifindex, uint8_t cmd)
{
    fsm_port_s *p = eoam_fsm_port(ifindex);

#if OAM_PARAM_DROP_LPBK
    xdbg_log(XDBG_INFO, "[%2d:XX] debug drop sending lpbk pdu (%s)",
             port, (cmd == 1) ? "start" : "stop");
#else
    /* if not in send_any skip sending */
    eoam_pdu_send(ifindex, PDU_CODE_LPBK, p->send_flags,
                  (uint8_t *)&cmd, 1);
#endif

    
#if 1 /* update lpbk timer */
    _set_lpbk_timer(ifindex, &p->last_lpbk);
#else
    gettimeofday(&p->last_lpbk, NULL);
#endif

    p->stats.oamLoopbackControlTx++;
    p->mux.pdu_cnt--;

    return;
}

size_t fill_sym_period(sym_period_s *p_evt_tlv, dot3_evt_log_s *p_evtlog)
{
    p_evt_tlv->hdr.type = p_evtlog->dot3OamEventLogType;
    p_evt_tlv->hdr.length = 40;
    p_evt_tlv->timestamp = htons(xos_get_uptime() * 10);

    /* 8 8 8 8 4 */

    p_evt_tlv->window_hi = htonl(p_evtlog->dot3OamEventLogWindowHi);
    p_evt_tlv->window_lo = htonl(p_evtlog->dot3OamEventLogWindowLo);

    p_evt_tlv->threshold_hi = htonl(p_evtlog->dot3OamEventLogThresholdHi);
    p_evt_tlv->threshold_lo = htonl(p_evtlog->dot3OamEventLogThresholdLo);

    p_evt_tlv->errors_hi = htonl((p_evtlog->dot3OamEventLogValue >> 32));
    p_evt_tlv->errors_lo = htonl(p_evtlog->dot3OamEventLogValue & 0xffffffff);

    p_evt_tlv->err_total_hi = htonl(p_evtlog->dot3OamEventLogRunningTotal >> 32);
    p_evt_tlv->err_total_lo = htonl(p_evtlog->dot3OamEventLogRunningTotal & 0xffffffff);

    p_evt_tlv->evt_total = htonl(p_evtlog->dot3OamEventLogEventTotal);

    return p_evt_tlv->hdr.length + 2;
}

size_t fill_frame_period(frame_period_s *p_evt_tlv, dot3_evt_log_s *p_evtlog)
{
    p_evt_tlv->hdr.type = p_evtlog->dot3OamEventLogType;
    p_evt_tlv->hdr.length = 26;
    p_evt_tlv->timestamp = htons(xos_get_uptime() * 10);
    
    /* 2 4 4 8 4 */

    p_evt_tlv->window = htons(p_evtlog->dot3OamEventLogWindowLo);
    
    p_evt_tlv->threshold = htonl(p_evtlog->dot3OamEventLogThresholdLo);
    
    p_evt_tlv->errors = htonl(p_evtlog->dot3OamEventLogValue & 0xffffffff);
    
    p_evt_tlv->err_total_hi = htonl(p_evtlog->dot3OamEventLogRunningTotal >> 32);
    p_evt_tlv->err_total_lo = htonl(p_evtlog->dot3OamEventLogRunningTotal & 0xffffffff);

    p_evt_tlv->evt_total = htonl(p_evtlog->dot3OamEventLogEventTotal);

    return p_evt_tlv->hdr.length + 2;
}

size_t fill_err_frame(err_frame_s *p_evt_tlv, dot3_evt_log_s *p_evtlog)
{
    p_evt_tlv->hdr.type = p_evtlog->dot3OamEventLogType;
    p_evt_tlv->hdr.length = 28;
    p_evt_tlv->timestamp = htons(xos_get_uptime() * 10);
    
    /* 4 4 4 8 4 */

    p_evt_tlv->window = htonl(p_evtlog->dot3OamEventLogWindowLo);
    
    p_evt_tlv->threshold = htonl(p_evtlog->dot3OamEventLogThresholdLo);
    
    p_evt_tlv->errors = htonl(p_evtlog->dot3OamEventLogValue & 0xffffffff);
    
    p_evt_tlv->err_total_hi = htonl(p_evtlog->dot3OamEventLogRunningTotal >> 32);
    p_evt_tlv->err_total_lo = htonl(p_evtlog->dot3OamEventLogRunningTotal & 0xffffffff);

    p_evt_tlv->evt_total = htonl(p_evtlog->dot3OamEventLogEventTotal);

    return p_evt_tlv->hdr.length + 2;
}

size_t fill_frame_sec(frame_sec_s *p_evt_tlv, dot3_evt_log_s *p_evtlog)
{
    p_evt_tlv->hdr.type = p_evtlog->dot3OamEventLogType;
    p_evt_tlv->hdr.length = 18;
    p_evt_tlv->timestamp = htons(xos_get_uptime() * 10);
    
    /* 2 2 2 4 4 */

    p_evt_tlv->window = htons(p_evtlog->dot3OamEventLogWindowLo);
    
    p_evt_tlv->threshold = htons(p_evtlog->dot3OamEventLogThresholdLo);
    
    p_evt_tlv->errors = htons(p_evtlog->dot3OamEventLogValue & 0xffff);
    
    p_evt_tlv->err_total = htonl(p_evtlog->dot3OamEventLogRunningTotal & 0xffffffff);

    p_evt_tlv->evt_total = htonl(p_evtlog->dot3OamEventLogEventTotal);

    return p_evt_tlv->hdr.length + 2;
}

/**
 * eoam_fsm_send_event_pdu
 *
 *  @comment 
 * 
 *  type        1   2   3   4
 *  lenngth     40  26  28  18
 *  timestamp   2   2   2   2  
 *  window      8   2   4   2
 *  threshold   8   4   4   2
 *  err         8   4   4   2
 *  total       8   8   8   4
 *  evt total   4   4   4   4
 */
void eoam_fsm_send_event_pdu(dot3_evt_log_s *p_evtlog)
{
    ifindex_s ifindex = p_evtlog->ifindex;
    fsm_port_s *p = eoam_fsm_port(ifindex);
    oam_pdu_event_s evt_data;
    size_t dsize;

    /* fill in pdu data */
    memset(&evt_data, 0, sizeof(evt_data));

    evt_data.evt_seq = htons(p->evt_rx_seq++);

    switch (p_evtlog->dot3OamEventLogType)
    {
    case EVT_ERR_SYMBOL_PERIOD:
        dsize = fill_sym_period(&evt_data.evt_tlv.sym_prd, p_evtlog);
        break;

    case EVT_ERR_FRAME_PERIOD:
        dsize = fill_frame_period(&evt_data.evt_tlv.frame_prd, p_evtlog);
        break;

    case EVT_ERR_FRAME_EVENT:
        dsize = fill_err_frame(&evt_data.evt_tlv.frame, p_evtlog);
        break;

    case EVT_ERR_FRAME_SEC_EVENT:
        dsize = fill_frame_sec(&evt_data.evt_tlv.frame_sec, p_evtlog);
        break;
    default:
            return ;
        break;
    }

    p->stats.oamUniqueEventNotificationTx++;
    p->mux.pdu_cnt--;

    eoam_pdu_send(ifindex, PDU_CODE_EVENT, p->send_flags,
                  (uint8_t *)&evt_data, dsize);

    return;
}

static BOOLEAN eoam_fsm_lpbk_timeout(ifindex_s ifindex)
{
    fsm_port_s *p = eoam_fsm_port(ifindex);
    struct timeval cur_time;
    int diff_ms;

    if (p->lpbk.oamLoopbackStatus == NO_LPBK)
        return FALSE;

    gettimeofday(&cur_time, NULL);
    diff_ms = xnet_time_diff(&p->last_lpbk, &cur_time);

    if (diff_ms >= (int)p->lpbk.lpbk_timeout)
    {
        return TRUE;
    }

    return FALSE;
}

oam_state_e eoam_fsm_pdu_timeout(ifindex_s ifindex)
{
    fsm_port_s *p = eoam_fsm_port(ifindex);
    oam_state_e old_state;
    char zero_mac[] = {0, 0, 0, 0, 0, 0};

    if (p == NULL)
    {
        xdbg_log(XDBG_ERR, "[%2d]  pdu timer timeout: invalid port", ifindex);
        return ST_FAULT;
    }

    old_state = p->cur_state;

    xdbg_log(XDBG_DEBUG, "[%2d]  pdu timer timeout %dadmin = %d oam_mode = %d",
             ifindex, p->cfg.oamAdminState, p->cfg.oamMode);

    if (p->cfg.oamAdminState == OAM_ADMIN_DISABLED)
        return old_state;

    if (p->local_pdu == PDU_LF_INFO ||
        p->local_pdu == PDU_RX_INFO)
        return old_state;

    /* handle lpbk operation timeout */
    if (eoam_fsm_lpbk_timeout(ifindex))
    {
        /* FIXME:lpbk timeout. stop lpbk, don't re-tx lpbk command */
        xdbg_log(XDBG_INFO, "[%2d] lpbk operation timeout (%s)",
                 ifindex, eoam_str_lpbk_status(p->lpbk.oamLoopbackStatus) );

        p->state = STATE_NO_LPBK; /* local changed */
        p->lpbk.oamLoopbackStatus = NO_LPBK;
        p->cfg.oamConfigRevision++;
        eoam_cout_lpbk_req(ifindex, p->lpbk.oamLoopbackStatus); /* set lpbk */
    }

    /* handle tx keepalive */
    if (p->mux.pdu_cnt == OAM_PDU_REFRESH_CNT)
    {
        /* no any pdu went out, so tx info pdu to keep session
         * handle command retransmisstion
         */
        if (p->local_pdu >= PDU_INFO )
            eoam_fsm_send_info_pdu(ifindex);
    }
    else
    {
        xdbg_log(XDBG_TRACE, "[%2d] pdu_cnt is decreased, skip tx info pdu (%s)",
                 ifindex, eoam_str_lpbk_status(p->lpbk.oamLoopbackStatus) );
    }

    p->mux.pdu_cnt = OAM_PDU_REFRESH_CNT; /* refill tx bucket */

    /* handle rx lost link timer */

    /* process lost link timer, if has ever received peer's info pdu
     */

    if (memcmp(p->peer_mac, zero_mac, MAC_ADRS_SIZE) != 0)
    {
        struct timeval cur_time;

        gettimeofday(&cur_time, NULL);
        if (xnet_time_diff(&p->last_rx, &cur_time) >= p->cfg.oam_timeout)
        {
            xdbg_log(XDBG_INFO, "[%2d] lost link timer down (timeout %d)",
                     ifindex, p->cfg.oam_timeout);

            eoam_fsm_step(ifindex, EV_LOST_TIMER, NULL);
            /* renew timer */
            gettimeofday(&p->last_rx, NULL);
        }
    }

    return old_state;
}


/**
 *--------------------------------------------------------------------------
 * local functions - state machine
 *--------------------------------------------------------------------------
 */
static oam_state_e handle_oam_mode(ifindex_s ifindex, void *param)
{
    fsm_port_s *p = eoam_fsm_port(ifindex);
    oam_state_e next = p->cur_state;
    dot3_oam_cfg_s *p_cfg = (dot3_oam_cfg_s *) param;

    if (p_cfg->oamAdminState == OAM_ADMIN_DISABLED)
    {
        next = ST_FAULT;
    }
    else
    {
        if (p_cfg->oamMode == OAM_MODE_PASSIVE)
            next = ST_PASSIVE_WAIT;
        else
            next = ST_ACTIVE_SEND_LOCAL;
    }
    
    xdbg_log(XDBG_INFO, "[%2d] adm:%s->%s mo:%s->%s (rev %d), next=%s",
             ifindex, 
             eoam_str_onoff(p->cfg.oamAdminState), 
             eoam_str_onoff(p_cfg->oamAdminState),
             eoam_str_oam_mode(p->cfg.oamMode), 
             eoam_str_oam_mode(p_cfg->oamMode),
             p->cfg.oamConfigRevision,
             eoam_str_fsm_state(next));

    return next;
}

static oam_state_e handle_link_status(ifindex_s ifindex, void *param)
{
    oam_state_e next;
    fsm_port_s *p = eoam_fsm_port(ifindex);

    if (param) {}

    if (eoam_cout_link_status(ifindex))
    {
        if (p->cfg.oamMode == OAM_MODE_ACTIVE)
            next = ST_ACTIVE_SEND_LOCAL;
        else
            next = ST_PASSIVE_WAIT;
    }
    else
    {
        next = ST_FAULT;
    }



    return next;
}

void eoam_fsm_set_state(fsm_port_s *p, oam_state_e state)
{
    p->cur_state = state;
    
    if (p->cfg.oamAdminState == OAM_ADMIN_DISABLED)
        p->cfg.oamOperStatus = OPER_DISABLED;
    else
        p->cfg.oamOperStatus = (oam_oper_e)state;
}



static oam_state_e state_fault(ifindex_s ifindex, oam_fsm_evt_e evt, void *param)
{
    oam_state_e next = ST_FAULT;

    switch (evt)
    {
    case EV_LINK_STATUS:
    case EV_LOST_TIMER:

        next = handle_link_status(ifindex, param);

        break;
    case EV_OAM_MODE:

        next = handle_oam_mode(ifindex, param); 
        
        break;
    case EV_REMOTE_STATE_VALID:
        break;
    case EV_LOCAL_SATISFIED:
        break;
    case EV_REMOTE_STABLE:
        break;
    default:
        break;
    }

    return next;
}

static oam_state_e state_send_local(ifindex_s ifindex, oam_fsm_evt_e evt,
                                    void *param)
{
    fsm_port_s *p = eoam_fsm_port(ifindex);
    oam_state_e next = ST_ACTIVE_SEND_LOCAL;
    oam_pdu_hdr_t *p_pdu = (oam_pdu_hdr_t *)param;
    uint8_t *packet = (uint8_t *)p_pdu;

    switch (evt)
    {
    case EV_LINK_STATUS:
    case EV_LOST_TIMER:
        next = handle_link_status(ifindex, param);

        break;
    case EV_OAM_MODE:

        next = handle_oam_mode(ifindex, param);
        break;
    case EV_REMOTE_STATE_VALID:
        if (param)
        {
            /* new session, save remote mac */
            xdbg_log(XDBG_INFO, "[%2d] send local: save mac %02x:%02x:%02x:%02x:%02x:%02x",
                     ifindex, packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);

            p->remote_flags = 0; /* make fsm goto remote_valid */
            memcpy(p->peer_mac, p_pdu->sa, MAC_ADRS_SIZE);
            next = ST_SEND_LOCAL_REMOTE;
        }
        break;
    case EV_LOCAL_SATISFIED:
        break;
    case EV_REMOTE_STABLE:
        break;
    default:
        break;
    }

    return next;
}

static oam_state_e state_passive_wait(ifindex_s ifindex, oam_fsm_evt_e evt,
                                      void *param)
{
    fsm_port_s *p = eoam_fsm_port(ifindex);
    oam_state_e next = ST_PASSIVE_WAIT;
    oam_pdu_hdr_t *p_pdu = (oam_pdu_hdr_t *)param;
    uint8_t *packet = (uint8_t *)p_pdu;

    switch (evt)
    {
    case EV_LINK_STATUS:
    case EV_LOST_TIMER:
        next = handle_link_status(ifindex, param);
        break;

    case EV_OAM_MODE:
        next = handle_oam_mode(ifindex, param);
        break;

    case EV_REMOTE_STATE_VALID:
        if (param)
        {
            /* new session, save remote mac */
            xdbg_log(XDBG_INFO, "[%2d] passive wait: save mac %02x:%02x:%02x:%02x:%02x:%02x",
                     ifindex, packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);

            p->remote_flags = 0; /* make fsm goto remote_valid */
            memcpy(p->peer_mac, p_pdu->sa, MAC_ADRS_SIZE);
            next = ST_SEND_LOCAL_REMOTE;
        }
        break;

    case EV_LOCAL_SATISFIED:
        break;

    case EV_REMOTE_STABLE:
        break;

    default:
        break;
    }

    return next;
}

static oam_state_e state_send_local_remote(ifindex_s ifindex, oam_fsm_evt_e evt,
                                           void *param)
{
    fsm_port_s *p = eoam_fsm_port(ifindex);
    oam_state_e next = ST_SEND_LOCAL_REMOTE;

    switch (evt)
    {
    case EV_LINK_STATUS:
    case EV_LOST_TIMER:
        next = handle_link_status(ifindex, param);
        break;

    case EV_OAM_MODE:
        next = handle_oam_mode(ifindex, param);
        break;

    case EV_REMOTE_STATE_VALID:
        next = ST_SEND_LOCAL_REMOTE;
        break;

    case EV_LOCAL_SATISFIED:
        if (param)
        {
            p->local_stable = TRUE;
            next = ST_SEND_LOCAL_REMOTE_OK;
        }
        else
        {
            if (p->cfg.oamMode == OAM_MODE_PASSIVE)
                next = ST_PASSIVE_WAIT; 
        }
        break;

    case EV_REMOTE_STABLE:
        break;

    default:
        break;
    }

    return next;
}

static oam_state_e state_send_local_remote_ok(ifindex_s ifindex, oam_fsm_evt_e evt,
                                              void *param)
{
    fsm_port_s *p = eoam_fsm_port(ifindex);
    oam_state_e next = ST_SEND_LOCAL_REMOTE_OK;

    switch (evt)
    {
    case EV_LINK_STATUS:
    case EV_LOST_TIMER:
        next = handle_link_status(ifindex, param);
        break;

    case EV_OAM_MODE:
        next = handle_oam_mode(ifindex, param);
        break;

    case EV_REMOTE_STATE_VALID:
        next = ST_SEND_LOCAL_REMOTE;
        break;

    case EV_LOCAL_SATISFIED:
        if (param)
        {
            p->local_stable = TRUE;
            next = ST_SEND_LOCAL_REMOTE_OK;
        }
        else
        {
            p->local_stable = FALSE;
            if (p->cfg.oamMode == OAM_MODE_PASSIVE)
                next = ST_PASSIVE_WAIT; 
            else        
                next = ST_SEND_LOCAL_REMOTE;    
        }

        break;

    case EV_REMOTE_STABLE:
        next = ST_SEND_ANY;
        break;

    default:
        break;
    }

    return next;
}

static oam_state_e state_send_any(ifindex_s ifindex, oam_fsm_evt_e evt, void *param)
{
    fsm_port_s *p = eoam_fsm_port(ifindex);
    oam_state_e next = ST_SEND_ANY;

    switch (evt)
    {
    case EV_LINK_STATUS:
    case EV_LOST_TIMER:
        next = handle_link_status(ifindex, param);

        break;
    case EV_OAM_MODE:

        next = handle_oam_mode(ifindex, param);
        break;
    case EV_REMOTE_STATE_VALID:
        p->local_stable = FALSE;
        next = ST_SEND_LOCAL_REMOTE;
        break;

    case EV_LOCAL_SATISFIED:
        if (param)
        {
            p->local_stable = TRUE;
            next = ST_SEND_LOCAL_REMOTE_OK;
        }
        else
        {
            p->local_stable = FALSE;
            if (p->cfg.oamMode == OAM_MODE_PASSIVE)
                next = ST_PASSIVE_WAIT; 
            else        
                next = ST_SEND_LOCAL_REMOTE;    
        }
        break;

    case EV_REMOTE_STABLE:
        if (param)
            next = ST_SEND_ANY;
        else
            next = ST_SEND_LOCAL_REMOTE_OK;
        break;
        
    default:
        break;
    }

    return next;
}

void eoam_transit_state(ifindex_s ifindex, oam_state_e next_state)
{
    fsm_port_s *p = eoam_fsm_port(ifindex);

    switch (next_state)
    {
    case ST_FAULT:
        if (eoam_cout_link_status(ifindex))
            p->local_pdu = PDU_RX_INFO;
        else
            p->local_pdu = PDU_LF_INFO;

#if 1 /* FIXME:valid */
        p->local_stable = FALSE;
        PDU_FLAGS_R_CLEAR(p->send_flags);
        p->remote_flags = 0;
        memset(&p->peer_mac, 0, sizeof(p->peer_mac));
#endif

        break;

    case ST_ACTIVE_SEND_LOCAL:
        PDU_FLAGS_R_CLEAR(p->send_flags);
        PDU_FLAGS_L_SETV(p->send_flags, PDU_FLAGS_L_EVAL);

        p->local_pdu = PDU_INFO;

#if 1 /* FIXME:valid */
        p->local_stable = FALSE;
        p->remote_flags = 0;
        memset(&p->peer_mac, 0, sizeof(p->peer_mac));
#endif

        break;

    case ST_PASSIVE_WAIT:
#if 1 /* FIXME:valid */
        PDU_FLAGS_R_CLEAR(p->send_flags);
        p->local_pdu = PDU_RX_INFO;
        p->local_stable = FALSE;
        p->remote_flags = 0;
        memset(&p->peer_mac, 0, sizeof(p->peer_mac));
#endif
        break;

    case ST_SEND_LOCAL_REMOTE:
        PDU_FLAGS_L_SETV(p->send_flags, PDU_FLAGS_L_EVAL);
        p->local_pdu = PDU_INFO;
        p->local_stable = FALSE;
        break;

    case ST_SEND_LOCAL_REMOTE_OK:
        PDU_FLAGS_L_SETV(p->send_flags, PDU_FLAGS_L_STABLE);
        p->local_stable = TRUE;

        break;

    case ST_SEND_ANY:
        PDU_FLAGS_L_SETV(p->send_flags, PDU_FLAGS_L_STABLE);
        p->local_pdu = PDU_ANY;


        break;

    default:
        break;
    }

    eoam_fsm_set_state(p, next_state);
}

/**
 *--------------------------------------------------------------------------
 * public functions
 *--------------------------------------------------------------------------
 */
BOOLEAN eoam_fsm_init(eoam_params_s *oam_params)
{
    BOOLEAN retval ;
    void *filter = NULL;

    eoam_fsm_set_params(oam_params);

    eoam_log_init(oam_params->log_table_size);

    /* start low layer packet capture */
    if (oam_params->filter_flag)
        filter = oam_params->dev_filter;

    retval = eoam_cout_init((char *)oam_params->dev_name,
                oam_params->dev_mac, filter);

    if (retval == FALSE)
        return FALSE;

    return TRUE;
}

BOOLEAN eoam_fsm_terminate(void)
{
    /* stop low layer packet capture */
    xdbg_log(XDBG_INFO, "eoam_fsm_terminate: stop dev");
    eoam_cout_stop_rx();

    xdbg_log(XDBG_INFO, "eoam_fsm_terminate: terminate ipc");
    eoam_xipc_terminate(); /* FIXME:init order */

    /* clost deve in final step */
    xdbg_log(XDBG_INFO, "eoam_fsm_terminate: close dev");
    eoam_cout_terminate();

    xdbg_log(XDBG_INFO, "eoam_fsm_terminate: close log");
    eoam_log_terminate();

#if 1 /* FIXNE:lib */
    if (g_fsm_port != NULL)
    {
        xmem_free(g_fsm_port, sizeof(fsm_port_s) * (g_fsm_init_params.max_oam_ports+1));
    }
#endif
    
    return TRUE;
}

BOOLEAN eoam_fsm_quit(void)
{
    /* stop low layer packet capture */
    xdbg_log(XDBG_INFO, "eoam_fsm_quit: stop dev");
    eoam_cout_stop_rx();

    return TRUE;
}

void eoam_fsm_usr_init(void *xnet, void *param)
{
    ifindex_s ifindex;
    dot3_oam_cfg_s cfg;
    eoam_params_s oam_params;

    if (xnet == NULL)
    {
        xdbg_log(XDBG_ERR, "eoam_fsm_usr_init: xnet is NULL !!!");
    }

    if (param) {}

    xdbg_log(XDBG_INFO, "eoam_fsm_usr_init: init interfaces");

    eoam_fsm_get_params(&oam_params);

    /* init port state */
    memset(&cfg, 0, sizeof(cfg));
    cfg.oamAdminState = oam_params.admin_state;
    cfg.oamMode = oam_params.oam_mode;

    for (ifindex = 1; ifindex <= eoam_max_ports(); ifindex++)
    {
        cfg.ifindex = ifindex;
        eoam_fsm_step(ifindex, EV_LINK_STATUS, &cfg);
    }

    return ;
}


void *eoam_fsm_loop(void *param)
{
    if (param) {}

    eoam_xipc_init(g_fsm_init_params.pkt_sock_path, g_fsm_init_params.cfg_sock_path);

    eoam_cout_start_rx();

    return NULL;
}

inline uint32_t eoam_max_ports(void)
{
    if (g_fsm_port == NULL)
    {
        return 0;
    }
    
    return g_fsm_init_params.max_oam_ports;
}

/**
 * eoam_fsm_port
 * FIXME, sould hide the internal data from other
 */
fsm_port_s *eoam_fsm_port(ifindex_s ifindex)
{
    if (ifindex == 0 || ifindex > eoam_max_ports())
        return NULL;

    return &g_fsm_port[ifindex];
}

oam_state_e eoam_fsm_step(ifindex_s ifindex, oam_fsm_evt_e evt, void *param)
{
    fsm_port_s *p = eoam_fsm_port(ifindex);
    oam_state_e cur_state = p->cur_state;
    oam_state_e next = cur_state;

#if FSM_DEBUG
    xdbg_log(XDBG_DEBUG, "step [%2d] state: %s, event: %s", ifindex,
             eoam_str_fsm_state(cur_state),
             eoam_str_events(evt));
#endif

    switch (cur_state)
    {
    case ST_FAULT:
        next = state_fault(ifindex, evt, param);
        break;
    case ST_ACTIVE_SEND_LOCAL:
        next = state_send_local(ifindex, evt, param);
        break;
    case ST_PASSIVE_WAIT:
        next = state_passive_wait(ifindex, evt, param);
        break;
    case ST_SEND_LOCAL_REMOTE:
        next = state_send_local_remote(ifindex, evt, param);
        break;
    case ST_SEND_LOCAL_REMOTE_OK:
        next = state_send_local_remote_ok(ifindex, evt, param);
        break;
    case ST_SEND_ANY:
        next = state_send_any(ifindex, evt, param);
        break;
    default:
        xdbg_log(XDBG_ERR, "[%02d] invalid state %s", ifindex,
                 eoam_str_fsm_state(cur_state));
        break;
    }

    eoam_transit_state(ifindex, next);

    if (cur_state != next)
    {
        xdbg_log(XDBG_DEBUG, "transit [%02d] %s :%s --> %s", ifindex, eoam_str_events(evt),
                 eoam_str_fsm_state(cur_state), eoam_str_fsm_state(next));

        eoam_cout_state_change(ifindex, cur_state, next);

#if 0 /* FIXME:valid */
        if (next == ST_ACTIVE_SEND_LOCAL)
            eoam_fsm_send_info_pdu(ifindex);
#endif
    }

    return next;
}

static void fsm_port_init_params(eoam_params_s *oam_params)
{
    ifindex_s ifindex;
    fsm_port_s *p;
    
    if (oam_params == NULL)
        return ;

    for (ifindex = 1; ifindex <= eoam_max_ports(); ifindex++)
    {
        p = eoam_fsm_port(ifindex);

        /* port mac (must call after system parameters is set) */
        eoam_cout_get_pmac(ifindex, (uint8_t *)p->pmac);

        /* fsm */
        eoam_fsm_set_state(p, ST_FAULT);

        /* oam cfg */
        p->cfg.ifindex = ifindex;
        p->cfg.oamAdminState = oam_params->admin_state;
        p->cfg.oamOperStatus = OPER_LINK_FAULT;
        p->cfg.oamMode = oam_params->oam_mode;
        p->cfg.oamMaxOamPduSize = oam_params->max_pdu_size;
        p->cfg.oam_timeout = oam_params->oam_timeout;

        /* FIXME:func */
        if (oam_params->support_unidirectional)
            XBITS_SET_BIT(p->cfg.oamFunctionsSupported, UNIDIRETIONAL_SUPPORT);

        /* FIXME:func oamFunctionsSupported is read-only, it can change ignore-rx to
         * disable loopback
         */
        if (oam_params->support_lpbk)
            XBITS_SET_BIT(p->cfg.oamFunctionsSupported, LOOPBACK_SUPPORT);

        if (oam_params->support_link_event)
            XBITS_SET_BIT(p->cfg.oamFunctionsSupported, EVENT_SUPPORT);

        if (oam_params->support_var_retrieval)
            XBITS_SET_BIT(p->cfg.oamFunctionsSupported, VARIABLE_SUPPORT);

        /* lpbk */
        p->lpbk.ifindex = ifindex;
        p->lpbk.oamLoopbackStatus = NO_LPBK;
        p->lpbk.oamLoopbackIgnoreRx = oam_params->rx_mode;
        
        p->lpbk.lpbk_timeout = oam_params->lpbk_timeout;
        
        /* events */
        memset(&p->evt_cfg, 0, sizeof(p->evt_cfg));
        p->evt_cfg.ifindex = ifindex;

        /* error symbol period */
        p->evt_cfg.dot3OamErrSymPeriodWindowLo = 1000; /* FIXME (symboles link) */
        p->evt_cfg.dot3OamErrSymPeriodThresholdLo = 1;
        p->evt_cfg.dot3OamErrSymPeriodEvNotifEnable = MIB_TRUE;

        /* error frame period */
        p->evt_cfg.dot3OamErrFramePeriodWindow = 1000; /* FIXME (64B link) */
        p->evt_cfg.dot3OamErrFramePeriodThreshold = 1;
        p->evt_cfg.dot3OamErrFramePeriodEvNotifEnable = MIB_TRUE;

        /* error frame event */
        p->evt_cfg.dot3OamErrFrameWindow = 10; /* FIXME (1s) */
        p->evt_cfg.dot3OamErrFrameThreshold = 1;
        p->evt_cfg.dot3OamErrFrameEvNotifEnable = MIB_TRUE;

        /* error frame summary */
        p->evt_cfg.dot3OamErrFrameSecsSummaryWindow = 100; /* FIXME (10s) */
        p->evt_cfg.dot3OamErrFrameSecsSummaryThreshold = 1;
        p->evt_cfg.dot3OamErrFrameSecsEvNotifEnable = MIB_TRUE;

        /* critical events (link failure is not configurable) */
        p->evt_cfg.dot3OamDyingGaspEnable = MIB_TRUE;
        p->evt_cfg.dot3OamCriticalEventEnable = MIB_TRUE;

        /* extension */
        p->evt_cfg.dot3OamLinkFaultStatus = MIB_FALSE;
        p->evt_cfg.dot3OamDyingGaspStatus = MIB_FALSE;
        p->evt_cfg.dot3OamCriticalEventStatus = MIB_FALSE;
    }
}

/**
 * eoam_fsm_set_params
 *
 * these parameters are feature flags of oam protocol and not provided
 * to change after initialization.
 */
BOOLEAN eoam_fsm_set_params(eoam_params_s *oam_params)
{
    if (oam_params == NULL)
        return FALSE;

    /* this user must call this once and only once. */
    if (g_fsm_port != NULL)
    {
        xdbg_log(XDBG_ERR, "eoam_fsm_set_params: duplicate init failed !!!");
        return FALSE;
    }

    memcpy(&g_fsm_init_params, oam_params, sizeof(eoam_params_s));

    g_fsm_port = (fsm_port_s *)xmem_malloc(sizeof(fsm_port_s) * (g_fsm_init_params.max_oam_ports+1));
    memset(g_fsm_port, 0, sizeof(fsm_port_s) * (g_fsm_init_params.max_oam_ports+1));
    
    fsm_port_init_params(oam_params);

    return TRUE;
}

BOOLEAN eoam_fsm_get_params(eoam_params_s *oam_params)
{
    if (oam_params == NULL)
        return FALSE;

    memcpy(oam_params, &g_fsm_init_params, sizeof(eoam_params_s));

    return TRUE;
}

