#include <arpa/inet.h>

#include "xutl_dbg.h"
#include "xutl_bits.h"
#include "xutl_os.h"
#include "eoam_mib.h"
#include "eoam_fsm.h"
#include "eoam_log.h"
#include "eoam_cout.h"
#include "eoam_str.h"
#include "eoam_proc.h"

/*--------------------------------------------------------------------------
 * local functions
 *--------------------------------------------------------------------------
 */
/** 
 * _locate_info_tlv
 *
 */
static BOOLEAN _locate_info_tlv(oam_pdu_hdr_t *p_pdu, size_t pdu_size,
                          oam_info_tlv_s **peer_local,
                          oam_info_tlv_s **peer_remote)
{
    oam_info_tlv_s *p_tlv;
    int total;
    BOOLEAN retval = FALSE;

    *peer_local = NULL;
    *peer_remote = NULL;

    /* locate local and remote tlv */
    p_tlv = (oam_info_tlv_s *)(p_pdu + 1);
    total = (int)(pdu_size - sizeof(oam_pdu_hdr_t));

    while (p_tlv->hdr.type != INFO_TLV_TYPE_END && total > 0 &&
           p_tlv->hdr.length == 16)
    {
        /* accept only one local and one remote */
        switch (p_tlv->hdr.type)
        {
        case INFO_TLV_TYPE_LOCAL: /* my.remote == peer.local ?? */

            *peer_local = p_tlv;
            retval = TRUE;
            break;

        case INFO_TLV_TYPE_REMOTE: /* my.local == peer.remote ?? */

            /* only accept peer_remote with my oui
             * FIXME:loc
             * if (memcmp(p_tlv->oui, g_sys_mac, 3) == 0)
             */
            *peer_remote = p_tlv;
            break;
        default:
            break;
        }

        total -= p_tlv->hdr.length;
        p_tlv++;
    }

    return retval;
}

/**
 * check_peer_response
 *
 * FIXME:lpbk
 */
void check_peer_response(ifindex_s ifindex, oam_info_tlv_s *p_tlv)
{
    fsm_port_s *p = eoam_fsm_port(ifindex);

    if (p->cur_state != ST_SEND_ANY)
        return;

    /* config change (oam mode) */

    /* state change (par or mux) */
    switch(p->lpbk.oamLoopbackStatus)
    {
    case INIT_LPBK:
        if (p_tlv->state == STATE_LCL_LPBK)
        {
            xdbg_log(XDBG_DEBUG, "[%2d] peer enter local loopback, loopbcak started",
                     ifindex);

            p->state = STATE_RMT_LPBK;
            p->lpbk.oamLoopbackStatus = REMOTE_LPBK;

            p->cfg.oamConfigRevision++; /* state changed, inc rev */
            
            eoam_cout_lpbk_req(ifindex, p->lpbk.oamLoopbackStatus); /* FIXME:lpbk */
        }
        break;
    case TERM_LPBK:
        if (p_tlv->state == STATE_NO_LPBK)
        {
            xdbg_log(XDBG_DEBUG, "[%2d] peer leave local loopback, loopbcak stopped",
                     ifindex);

            p->state = STATE_NO_LPBK; /* remote changed */
            p->lpbk.oamLoopbackStatus = NO_LPBK;

            p->cfg.oamConfigRevision++; /* state changed, inc rev */
            
            eoam_cout_lpbk_req(ifindex, p->lpbk.oamLoopbackStatus); /* set lpbk */
        }
        break;

    default:
        break;
    }
}

void _update_lpbk_timer(ifindex_s ifindex, struct timeval *tv)
{
    fsm_port_s *p = eoam_fsm_port(ifindex);

    gettimeofday(tv, NULL);

    xdbg_log(XDBG_DEBUG, "[%2d] update lpbk timer (%s)",
             ifindex, eoam_str_lpbk_status(p->lpbk.oamLoopbackStatus));

    return;
}

static void _refresh_lpbk_timer(ifindex_s ifindex, oam_info_tlv_s *p_tlv)
{
    fsm_port_s *p = eoam_fsm_port(ifindex);

    xdbg_log(XDBG_DEBUG, "[%2d] refresh lpbk timer (%s)",
             ifindex, eoam_str_lpbk_status(p->lpbk.oamLoopbackStatus));

    switch(p->lpbk.oamLoopbackStatus)
    {
    case REMOTE_LPBK:
        if (p_tlv->state == STATE_LCL_LPBK)
        {
            _update_lpbk_timer(ifindex, &p->last_lpbk);
        }
        break;
    case LOCAL_LPBK:
        if (p_tlv->state == STATE_RMT_LPBK)
        {
            _update_lpbk_timer(ifindex, &p->last_lpbk);
        }
        break;
    default:
        break;
    }

    return;
}

static void procee_peer_cevt_flags(ifindex_s ifindex, uint8_t flags)
{
    fsm_port_s *p = eoam_fsm_port(ifindex);
    dot3_evt_log_s evt;
    char info_buf[32], info_buf2[32];

    memset(&evt, 0, sizeof(evt));
    evt.ifindex = ifindex;
    evt.dot3OamEventLogTimestamp = xos_get_uptime();
    evt.dot3OamEventLogLocation = EVT_REMOTE;

    if (p->remote_flags != flags)
    {
        if (p->remote_flags)
            xdbg_log(XDBG_INFO, "[%2d] remote flags changes %s --> %s",
                    ifindex, 
                    eoam_str_info_flags(p->remote_flags, info_buf),
                    eoam_str_info_flags(flags, info_buf2));
        else
            xdbg_log(XDBG_INFO, "[%2d] new remote flags %s",
                    ifindex, 
                    eoam_str_info_flags(flags, info_buf2));
    }
    
    /* for other router, it might raise multiple events
        * link failure
        */
    if ((flags & PDU_FLAGS_EV_LF) != (p->remote_flags & PDU_FLAGS_EV_LF) )
    {
        if ((flags & PDU_FLAGS_EV_LF) != PDU_FLAGS_EV_LF)
            evt.clear_flag = TRUE;

        evt.dot3OamEventLogType = EVT_LINK_FAULT;

        eoam_log_set_log(&evt); /* FIXME:log */

        eoam_cout_report_evt(&evt); /* need xdev param */
    }

    /* dying gasp */
    if ((flags & PDU_FLAGS_EV_DGASP) != (p->remote_flags & PDU_FLAGS_EV_DGASP) )
    {
        if ((flags & PDU_FLAGS_EV_DGASP) != PDU_FLAGS_EV_DGASP)
            evt.clear_flag = TRUE;

        evt.dot3OamEventLogType = EVT_DYING_GASP;

        eoam_log_set_log(&evt); /* FIXME:log */

        eoam_cout_report_evt(&evt); /* need xdev param */
    }

    /* critical */
    if ((flags & PDU_FLAGS_EV_CEVT) != (p->remote_flags & PDU_FLAGS_EV_CEVT) )
    {
        if ((flags & PDU_FLAGS_EV_CEVT) != PDU_FLAGS_EV_CEVT)
            evt.clear_flag = TRUE;

        evt.dot3OamEventLogType = EVT_CRITICAL;

        eoam_log_set_log(&evt); /* FIXME:log */

        eoam_cout_report_evt(&evt); /* need xdev param */
    }

    return ;
}

static BOOLEAN _eoam_fsm_update(ifindex_s ifindex, oam_pdu_hdr_t *p_pdu, oam_info_tlv_s *p_tlv)
{
    fsm_port_s *p = eoam_fsm_port(ifindex);
    char info_buf[32];

    xdbg_log(XDBG_DEBUG, "[%2d] rx tlv len %d rev %d, fl %s, cfg %02x, st %s",
             ifindex, p_tlv->hdr.length, ntohs(p_tlv->tlv_revision),
             eoam_str_info_flags(p_pdu->flags, info_buf),
             p_tlv->config, eoam_str_info_state(p_tlv->state));

    /* lpbk timer */
    _refresh_lpbk_timer(ifindex, p_tlv); 

    if (p->peer_tlv.tlv_revision != p_tlv->tlv_revision)
    {
        xdbg_log(XDBG_INFO, "[%2d] rev %d cfg (%02x ->  %02x), state (%02x -> %02x)",
                 ifindex, ntohs(p_tlv->tlv_revision),
                 p->peer_tlv.config, p_tlv->config,
                 p->peer_tlv.state, p_tlv->state);

        eoam_cout_peer_capability(ifindex, p_tlv->config, p_tlv->state);

        /* check config (mode change) */
        if (p->peer_tlv.config != p_tlv->config)
        {
            /* peer disable lpbk, but port is in remote lpbk */

            /* peer become passive, but port is in local lpbk */

            /* FIXME peer become passive, stop loopback <-- wrong ? */
            if ((p_tlv->config & CFG_MODE_ACTIVE) == 0 &&
                p->lpbk.oamLoopbackStatus != NO_LPBK)
            {
                xdbg_log(XDBG_INFO, "[%2d] peer mode changed to passive, stop lpbk",
                         ifindex);
                p->state = STATE_NO_LPBK; /* remote changed */
                p->lpbk.oamLoopbackStatus = NO_LPBK;
                eoam_cout_lpbk_req(ifindex, p->lpbk.oamLoopbackStatus); /* set lpbk */
            }
        }

        /* check state (lpbk) */
        if (p->peer_tlv.state != p_tlv->state)
            check_peer_response(ifindex, p_tlv);
    }

    return TRUE;
}

static BOOLEAN fsm_check_peer_config(ifindex_s ifindex, uint8_t code)
{
    fsm_port_s *p = eoam_fsm_port(ifindex);
    BOOLEAN feature_flag = FALSE;
    BOOLEAN retval = FALSE;

    if (p->cur_state != ST_SEND_ANY)
    {
        xdbg_log(XDBG_INFO, "[%2d] current state not able to send (code %d) oam pdu.",
                 ifindex, code);
        return FALSE;
    }

    switch (code)
    {
    case PDU_CODE_EVENT:
        feature_flag = (p->peer_tlv.config & CFG_LINK_EVENTS);
        break;
    case PDU_CODE_LPBK:
        feature_flag = (p->peer_tlv.config & CFG_LPBK);
        break;
    case PDU_CODE_VAR_REQ:
        feature_flag = (p->peer_tlv.config & CFG_VAR_REQ);
        break;
    default:
        break;
    }

    if (feature_flag)
    {
        retval = TRUE;
    }
    else
    {
        xdbg_log(XDBG_ERR, "[%2d] peer does not support (%d) !!!",
                 ifindex, code);
    }

    return retval;
}

BOOLEAN _validate_oam_tlv(oam_tlv_hdr_t *p_tlv, size_t size)
{
    size_t processed_bytes = 0;
    BOOLEAN retval = TRUE;

    /* tlv sanity check */
    while (processed_bytes < size)
    {
        if (p_tlv->type == TLV_TYPE_END)
            break;

        processed_bytes += p_tlv->length;
        if (processed_bytes > size)
        {
            xdbg_log(XDBG_ERR, "_validate_oam_tlv: invalid tlv chain !!!");
            retval = FALSE;
            break;
        }
        p_tlv = (oam_tlv_hdr_t *)((uint8_t *)p_tlv + p_tlv->length);
    }

    return retval;
}

/** 
 * _local_safisfied
 * 
 * The local_satisfied parameter is set by the OAM client as a result 
 * of comparing its local configuration and the remote configuration 
 * found in the received Local Information TLV
 * 
 * This indicates the OAM client finds the local and remote OAM configuration 
 * settings are agreeable.
 * compare:
 *  - DTE state (parser, mux)
 *  - oam mode
 *  - capabilities
 *  - oam max mtu size
 * 
 */
static BOOLEAN _local_satisfied(ifindex_s ifindex, uint8_t remote_flags, oam_info_tlv_s *p_tlv)
{
    fsm_port_s *p = eoam_fsm_port(ifindex);

    if (remote_flags) {}

    /* it is not ok with both party is passive */
    if (p->cfg.oamMode == OAM_MODE_PASSIVE &&
        (p_tlv->config & CFG_MODE_ACTIVE) == 0)
    {
        xdbg_log(XDBG_ERR, "[%2d] loc unsatisfy: both passive (cfg %s) !!!",
            ifindex, eoam_str_oam_config(p_tlv->config));
        return FALSE;
    }

    return TRUE;

#if 0
    if (LOCAL_EQ_REMOTE(p->send_flags, remote_flags))
        return TRUE;
    else
        return FALSE;
#endif

}

/**
 * _remoote_stable
 * 
 * remote_stable is used to indicate remote OAM client acknowledgment of and 
 * satisfaction with local OAM state information
 */
static BOOLEAN _remote_stable(ifindex_s ifindex, oam_pdu_hdr_t *p_pdu)
{
    fsm_port_s *p = eoam_fsm_port(ifindex);

    if (p == NULL)
        return FALSE;

    if (p_pdu->flags & PDU_FLAGS_L_STABLE)
        return TRUE;
    else
        return FALSE;
}

/*--------------------------------------------------------------------------
 * Public Functions
 *--------------------------------------------------------------------------
 */

/*
 * pdu indications
 */
/**
 * fsm_info_pdu_indication
 * @param pdu - oam pdu (mac header is included)
 */
oam_err_e eoam_proc_info_pdu_indication(ifindex_s ifindex, oam_pdu_hdr_t *p_pdu, 
    size_t pdu_size)
{
    oam_info_tlv_s *peer_local = NULL, *peer_remote = NULL;
    int tlv_size;
    oam_err_e status = OAM_NO_ERROR;
    fsm_port_s *p;
    oam_tlv_hdr_t *p_tlv;
    char zero_mac[] = {0, 0, 0, 0, 0, 0};
    char buf[32], buf2[32];

    p_tlv = (oam_tlv_hdr_t *)(p_pdu + 1);

    if ((p = eoam_fsm_port(ifindex)) == NULL)
        return INVALID_PORT;

    tlv_size = (int)(pdu_size - sizeof(oam_pdu_hdr_t));

    if (!_validate_oam_tlv(p_tlv, tlv_size))
        return INVALID_OAM_PDU;

    p->stats.oamInformationRx++;

    /* process critical event flags */
    procee_peer_cevt_flags(ifindex, p_pdu->flags);

    /* for LF event, there is no tlv */
    if (PDU_FLAGS_L_VALID(p_pdu->flags) == 0)
    {
        if ((p_pdu->flags & PDU_FLAGS_EV_LF) != 0)
        {
            return OAM_NO_ERROR;
        }
        else
        {
            xdbg_log(XDBG_ERR, "[%02d] rx invalid local flags (flags = 0x%02x)", ifindex,
                 p_pdu->flags);

            return INVALID_OAM_PDU;
        }
    }

    if (!_locate_info_tlv(p_pdu, pdu_size, &peer_local, &peer_remote))
    {
        xdbg_log(XDBG_ERR, "[%02d] rx pdu with no local tlv !!!", ifindex,
                 p_pdu->flags);
        return INVALID_OAM_PDU;
    }

    /* only update timer with valid pdu and contain tlv */
    gettimeofday(&p->last_rx, NULL);

    if (memcmp(p->peer_mac, zero_mac, MAC_ADRS_SIZE) == 0)
    {
        /* at least, one party is in active mode */
        if (p->cfg.oamMode != OAM_MODE_PASSIVE ||
            (peer_local->config & CFG_MODE_ACTIVE) != 0)
        {
            xdbg_log(XDBG_INFO, "[%2d] rx pdu, remote valid, flags:%s",
                 ifindex, 
                 eoam_str_info_flags(p_pdu->flags, buf));

            eoam_fsm_step(ifindex, EV_REMOTE_STATE_VALID, p_pdu);
        }
        else
        {
            xdbg_log(XDBG_INFO, "[%2d] rx pdu, both passive, remote invalid, flags:%s",
                 ifindex, 
                 eoam_str_info_flags(p_pdu->flags, buf));

            eoam_fsm_step(ifindex, EV_REMOTE_STATE_VALID, NULL);
        }
    }
    else
    {
        /* has both local and remote tlv */
        if (_local_satisfied(ifindex, p_pdu->flags, peer_local))
        {
            if (p->local_stable != TRUE)
            {
                eoam_fsm_step(ifindex, EV_LOCAL_SATISFIED, p_pdu);
            }
            else
            {
                if (_remote_stable(ifindex, p_pdu))
                {
                #if 1
                    _eoam_fsm_update(ifindex, p_pdu, peer_local); /* FIXME:valid */
                #endif

                    eoam_fsm_step(ifindex, EV_REMOTE_STABLE, p_pdu);
                }
                else
                {
                    xdbg_log(XDBG_INFO, "[%2d] remote unstable state:%s remote flag:%s",
                        ifindex, eoam_str_fsm_state(p->cur_state),
                        eoam_str_info_flags(p_pdu->flags, buf));

                    eoam_fsm_step(ifindex, EV_REMOTE_STABLE, NULL);
                }
            }
        }
        else
        {
            xdbg_log(XDBG_INFO, "[%2d] local unsatisfied state:%s loc:%s rmt:%s",
                ifindex, eoam_str_fsm_state(p->cur_state),
                eoam_str_info_flags(p->send_flags, buf),
                eoam_str_info_flags(p_pdu->flags, buf2));

            eoam_fsm_step(ifindex, EV_LOCAL_SATISFIED, NULL);
        }
    }

    /* copy tlv */
    memcpy(&p->peer_tlv, peer_local, sizeof(oam_info_tlv_s));
    p->peer_tlv.hdr.type = INFO_TLV_TYPE_REMOTE;

    return status;
}

/**
 * eoam_proc_lpbk_pdu_indication
 * @param pdu - oam pdu (mac header is included)
 *
 * received loopback request,
 * acceptance condition:
 *  - state is in send_any
 *  - loopback (oam config) is suppoprted locally
 *  - oamLoopbackIgnoreRx is PROCESS_LPBK
 * actions
 *  if aleady in remote loopback and peer's has smaller mac (hander in upper layer ??)
 *  - turn par:LB, mux: DISCARD
 *  - update mib status variable
 *  - response with info pdu
 */
oam_err_e eoam_proc_lpbk_pdu_indication(ifindex_s ifindex, oam_pdu_hdr_t *p_pdu, size_t pdu_size)
{
    oam_err_e status = OAM_NO_ERROR;
    uint8_t *cmd;
    fsm_port_s *p;
    char pmac[MAC_ADRS_SIZE];

    if (pdu_size) {}

    cmd = (uint8_t *)(p_pdu + 1);

    p = eoam_fsm_port(ifindex);

    if (p == NULL)
        return INVALID_PORT;

    if (p->lpbk.oamLoopbackIgnoreRx != PROCESS_LPBK)
    {
        xdbg_log(XDBG_DEBUG, "[%2d] eoam_proc_lpbk_pdu_indication: ignore-rx is enable, drop lpbk req !!!",
                 ifindex);
        return LPBK_NOT_ALLOWED;
    }

    p->stats.oamLoopbackControlRx++; /* FIXME: should count drop lpbk req ?? */

    if (*cmd != OAM_LPBK_START && *cmd != OAM_LPBK_STOP)
    {
        xdbg_log(XDBG_ERR, "[%2d] eoam_proc_lpbk_pdu_indication: code (%d) invalid cmd %d !!!",
                 ifindex, p_pdu->code, *cmd);
        return INVALID_OAM_PDU;
    }

    /* compare mac address if we also initializing loopback */
    if (p->lpbk.oamLoopbackStatus == INIT_LPBK)
    {
        /* ignore peer request if we have lower mac */
        eoam_cout_get_pmac(ifindex, (uint8_t *)pmac);
        if (memcmp(pmac, p_pdu->sa, MAC_ADRS_SIZE) <= 0)
        {
            xdbg_log(XDBG_ERR, "[%2d] eoam_proc_lpbk_pdu_indication: ignore lower priority req !!!",
                     ifindex);
            return LOW_PRIORITY;
        }
    }

    if (*cmd == OAM_LPBK_START)
    {
        /* turn par:LB, mux: DISCARD */
        p->lpbk.oamLoopbackStatus = LOCAL_LPBK;  /* FIXME */
        p->state = STATE_PAR_LPBK | STATE_MUX_DISCARD;
    }
    else
    {
        /* turn par:FWD, mux: FWD */
        p->lpbk.oamLoopbackStatus = NO_LPBK;  /* FIXME */
        p->state = STATE_PAR_FWD | STATE_MUX_FWD;
    }

    /* only update timer with valid pdu */
    gettimeofday(&p->last_rx, NULL);

    /* update lpbk timer */
    _update_lpbk_timer(ifindex, &p->last_lpbk); 

    p->cfg.oamConfigRevision++; /* respond with new tlv state is updated, so inc revision */

    xdbg_log(XDBG_INFO, "[%2d] eoam_proc_lpbk_pdu_indication: loopback cmd %d",
             ifindex, *cmd);

    /* FIXME:lpbk send info pdu to peer to notify our state is changed */
    xdbg_log(XDBG_INFO, "[%2d] eoam_proc_lpbk_pdu_indication: lpbk respond info pdu",
             ifindex);

    eoam_fsm_send_info_pdu(ifindex);

    eoam_cout_lpbk_req(ifindex, p->lpbk.oamLoopbackStatus);

    return status;
}

void parse_sym_period(dot3_evt_log_s *p_evtlog, sym_period_s *p_tlv)
{
    p_evtlog->dot3OamEventLogWindowHi = ntohl(p_tlv->window_hi);
    p_evtlog->dot3OamEventLogWindowLo = ntohl(p_tlv->window_lo);

    p_evtlog->dot3OamEventLogThresholdHi = ntohl(p_tlv->threshold_hi);
    p_evtlog->dot3OamEventLogThresholdLo = ntohl(p_tlv->threshold_lo);

    p_evtlog->dot3OamEventLogValue = ntohl(p_tlv->errors_hi);
    p_evtlog->dot3OamEventLogValue = (p_evtlog->dot3OamEventLogValue << 32) |
        (ntohl(p_tlv->errors_lo));

    p_evtlog->dot3OamEventLogRunningTotal = ntohl(p_tlv->err_total_hi);
    p_evtlog->dot3OamEventLogRunningTotal = (p_evtlog->dot3OamEventLogRunningTotal << 32) |
        (ntohl(p_tlv->err_total_lo));

    p_evtlog->dot3OamEventLogEventTotal = ntohl(p_tlv->evt_total);

    return ;
}

void parse_frame_period(dot3_evt_log_s *p_evtlog, frame_period_s *p_tlv)
{
    p_evtlog->dot3OamEventLogWindowHi = 0;
    p_evtlog->dot3OamEventLogWindowLo = ntohs(p_tlv->window);
    
    p_evtlog->dot3OamEventLogThresholdHi = 0;
    p_evtlog->dot3OamEventLogThresholdLo = ntohl(p_tlv->threshold);
    
    p_evtlog->dot3OamEventLogValue = ntohl(p_tlv->errors);
    
    p_evtlog->dot3OamEventLogRunningTotal = ntohl(p_tlv->err_total_hi);
    p_evtlog->dot3OamEventLogRunningTotal = (p_evtlog->dot3OamEventLogRunningTotal << 32) |
    (ntohl(p_tlv->err_total_lo));
    
    p_evtlog->dot3OamEventLogEventTotal = ntohl(p_tlv->evt_total);
    
    return ;
}

void parse_err_frame(dot3_evt_log_s *p_evtlog, err_frame_s *p_tlv)
{
    p_evtlog->dot3OamEventLogWindowHi = 0;
    p_evtlog->dot3OamEventLogWindowLo = ntohl(p_tlv->window);
    
    p_evtlog->dot3OamEventLogThresholdHi = 0;
    p_evtlog->dot3OamEventLogThresholdLo = ntohl(p_tlv->threshold);
    
    p_evtlog->dot3OamEventLogValue = ntohl(p_tlv->errors);
    
    p_evtlog->dot3OamEventLogRunningTotal = ntohl(p_tlv->err_total_hi);
    p_evtlog->dot3OamEventLogRunningTotal = (p_evtlog->dot3OamEventLogRunningTotal << 32) |
    (ntohl(p_tlv->err_total_lo));
    
    p_evtlog->dot3OamEventLogEventTotal = ntohl(p_tlv->evt_total);
    
    return ;
}

void parse_frame_sec(dot3_evt_log_s *p_evtlog, frame_sec_s *p_tlv)
{
    p_evtlog->dot3OamEventLogWindowHi = 0;
    p_evtlog->dot3OamEventLogWindowLo = ntohs(p_tlv->window);
    
    p_evtlog->dot3OamEventLogThresholdHi = 0;
    p_evtlog->dot3OamEventLogThresholdLo = ntohs(p_tlv->threshold);
    
    p_evtlog->dot3OamEventLogValue = ntohs(p_tlv->errors);
    
    p_evtlog->dot3OamEventLogRunningTotal = ntohl(p_tlv->err_total);
    
    p_evtlog->dot3OamEventLogEventTotal = ntohl(p_tlv->evt_total);
    
    return ;
}

void process_event_tlv(ifindex_s ifindex, uint16_t rx_seq, oam_event_tlv_s *p_evt_tlv,
    size_t size)
{
    dot3_evt_log_s evt;
    oam_tlv_hdr_t *p_hdr = (oam_tlv_hdr_t *) p_evt_tlv;

    if (size) {}
    if (rx_seq) {}

    /* remote timestamp and sequence is not stored */
    evt.ifindex = ifindex;
    evt.dot3OamEventLogType = (mib_evt_type_e)p_hdr->type;
    evt.dot3OamEventLogTimestamp = xos_get_uptime(); /* rfc, record rx time */

#if 1 /* not, dot3OamEventLogIndex will be auto filled */
    evt.dot3OamEventLogIndex = 0; 
#else
    evt.dot3OamEventLogIndex = rx_seq; 
#endif
  
    evt.dot3OamEventLogLocation = EVT_REMOTE;

    evt.dot3OamEventLogOui[0] = 0x01;
    evt.dot3OamEventLogOui[0] = 0x80;
    evt.dot3OamEventLogOui[0] = 0xc2;
    
    switch (p_hdr->type)
    {
    case EVT_ERR_SYMBOL_PERIOD:
        if (size != 40)
        {
            xdbg_log(XDBG_DEBUG, "[%2d] process_event_tlv: wrong size (%d) ignore !!!",
                     ifindex, size);
            return ;
        }
        parse_sym_period(&evt, &p_evt_tlv->sym_prd);
        break;
            
    case EVT_ERR_FRAME_PERIOD:
        if (size != 26)
        {
            xdbg_log(XDBG_DEBUG, "[%2d] process_event_tlv: wrong size (%d) ignore !!!",
                     ifindex, size);
            return ;
        }
        parse_frame_period(&evt, &p_evt_tlv->frame_prd);
        break;

    case EVT_ERR_FRAME_EVENT:
        if (size != 28)
        {
            xdbg_log(XDBG_DEBUG, "[%2d] process_event_tlv: wrong size (%d) ignore !!!",
                     ifindex, size);
            return ;
        }
        parse_err_frame(&evt, &p_evt_tlv->frame);
        break;

    case EVT_ERR_FRAME_SEC_EVENT:
        if (size != 18)
        {
            xdbg_log(XDBG_DEBUG, "[%2d] process_event_tlv: wrong size (%d) ignore !!!",
                     ifindex, size);
            return ;
        }
        parse_frame_sec(&evt, &p_evt_tlv->frame_sec);
        break;

    default:
            return ;
        break;
    }

    if (eoam_log_set_log(&evt) != OAM_NO_ERROR)
    {
        xdbg_log(XDBG_DEBUG, "[%2d] process_event_tlv: faill to add log (type = %d) !!!",
            ifindex, p_hdr->type);
        return ;
    }

    eoam_cout_report_evt(&evt); /* need xdev param */

    return ;
}

oam_err_e eoam_proc_evt_pdu_indication(ifindex_s ifindex, oam_pdu_hdr_t *p_pdu, size_t pdu_size)
{
    oam_pdu_event_s *p_evtpdu;
    oam_event_tlv_s *p_evt_tlv;
    oam_err_e status = OAM_NO_ERROR;
    fsm_port_s *p;
    uint16_t rx_seq;
    size_t processed_bytes = 0;
    size_t tlv_total_size, tlv_size, phdr_size;

    p_evtpdu = (oam_pdu_event_s *)(p_pdu + 1);
    p_evt_tlv = (oam_event_tlv_s *) &p_evtpdu->evt_tlv;

    p = eoam_fsm_port(ifindex);

    if (p == NULL)
        return INVALID_PORT;

    phdr_size = sizeof(oam_pdu_hdr_t);
    tlv_total_size = pdu_size - phdr_size - 2 /* seq */;

    if (!_validate_oam_tlv((oam_tlv_hdr_t *)p_evt_tlv, tlv_total_size))
        return INVALID_OAM_PDU;

    /* sequence number */
    rx_seq = ntohs(p_evtpdu->evt_seq);
    if (p->evt_rx_seq == rx_seq)
        p->stats.oamDuplicateEventNotificationRx++;
    else
        p->stats.oamUniqueEventNotificationRx++;
    p->evt_rx_seq = rx_seq;

    /* FIXME:tlv process multiple event tlv, not tested yet */
    while (processed_bytes < tlv_total_size)
    {
        if (p_evt_tlv->sym_prd.hdr.type == TLV_TYPE_END)
            break;
        
        xdbg_log(XDBG_INFO, "[%2d] rx evt pdu: seq %d ts %d type %d value %d:%d",
                 ifindex, rx_seq, ntohs(p_evt_tlv->sym_prd.timestamp), p_evt_tlv->sym_prd.hdr.type,
                 ntohl(p_evt_tlv->sym_prd.errors_hi), ntohl(p_evt_tlv->sym_prd.errors_lo));
        
        tlv_size = p_evt_tlv->sym_prd.hdr.length;

        /* process event tlv */
        process_event_tlv(ifindex, rx_seq, (oam_event_tlv_s *)p_evt_tlv, tlv_size);
        processed_bytes += p_evt_tlv->sym_prd.hdr.length;
        if (processed_bytes > tlv_total_size)
        {
            xdbg_log(XDBG_ERR, "eoam_proc_evt_pdu_indication: invalid tlv chain !!!");
            status = INVALID_OAM_PDU;
            break;
        }
        p_evt_tlv = (oam_event_tlv_s *)((uint8_t *)p_evt_tlv + p_evt_tlv->sym_prd.hdr.length);
    }

    return status;
}

oam_err_e eoam_proc_other_pdu_indication(ifindex_s ifindex, oam_pdu_hdr_t *p_pdu, 
    size_t pdu_size)
{
    fsm_port_s *p;

    if (p_pdu) {}
    if (pdu_size) {}

    p = eoam_fsm_port(ifindex);

    if (p == NULL)
        return INVALID_PORT;

    p->stats.oamUnsupportedCodesRx++;

    return INVALID_OAM_PDU;
}

/*
 * process client reqeust
 */

oam_err_e eoam_proc_set_port_cfg(dot3_oam_cfg_s *oam_cfg)
{
    ifindex_s ifindex;
    fsm_port_s *p;

    ifindex = oam_cfg->ifindex;
    p = eoam_fsm_port(ifindex);

    if (p == NULL)
        return INVALID_PORT;

    /* parameter checking */
    if (oam_cfg->oamMode != OAM_MODE_ACTIVE && 
        oam_cfg->oamMode != OAM_MODE_PASSIVE)
    {
        xdbg_log(XDBG_ERR, "[%2d] eoam_proc_set_port_cfg: invalid oam mode (%d) !!!",
            ifindex, oam_cfg->oamMode);

        return INVALID_CONFIG;
    }

    if (oam_cfg->oamAdminState != OAM_ADMIN_ENABLED && 
        oam_cfg->oamAdminState != OAM_ADMIN_DISABLED)
    {
        xdbg_log(XDBG_ERR, "[%2d] eoam_proc_set_port_cfg: admin state (%d) !!!",
            ifindex, oam_cfg->oamAdminState);

        return INVALID_CONFIG;
    }

    if (oam_cfg->oam_timeout < 2000 || oam_cfg->oam_timeout > 30000)
    {
        xdbg_log(XDBG_ERR, "[%2d] eoam_proc_set_port_cfg: invalid oam timeout (%d) !!!",
            ifindex, oam_cfg->oam_timeout);

        return INVALID_CONFIG;
    }

    if (p->cfg.oamMode != oam_cfg->oamMode && 
        p->lpbk.oamLoopbackStatus != NO_LPBK)
    {
        /* if in lpbk mode, don't allow to change mode */
        xdbg_log(XDBG_ERR, "[%2d] eoam_proc_set_port_cfg: in lpbk, not allowd !!!",
            ifindex);

        return OP_NOT_ALLOWED;            
    }

    if (p->cfg.oamMode != oam_cfg->oamMode)
        p->cfg.oamConfigRevision++;

    eoam_fsm_step(oam_cfg->ifindex, EV_OAM_MODE, oam_cfg);

    p->cfg.oamAdminState = oam_cfg->oamAdminState;
    p->cfg.oamMode = oam_cfg->oamMode;
    p->cfg.oam_timeout = oam_cfg->oam_timeout;

    /* note, oamFunctionsSupported is read-only */

    /* if oam admin is disabled, clear critical event flags */
    if (p->cfg.oamAdminState == OAM_ADMIN_DISABLED)
    {
        XBITS_CLR_MASK(p->send_flags, PDU_FLAGS_EV_LF);
        p->evt_cfg.dot3OamLinkFaultStatus = MIB_FALSE;

        XBITS_CLR_MASK(p->send_flags, PDU_FLAGS_EV_DGASP);
        p->evt_cfg.dot3OamDyingGaspStatus = MIB_FALSE;
        
        XBITS_CLR_MASK(p->send_flags, PDU_FLAGS_EV_CEVT);
        p->evt_cfg.dot3OamCriticalEventStatus = MIB_FALSE;

        if (p->lpbk.oamLoopbackStatus != NO_LPBK)
        {
            xdbg_log(XDBG_INFO, "[%2d] set admin disabled, stop lpbk",
                        ifindex);
            p->state = STATE_NO_LPBK; /* local changed */
            p->lpbk.oamLoopbackStatus = NO_LPBK;

            eoam_cout_lpbk_req(ifindex, p->lpbk.oamLoopbackStatus); /* set lpbk */
        }
    }

    return OAM_NO_ERROR;
}

oam_err_e eoam_proc_get_port_cfg(dot3_oam_cfg_s *oam_cfg)
{
    ifindex_s ifindex;
    fsm_port_s *p;

    ifindex = oam_cfg->ifindex;
    p = eoam_fsm_port(ifindex);

    if (p == NULL)
        return INVALID_PORT;

    memcpy(oam_cfg, &p->cfg, sizeof(dot3_oam_cfg_s));
    oam_cfg->ifindex = ifindex;

    /* FIXME:config (default config) */

    return OAM_NO_ERROR;
}

oam_err_e eoam_proc_get_peer(dot3_peer_s *peer)
{
    ifindex_s ifindex;
    fsm_port_s *p;
    oam_info_tlv_s *p_tlv ;

    ifindex = peer->ifindex;
    p = eoam_fsm_port(ifindex);

    if (p == NULL)
        return INVALID_PORT;

#if 1 /* FIXME:valid */
    p_tlv = &p->peer_tlv;
    peer->ifindex = ifindex;
    memcpy(peer->dot3OamPeerMacAddress, p->peer_mac, MAC_ADRS_SIZE);
    peer->dot3OamPeerConfigRevision = ntohs(p_tlv->tlv_revision);
    peer->dot3OamPeerMaxOamPduSize = ntohs(p_tlv->max_pdu_size);
    peer->dot3OamPeerMode = (p_tlv->config & CFG_MODE_ACTIVE) ? OAM_MODE_ACTIVE : OAM_MODE_PASSIVE;
    peer->dot3OamPeerFunctionsSupported = (p_tlv->config >> 1); /* shift out oam-mode bit */
    memcpy(peer->dot3OamPeerVendorOui, p_tlv->oui, 3);
    peer->dot3OamPeerVendorInfo = ntohl(p_tlv->vendor_spec); /* FIXME:vendor */
#else
    memcpy(peer, &p->peer, sizeof(dot3_peer_s));
    peer->ifindex = ifindex;
#endif

    return OAM_NO_ERROR;
}

oam_err_e eoam_proc_get_stats(dot3_oam_stats_s *stats)
{
    ifindex_s ifindex;
    fsm_port_s *p;

    ifindex = stats->ifindex;
    p = eoam_fsm_port(ifindex);

    if (p == NULL)
        return INVALID_PORT;

    memcpy(stats, &p->stats, sizeof(dot3_oam_stats_s));
    stats->ifindex = ifindex;

    return OAM_NO_ERROR;
}

oam_err_e eoam_proc_clear_stats(ifindex_s ifindex)
{
    size_t i ;
    fsm_port_s *p;

    if (ifindex > 0)
    {
        p = eoam_fsm_port(ifindex);

        if (p == NULL)
            return INVALID_PORT;

        memset(&p->stats, 0, sizeof(dot3_oam_stats_s));
        memset(&p->link_evt_sum, 0, sizeof(p->link_evt_sum));
        memset(&p->c_evt_sum, 0, sizeof(p->c_evt_sum));
    }
    else
    {
        /* clear all */
        for (i = 1; i <= eoam_max_ports(); i++)
        {
            p = eoam_fsm_port(i);
            if (p == NULL)
            {
                xdbg_log(XDBG_ERR, "eoam_proc_clear_stats: invalid port pointer (ifindex = %d, i = %d) !!!", ifindex, i);
                return OAM_INTERNAL_ERROR;
            }

            memset(&p->stats, 0, sizeof(dot3_oam_stats_s));
            memset(&p->link_evt_sum[0], 0, sizeof(p->link_evt_sum));
            memset(&p->c_evt_sum[0], 0, sizeof(p->c_evt_sum));
        }
    }

    return OAM_NO_ERROR;
}

oam_err_e check_lpbk_condition(ifindex_s ifindex, fsm_port_s *p, dot3_lpbk_cfg_s *lpbk_cfg)
{
    oam_err_e status = OAM_NO_ERROR;

    switch (lpbk_cfg->oamLoopbackStatus)
    {
    case  INIT_LPBK:
        /* check if peer support lpbk */
        if (!fsm_check_peer_config(ifindex, PDU_CODE_LPBK))
        {
            xdbg_log(XDBG_ERR, "[%2d] check_lpbk_condition: peer does not have lpbk capability !!!",
                     ifindex);
            return PEER_CAP_LPBK;
        }

        /* only active role can issue loopback command */
        if (p->cfg.oamMode != OAM_MODE_ACTIVE || p->cur_state != ST_SEND_ANY)
        {
            xdbg_log(XDBG_ERR, "[%2d] check_lpbk_condition: wrong oam mode or state !!!", ifindex);
            return OP_NOT_ALLOWED;
        }

        /* check if port in appropriate state for request */
        if (p->lpbk.oamLoopbackStatus != NO_LPBK)
        {
            if (p->lpbk.oamLoopbackStatus != LOCAL_LPBK &&
                lpbk_cfg->oamLoopbackIgnoreRx != IGNORED_LPBK)
            {
                xdbg_log(XDBG_ERR, "[%2d] check_lpbk_condition: lpbk in ongoing (%d)!!!",
                         ifindex, p->lpbk.oamLoopbackStatus);
                return OP_NOT_ALLOWED;
            }
        }
        break;

    case TERM_LPBK:
        /* only active role can issue loopback command */
        if (p->cfg.oamMode != OAM_MODE_ACTIVE || p->cur_state != ST_SEND_ANY)
        {
            xdbg_log(XDBG_ERR, "[%2d] check_lpbk_condition: wrong oam mode or state !!!", ifindex);
            return OP_NOT_ALLOWED;
        }

        /* check if port in appropriate state for request */
        if (p->lpbk.oamLoopbackStatus != REMOTE_LPBK)
        {
            xdbg_log(XDBG_ERR, "[%2d] check_lpbk_condition: lpbk is not stared (%d) !!!",
                     ifindex, p->lpbk.oamLoopbackStatus);
            return OP_NOT_ALLOWED;
        }
        break;
    default:
        break;
    }

    return status;
}

/**
 *
 * start lpbk:
 *  - oam mode - active, current fsm state
 *  - lpbk status - no lpbk
 *  - peer cap
 *
 * stop lpbk:
 *  - oam mode - active, current fsm state
 *  - lpbk status - remote loopback
 *
 * other:
 *  - ignore status, update ignore-rx only
 *
 */
oam_err_e eoam_proc_set_lpbk(dot3_lpbk_cfg_s *lpbk_cfg)
{
    ifindex_s ifindex;
    fsm_port_s *p;
    uint8_t cmd; /* 1: enable, 2: disable */
    oam_err_e status = OAM_NO_ERROR;

    ifindex = lpbk_cfg->ifindex;
    p = eoam_fsm_port(ifindex);

    /**
     * parameter check
     */

    /* port */
    if (p == NULL)
        return INVALID_PORT;

    if (lpbk_cfg == NULL)
        return INVALID_CONFIG;

    /* oamLoopbackStatus */
    if (lpbk_cfg->oamLoopbackStatus == INIT_LPBK ||
        lpbk_cfg->oamLoopbackStatus == TERM_LPBK)
    {
        /* only active role can issue loopback command */
        if (p->cfg.oamMode != OAM_MODE_ACTIVE || p->cur_state != ST_SEND_ANY)
        {
            xdbg_log(XDBG_ERR, "[%02d] eoam_proc_set_lpbk: wrong oam mode or state !!!", 
                ifindex);
            return OP_NOT_ALLOWED;
        }
    }

    /* range check */
    if (lpbk_cfg->oamLoopbackStatus < NO_LPBK ||
        lpbk_cfg->oamLoopbackStatus > LOCAL_LPBK)
    {
        xdbg_log(XDBG_ERR, "[%02d] eoam_proc_set_lpbk: invaid lpbk status %d !!!",
                 ifindex, lpbk_cfg->oamLoopbackStatus);
        return OP_NOT_ALLOWED;
    }

    /* oamLoopbackIgnoreRx */
    if (lpbk_cfg->oamLoopbackIgnoreRx < IGNORED_LPBK ||
        lpbk_cfg->oamLoopbackIgnoreRx > PROCESS_LPBK)
    {
        xdbg_log(XDBG_ERR, "[%02d] eoam_proc_set_lpbk: invaid ignore-rx value %d !!!",
                 ifindex, lpbk_cfg->oamLoopbackIgnoreRx);
        return OP_NOT_ALLOWED;
    }

    if (lpbk_cfg->lpbk_timeout < 1 &&
        lpbk_cfg->lpbk_timeout > 10)
    {
        xdbg_log(XDBG_ERR, "[%02d] eoam_proc_set_lpbk: invaid lpbk timeout %d !!!",
                 ifindex, lpbk_cfg->lpbk_timeout);
        return INVALID_CONFIG;
    }

    /* check status */
    status = check_lpbk_condition(ifindex, p, lpbk_cfg);
    if (status != OAM_NO_ERROR)
        return status;

    /**
     * oamLoopbackIgnoreRx (only affect passive role)
     */
    if (p->lpbk.oamLoopbackIgnoreRx != lpbk_cfg->oamLoopbackIgnoreRx)
    {
        p->cfg.oamConfigRevision++; /* config changed, inc rev */
        
#if 1
        /* func change ignore-rx also have to reflect on function support */
        if (lpbk_cfg->oamLoopbackIgnoreRx == IGNORED_LPBK)
            XBITS_CLR_BIT(p->cfg.oamFunctionsSupported, LOOPBACK_SUPPORT);
        else
            XBITS_SET_BIT(p->cfg.oamFunctionsSupported, LOOPBACK_SUPPORT);
        
        eoam_cout_lpbk_req(ifindex, p->lpbk.oamLoopbackStatus); /* set lpbk */
#endif
        
        if (lpbk_cfg->oamLoopbackIgnoreRx == IGNORED_LPBK)
        {
            if (p->lpbk.oamLoopbackStatus == LOCAL_LPBK)
            {
                /* 
                 * req to disable rx lpbk, terminate current remote loopback
                 */

                p->lpbk.oamLoopbackStatus = NO_LPBK;
                p->state = (STATE_PAR_FWD | STATE_MUX_FWD);

                eoam_cout_lpbk_req(ifindex, p->lpbk.oamLoopbackStatus); /* set lpbk */
            }
        }
    }

    /**
     * oamLoopbackStatus
     */
    /* copy INIT_LPBK or TERM_LPBK here */
    p->lpbk.ifindex = lpbk_cfg->ifindex;
    p->lpbk.oamLoopbackStatus = lpbk_cfg->oamLoopbackStatus;  /* set lpbk */
    p->lpbk.oamLoopbackIgnoreRx = lpbk_cfg->oamLoopbackIgnoreRx; /* FIXME */
    p->lpbk.lpbk_timeout = lpbk_cfg->lpbk_timeout ;

    
    /* send oam pdu */
    if (lpbk_cfg->oamLoopbackStatus == INIT_LPBK)
    {
        cmd = OAM_LPBK_START;
        p->state = (STATE_PAR_DISCARD | STATE_MUX_DISCARD);

        /* inc revision */
        p->cfg.oamConfigRevision++; /* FIXME: might double inc (ignore-rx) */

        eoam_fsm_send_lpbk_pdu(ifindex, cmd);
    }

    if (lpbk_cfg->oamLoopbackStatus == TERM_LPBK)
    {
        cmd = OAM_LPBK_STOP;
        p->state = (STATE_PAR_FWD | STATE_MUX_FWD);

        /* inc revision */
        p->cfg.oamConfigRevision++; /* FIXME: might double inc (ignore-rx) */

        eoam_fsm_send_lpbk_pdu(ifindex, cmd);
    }

    return status;
}

oam_err_e eoam_proc_get_lpbk(dot3_lpbk_cfg_s *lpbk_cfg)
{
    ifindex_s ifindex;
    fsm_port_s *p;

    ifindex = lpbk_cfg->ifindex;
    p = eoam_fsm_port(ifindex);

    if (p == NULL)
        return INVALID_PORT;

    memcpy(lpbk_cfg, &p->lpbk, sizeof(dot3_lpbk_cfg_s));

    return OAM_NO_ERROR;
}

oam_err_e eoam_proc_set_evt_cfg(dot3_evt_cfg_s *p_evtcfg)
{
    ifindex_s ifindex;
    fsm_port_s *p;

    ifindex = p_evtcfg->ifindex;
    p = eoam_fsm_port(ifindex);

    if (p == NULL)
        return INVALID_PORT;

    memcpy(&p->evt_cfg, p_evtcfg, sizeof(dot3_evt_cfg_s));
    p_evtcfg->ifindex = ifindex;

    /* if mask is disabled, clear critical event flag in info pdu */
    if (p_evtcfg->dot3OamDyingGaspEnable == MIB_FALSE)
    {
        XBITS_CLR_MASK(p->send_flags, PDU_FLAGS_EV_DGASP);
        p->evt_cfg.dot3OamDyingGaspStatus = MIB_FALSE;
    }

    if (p_evtcfg->dot3OamCriticalEventEnable == MIB_FALSE)
    {
        XBITS_CLR_MASK(p->send_flags, PDU_FLAGS_EV_CEVT);
        p->evt_cfg.dot3OamCriticalEventStatus = MIB_FALSE;
    }

    return OAM_NO_ERROR;
}

oam_err_e eoam_proc_get_evt_cfg(dot3_evt_cfg_s *p_evtcfg)
{
    ifindex_s ifindex;
    fsm_port_s *p;

    ifindex = p_evtcfg->ifindex;
    p = eoam_fsm_port(ifindex);

    if (p == NULL)
        return INVALID_PORT;

    memcpy(p_evtcfg, &p->evt_cfg, sizeof(dot3_evt_cfg_s));
    p_evtcfg->ifindex = ifindex;

    return OAM_NO_ERROR;
}

static BOOLEAN eval_evt_condiation(fsm_port_s *p, eoam_rpt_evt_s *p_rpt, 
    dot3_evt_log_s *p_log, uint8_t *p_mask)
{
    mib_evt_type_e type;
    /* the threshold of specific event.  if only one threshold, use low */
    uint32_t window_hi = 0xffffffff;
    uint32_t window_lo = 0xffffffff;
    uint32_t threshold_hi = 0xffffffff;
    uint32_t threshold_lo = 0xffffffff;
    oam_gauge64_s threshold, value64, total64;
    BOOLEAN over_threshold = FALSE;
    uint32_t evt_total;

    type = p_rpt->evt_type;
    value64 = p_rpt->value64;
    total64 = p_rpt->total64;
    *p_mask = 0; /* marked for critical event */

    /* only EVT_ERR_SYMBOL_PERIOD has high & low */
    switch (type)
    {
        /* error event tlv */
    case EVT_ERR_SYMBOL_PERIOD:
        window_hi = p->evt_cfg.dot3OamErrSymPeriodWindowHi;
        window_lo = p->evt_cfg.dot3OamErrSymPeriodWindowLo;
        
        threshold_hi = p->evt_cfg.dot3OamErrSymPeriodThresholdHi;
        threshold_lo = p->evt_cfg.dot3OamErrSymPeriodThresholdLo;
        
        threshold = threshold_hi;
        threshold = (threshold << 32) | threshold_lo;

        
        evt_total = p->link_evt_sum[EVT_ERR_SYMBOL_PERIOD-1].err_evt_total += 1;
        
        /*
         * RFC p36.  If the threshold value is zero, then an Event Notification OAMPDU is
         * sent periodically. (in this implementation, just bypass the threshold checking)
         */
        /* if over threshold or threshold is zero, send the notification pdu */
        if (p->evt_cfg.dot3OamErrSymPeriodEvNotifEnable == MIB_TRUE && 
            (p_rpt->assert_flag || p_rpt->value64 > threshold || threshold == 0))
        {
            over_threshold = TRUE;
        }
        
        break;
        
    case EVT_ERR_FRAME_PERIOD:
        window_hi = 0;
        window_lo = p->evt_cfg.dot3OamErrFramePeriodWindow;
        threshold_hi = 0;
        threshold_lo = p->evt_cfg.dot3OamErrFramePeriodThreshold;
        threshold = threshold_lo;
        
        evt_total = p->link_evt_sum[EVT_ERR_FRAME_PERIOD-1].err_evt_total += 1;
        
        /* if over threshold or threshold is zero, send the notification pdu */
        if (p->evt_cfg.dot3OamErrFramePeriodEvNotifEnable == MIB_TRUE && 
            (p_rpt->assert_flag || p_rpt->value64 > threshold || threshold == 0))
        {
            over_threshold = TRUE;
        }
        
        break;
        
    case EVT_ERR_FRAME_EVENT:
        window_hi = 0;
        window_lo = p->evt_cfg.dot3OamErrFrameWindow;
        threshold_hi = 0;
        threshold_lo = p->evt_cfg.dot3OamErrFrameThreshold;
        threshold = threshold_lo;
        
        evt_total = p->link_evt_sum[EVT_ERR_FRAME_EVENT-1].err_evt_total += 1;
        
        /* if over threshold or threshold is zero, send the notification pdu */
        if (p->evt_cfg.dot3OamErrFrameEvNotifEnable == MIB_TRUE && 
            (p_rpt->assert_flag || p_rpt->value64 > threshold || threshold == 0))
        {
            over_threshold = TRUE;
        }
        
        break;
        
    case EVT_ERR_FRAME_SEC_EVENT:
        window_hi = 0;
        window_lo = p->evt_cfg.dot3OamErrFrameSecsSummaryWindow;
        threshold_hi = 0;
        threshold_lo = p->evt_cfg.dot3OamErrFrameSecsSummaryThreshold;
        threshold = threshold_lo;
        
        evt_total = p->link_evt_sum[EVT_ERR_FRAME_SEC_EVENT-1].err_evt_total += 1;
            
        /* if over threshold or threshold is zero, send the notification pdu */
        if (p->evt_cfg.dot3OamErrFrameSecsEvNotifEnable == MIB_TRUE && 
            (p_rpt->assert_flag || p_rpt->value64 > threshold || threshold == 0))
        {
            over_threshold = TRUE;
        }
        
        break;
        
        /* event flags */
    case EVT_LINK_FAULT:
        value64 = 0xffffffffffffffff;
            
        if (p_rpt->clear_flag != TRUE)
        {
            evt_total = p->c_evt_sum[EVT_LINK_FAULT-256].err_evt_total += 1;
            total64 = evt_total;
        }
                      
        *p_mask = PDU_FLAGS_EV_LF;
        over_threshold = MIB_TRUE; /* link failure cannot mask out */
        break;
        
    case EVT_DYING_GASP:
        value64 = 0xffffffffffffffff;

        if (p_rpt->clear_flag != TRUE)
        {
            evt_total = p->c_evt_sum[EVT_DYING_GASP-256].err_evt_total += 1;
            total64 = evt_total;
        }
                        
        *p_mask = PDU_FLAGS_EV_DGASP;
        over_threshold = (p->evt_cfg.dot3OamDyingGaspEnable == MIB_TRUE) ? TRUE:FALSE;
        break;
        
    case EVT_CRITICAL:
        value64 = 0xffffffffffffffff;

        if (p_rpt->clear_flag != TRUE)
        {
            evt_total = p->c_evt_sum[EVT_CRITICAL-256].err_evt_total += 1;
            total64 = evt_total;
        }
        
        *p_mask = PDU_FLAGS_EV_CEVT;
        over_threshold = (p->evt_cfg.dot3OamCriticalEventEnable == MIB_TRUE) ? TRUE:FALSE;
        break;
    }
    
    if (over_threshold != TRUE)
        return FALSE;
    
    p_log->ifindex = p_rpt->ifindex;
    p_log->dot3OamEventLogIndex = 0 ; /* filled in log function */
    p_log->dot3OamEventLogTimestamp = xos_get_uptime();

    p_log->dot3OamEventLogOui[0] = 0x00;
    p_log->dot3OamEventLogOui[0] = 0x80;
    p_log->dot3OamEventLogOui[0] = 0xc2;

    p_log->dot3OamEventLogType = type;
    p_log->dot3OamEventLogLocation = EVT_LOCAL;
    p_log->dot3OamEventLogValue = value64;
    
    p_log->dot3OamEventLogWindowHi = window_hi;
    p_log->dot3OamEventLogWindowLo = window_lo;
    p_log->dot3OamEventLogThresholdHi = threshold_hi;
    p_log->dot3OamEventLogThresholdLo = threshold_lo;
    p_log->dot3OamEventLogValue = value64;
    p_log->dot3OamEventLogRunningTotal = total64;
    p_log->dot3OamEventLogEventTotal = evt_total;
    
    return TRUE;
}

/**
 * @brief process local system reporting event log and if necessary send
 * event pdu to peer
 *
 * @param p_evt
 * @return oam_err_e
 *
 * FIXME:log assuming the client already ensure the event is over threshold ??
 *
 * The corresponding client function is eoam_req_set_event.
 */
oam_err_e eoam_proc_report_event(eoam_rpt_evt_s *p_rpt)
{
    ifindex_s ifindex;
    dot3_evt_log_s evtlog;
    fsm_port_s *p;
    oam_err_e status = OAM_NO_ERROR;
    uint8_t cevt_mask, cevt_value = 0;;

    xdbg_log(XDBG_INFO, "[0x%08x][%2d] eoam_proc_report_event: type %d",
             pthread_self(), p_rpt->ifindex, p_rpt->evt_type);
    
    ifindex = p_rpt->ifindex;
    p = eoam_fsm_port(ifindex);

    if (p == NULL)
        return INVALID_PORT;

    if ((p_rpt->evt_type > EVT_ERR_FRAME_SEC_EVENT &&
         p_rpt->evt_type < EVT_LINK_FAULT) ||
        p_rpt->evt_type > EVT_CRITICAL)
    {
        xdbg_log(XDBG_ERR, "[%2d] eoam_proc_report_event: invalid event type %d",
            p_rpt->ifindex, p_rpt->evt_type);
        return INVALID_EVENT;
    }

    if (eval_evt_condiation(p, p_rpt, &evtlog, &cevt_mask) != TRUE)
    {
        xdbg_log(XDBG_INFO, "[%2d] eoam_proc_report_event: type %d under threshold or mask disabled, skipped.",
                 p_rpt->ifindex, p_rpt->evt_type);
        return OAM_NO_ERROR;
    }

    evtlog.clear_flag = p_rpt->clear_flag;
    
    if (cevt_mask == 0)
    {
        xdbg_log(XDBG_DEBUG, "[%2d] eoam_proc_report_event type %d (threshold %u:%u, val %llu)",
                 p_rpt->ifindex, evtlog.dot3OamEventLogType,
                 evtlog.dot3OamEventLogThresholdHi, evtlog.dot3OamEventLogThresholdLo,
                 evtlog.dot3OamEventLogValue);

        /* send notification if peer accept event reporting */
        if (fsm_check_peer_config(ifindex, PDU_CODE_EVENT))
            eoam_fsm_send_event_pdu(&evtlog);

        evtlog.dot3OamEventLogLocation = EVT_LOCAL;

        if (p_rpt->no_logging != TRUE)
        {
            if ((status = eoam_log_set_log(&evtlog)) != OAM_NO_ERROR) /* FIXME:log */
            {
                xdbg_log(XDBG_ERR, "[%2d] eoam_proc_report_event: eoam_log_set_log (type %d) failed !!!",
                    ifindex, p_rpt->evt_type);
                return status;
            }
        }

        eoam_cout_report_evt(&evtlog); /* need xdev param */
    }
    else
    {
        /* set the critical event flag in info pdu */
        if (p_rpt->clear_flag != TRUE)
        {
            p->send_flags |= cevt_mask;
        }
        else
        {
            XBITS_CLR_MASK(p->send_flags, cevt_mask);
        }

        /* update critical event status */
        if (p->send_flags & PDU_FLAGS_EV_LF)
            p->evt_cfg.dot3OamLinkFaultStatus = MIB_TRUE;
        else
            p->evt_cfg.dot3OamLinkFaultStatus = MIB_FALSE;


        if (p->send_flags & PDU_FLAGS_EV_DGASP)
            p->evt_cfg.dot3OamDyingGaspStatus = MIB_TRUE;
        else
            p->evt_cfg.dot3OamDyingGaspStatus = MIB_FALSE;

        if (p->send_flags & PDU_FLAGS_EV_CEVT)
            p->evt_cfg.dot3OamCriticalEventStatus = MIB_TRUE;
        else
            p->evt_cfg.dot3OamCriticalEventStatus = MIB_FALSE;

        xdbg_log(XDBG_DEBUG, "[%2d] report critical event flags %02x (mask %2x, val %d)",
                    ifindex, p->send_flags, cevt_mask, cevt_value);

        /* sending updated info pdu (critical event is represented in flags) */
        eoam_fsm_send_info_pdu(ifindex);

        if (p_rpt->no_logging != TRUE)
        {
            if ((status = eoam_log_set_log(&evtlog)) != OAM_NO_ERROR) /* FIXME:log */
            {
                xdbg_log(XDBG_ERR, "[%2d] eoam_proc_report_event: eoam_log_set_log (type %d) failed !!!",
                    ifindex, p_rpt->evt_type);
                return status;
            }
        }

        eoam_cout_report_evt(&evtlog); /* need xdev param */

    }

    return status;
}

oam_err_e eoam_proc_quit(uint32_t dummy)
{
    if (dummy) {}
    
    eoam_fsm_quit();

    return OAM_NO_ERROR;
}

oam_err_e eoam_proc_debug(uint32_t priority)
{
    BOOLEAN retval ;

    retval = xdbg_set_priority((xdbg_prio_e) priority);

    if (retval != TRUE)
        return INVALID_VALUE;

    return OAM_NO_ERROR;
}
