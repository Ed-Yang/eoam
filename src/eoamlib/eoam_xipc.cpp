#include <arpa/inet.h>

#include "xutl_dbg.h"

#include "eoam_xipc.h"
#include "eoam_pdu.h"
#include "eoam_proc.h"
#include "eoam_mib.h"
#include "eoam_log.h"
#include "eoam_rx.h"
#include "eoam_str.h"

#include "eoam_timer.h"
#include "eoam_fsm.h" // only for user_init

/**
 * invalidate packet met one of the following conditions:
 *
 * - loopback (might be drop in low layer (OSX) or OS (Linux))
 * - non-OAM pdu
 * - etc.
 *
 */
BOOLEAN _validate_oam_pdu(fsm_port_s *p, oam_pdu_hdr_t *p_pdu, size_t pdu_size)
{
    uint8_t *packet = (uint8_t *) p_pdu;

    if (pdu_size) {}

    /* drop loopback */
    if (memcmp(&packet[6], p->pmac, MAC_ADRS_SIZE) == 0)
    {
        /* in OSX, it will receive the loopback page, but not in Linux */
        xdbg_log(XDBG_INFO, "drop loopback %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
                 packet[0], packet[1], packet[2], packet[3], packet[4], packet[5],
                 packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);

        return FALSE;
    }

    /* type (0xx8809) */
    if (ntohs(p_pdu->type) != OAM_PDU_TYPE)
    {
        xdbg_log(XDBG_DEBUG, "drop non-oam type (0x%04x) packet", ntohs(p_pdu->type));
        return FALSE;
    }

    /* subtype */
    if (p_pdu->subtype != OAM_PDU_SUBTYPE)
    {
        xdbg_log(XDBG_DEBUG, "drop non-oam sub-type (%d) %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
                 p_pdu->subtype, packet[0], packet[1], packet[2], packet[3], packet[4], packet[5],
                 packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);

        return FALSE;
    }

    /* flags (reserved) */
    if (p_pdu->flags_reserved != 0)
    {
        xdbg_log(XDBG_DEBUG, "drop non-oam non-zero reserved flags (0x%02x) packet", p_pdu->flags_reserved);
        return FALSE;
    }

    /* flags */

    /* code */
    if (p_pdu->code > PDU_CODE_LPBK)
    {
        xdbg_log(XDBG_DEBUG, "drop invalid or unsupported pdu (code=%d) packet", p_pdu->code);
        return FALSE;
    }

    return TRUE;
}

/**
 *--------------------------------------------------------------------------
 * globals
 *--------------------------------------------------------------------------
 */

static xnet_s *g_xnet_handle = NULL;
pthread_t g_fsm_net_tid;

xtimer_s *g_fsm_timer;

static xipc_s *g_cfg_xipc = NULL;
static xipc_s *g_pkt_xipc = NULL;

void eoam_xipc_register_handler()
{
    xipc_hdr_s hdr;
    
    // packet
    hdr.op = EOAM_OP_EVENT;
    hdr.mtype = EOAM_PACKET;
    xipc_set_group_handler(g_pkt_xipc, &hdr, eoam_xipc_handle_packet, 0, NULL);

    // config
    hdr.op = EOAM_OP_SET;
    hdr.mtype = EOAM_CONFIG;
    xipc_set_data_handler(g_cfg_xipc, &hdr, (xipc_data_cb_s *)eoam_proc_set_port_cfg, sizeof(dot3_oam_cfg_s));

    hdr.op = EOAM_OP_GET;
    hdr.mtype = EOAM_CONFIG;
    xipc_set_data_handler(g_cfg_xipc, &hdr, (xipc_data_cb_s *)eoam_proc_get_port_cfg, sizeof(dot3_oam_cfg_s));

    hdr.op = EOAM_OP_GET;
    hdr.mtype = EOAM_PEER;
    xipc_set_data_handler(g_cfg_xipc, &hdr, (xipc_data_cb_s *)eoam_proc_get_peer, sizeof(dot3_peer_s));

    // lpbk
    hdr.op = EOAM_OP_SET;
    hdr.mtype = EOAM_LPBK;
    xipc_set_data_handler(g_cfg_xipc, &hdr, (xipc_data_cb_s *)eoam_proc_set_lpbk, sizeof(dot3_lpbk_cfg_s));
    
    hdr.op = EOAM_OP_GET;
    hdr.mtype = EOAM_LPBK;
    xipc_set_data_handler(g_cfg_xipc, &hdr, (xipc_data_cb_s *)eoam_proc_get_lpbk, sizeof(dot3_lpbk_cfg_s));
    
    // stats
    hdr.op = EOAM_OP_GET;
    hdr.mtype = EOAM_STATS;
    xipc_set_data_handler(g_cfg_xipc, &hdr, (xipc_data_cb_s *)eoam_proc_get_stats, sizeof(dot3_oam_stats_s));

    hdr.op = EOAM_OP_EXEC;
    hdr.mtype = EOAM_STATS;
    xipc_set_exec_handler(g_cfg_xipc, &hdr, (xipc_exec_cb_s *)eoam_proc_clear_stats);

    // event config
    hdr.op = EOAM_OP_SET;
    hdr.mtype = EOAM_EVENT_CFG;
    xipc_set_data_handler(g_cfg_xipc, &hdr, (xipc_data_cb_s *)eoam_proc_set_evt_cfg, sizeof(dot3_evt_cfg_s));
    
    hdr.op = EOAM_OP_GET;
    hdr.mtype = EOAM_EVENT_CFG;
    xipc_set_data_handler(g_cfg_xipc, &hdr, (xipc_data_cb_s *)eoam_proc_get_evt_cfg, sizeof(dot3_evt_cfg_s));
    
    hdr.op = EOAM_OP_SET;
    hdr.mtype = EOAM_REPORT_EVENT;
    xipc_set_data_handler(g_cfg_xipc, &hdr, (xipc_data_cb_s *)eoam_proc_report_event, sizeof(eoam_rpt_evt_s));
    
    hdr.op = EOAM_OP_GET;
    hdr.mtype = EOAM_EVENT_LOG;
    xipc_set_data_handler(g_cfg_xipc, &hdr, (xipc_data_cb_s *)eoam_proc_get_log, sizeof(dot3_evt_log_s));

    hdr.op = EOAM_OP_GETNEXT;
    hdr.mtype = EOAM_EVENT_LOG;
    xipc_set_data_handler(g_cfg_xipc, &hdr, (xipc_data_cb_s *)eoam_proc_getnext_log, sizeof(dot3_evt_log_s));

    hdr.op = EOAM_OP_EXEC;
    hdr.mtype = EOAM_EVENT_LOG;
    xipc_set_exec_handler(g_cfg_xipc, &hdr, eoam_proc_clear_log);

    hdr.op = EOAM_OP_EXEC;
    hdr.mtype = EOAM_EVENT_QUIT;
    xipc_set_exec_handler(g_cfg_xipc, &hdr, (xipc_exec_cb_s *)eoam_proc_quit);

    hdr.op = EOAM_OP_EXEC;
    hdr.mtype = EOAM_EVENT_DEBUG;
    xipc_set_exec_handler(g_cfg_xipc, &hdr, (xipc_exec_cb_s *)eoam_proc_debug);
    
}

xipc_status_s eoam_xipc_handle_packet(xipc_s *xipc, xipc_hdr_s *xhdr,
                              void *data, size_t *size, // FIXME
                              void *param)
{
    oam_pdu_hdr_t *p_pdu = (oam_pdu_hdr_t *) data;
    oam_err_e status = OAM_NO_ERROR;
    ifindex_s ifindex = xhdr->value;
    fsm_port_s *p = eoam_fsm_port(ifindex);
    uint8_t rmt_flags = 0;
    char buf[32];
    char zero_mac[] = {0, 0, 0, 0, 0, 0};

    if (xipc) {}
    if (param) {}

    if (p == NULL)
    {
        xdbg_log(XDBG_ERR, "[%02d] invalid ifindex !!!", ifindex);
        return (xipc_status_s)INVALID_PORT;
    }

    /* if oam admin is disabled, drop pdu */
    if (p->cfg.oamAdminState == OAM_ADMIN_DISABLED)
    {
        xdbg_log(XDBG_ERR, "[%02d] oam is disabled, drop pdu, flag:(%02x):%s",
                 ifindex,
                 p_pdu->flags,
                 eoam_str_info_flags(p_pdu->flags, buf));
        return (xipc_status_s)INVALID_PORT;
    }

    if (!_validate_oam_pdu(p, p_pdu, *size))
    {
        xdbg_log(XDBG_DEBUG, "eoam_proc_info_pdu_indication: drop invalid pdu format or loopback !!!");
        return (xipc_status_s)INVALID_OAM_PDU;
    }

    /**
     * if in remote_state_valid, verify the peer is the same one by src-mac, or
     * just drop the packet and wait the session timeout
     */
    if (memcmp(p->peer_mac, zero_mac, MAC_ADRS_SIZE) != 0)
    {
        if (memcmp(p->peer_mac, p_pdu->sa, MAC_ADRS_SIZE) != 0)
        {
            xdbg_log(XDBG_INFO, "session ongoing, pdu  mac:%02x:%02x:%02x:%02x:%02x:%02x !!!",
                     p_pdu->sa[0], p_pdu->sa[1], p_pdu->sa[2],
                     p_pdu->sa[3], p_pdu->sa[4], p_pdu->sa[5]);

            xdbg_log(XDBG_INFO, "session ongoing, save mac:%02x:%02x:%02x:%02x:%02x:%02x !!!",
                     p->peer_mac[0], p->peer_mac[1], p->peer_mac[2],
                     p->peer_mac[3], p->peer_mac[4], p->peer_mac[5]);

            return (xipc_status_s)INVALID_OAM_PDU;
        }
    }

    switch (p_pdu->code)
    {
        case PDU_CODE_INFO: // only accept one local and one remote
            status = eoam_proc_info_pdu_indication(ifindex, p_pdu, *size);
            break;
        case PDU_CODE_LPBK:
#if OAM_PARAM_DROP_LPBK
            xdbg_log(XDBG_INFO, "[%2d:XX] debug drop received lpbk pdu", ifindex); 
#else
            status = eoam_proc_lpbk_pdu_indication(ifindex, p_pdu, *size);
#endif
            break;
        case PDU_CODE_EVENT:
            status = eoam_proc_evt_pdu_indication(ifindex, p_pdu, *size);
            break;
        default:
            xdbg_log(XDBG_ERR, "eoam_xipc_handle_packet: --- unhandled code (%d)", p_pdu->code);
            status = eoam_proc_other_pdu_indication(ifindex, p_pdu, *size);
            
            break;
    }
    
    /* 
     * copy remote flags 
     */
    if (status == OAM_NO_ERROR)
    {
        /* eval */
        if (p_pdu->flags & PDU_FLAGS_L_EVAL)
        {
            rmt_flags |= PDU_FLAGS_R_EVAL;
        }

        /* stable */
        if (p_pdu->flags & PDU_FLAGS_L_STABLE)
        {
            rmt_flags |= PDU_FLAGS_R_STABLE;
        }

        /* update pdu flags */
        PDU_FLAGS_R_SETV(p->send_flags, rmt_flags);

        /* save remote flags */
        p->remote_flags = p_pdu->flags;
        //xdbg_log(XDBG_INFO, "eoam_xipc_handle_packet: remote_flags = %d", p->remote_flags);
    }

    return status;
}

BOOLEAN eoam_xipc_init(char *pkt_path, char *cfg_path)
{
    if ((g_pkt_xipc = xipc_unix_server(XIPC_DGRAM, (char *)pkt_path, 0)) == NULL)
        return FALSE;

    if ((g_cfg_xipc = xipc_unix_server(XIPC_STREAM, (char *)cfg_path, 0)) == NULL)
        return FALSE;

    if (eoam_rx_init(pkt_path) != TRUE)
        return FALSE;
    
    eoam_xipc_register_handler();

    g_xnet_handle = xnet_open(eoam_fsm_usr_init, NULL);

    /* fsm & pdu timer */
    g_fsm_timer = xnet_add_timer(g_xnet_handle, 1000,
                                 eoam_fsm_timer_handler, NULL, FALSE);

    xnet_start_timer(g_fsm_timer);

    /* io callback */
    xnet_add_socket(g_xnet_handle, eoam_xipc_cfg_fd(), xipc_process_trans, 
        (void *)eoam_xipc_cfg());
        
    xnet_add_socket(g_xnet_handle, eoam_xipc_pkt_fd(), xipc_process_trans, 
        (void *)eoam_xipc_pkt());

    /* start fsm */
    if (xnet_start(g_xnet_handle, NULL, NULL, 0) == FALSE)
        return FALSE;

    return TRUE;
}

BOOLEAN eoam_xipc_terminate()
{
    eoam_rx_terminate();

    if (g_pkt_xipc)
        xipc_close(g_pkt_xipc);

    if (g_cfg_xipc)
        xipc_close(g_cfg_xipc);

    xdbg_log(XDBG_INFO, "eoam_fsm_terminate: stop net");
    xnet_stop(g_xnet_handle);

    xdbg_log(XDBG_INFO, "eoam_fsm_terminate: close net");
    xnet_close(g_xnet_handle);

    return TRUE;
}

int eoam_xipc_cfg_fd()
{
    int fd = 0;
    
    if (g_cfg_xipc)
        fd = xipc_get_fd(g_cfg_xipc);
    
    return fd;
}

int eoam_xipc_pkt_fd()
{
    int fd = 0;
    
    if (g_pkt_xipc)
        fd = xipc_get_fd(g_pkt_xipc);
    
    return fd;
}

xipc_s *eoam_xipc_cfg()
{
    return g_cfg_xipc;
}

xipc_s *eoam_xipc_pkt()
{
    return g_pkt_xipc;
}


