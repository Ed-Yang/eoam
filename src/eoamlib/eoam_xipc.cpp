
#include "xutl_dbg.h"

#include "eoam_xipc.h"
#include "eoam_pdu.h"
#include "eoam_proc.h"
#include "eoam_mib.h"
#include "eoam_log.h"
#include "eoam_rx.h"

#include "eoam_timer.h"
#include "eoam_fsm.h" // only for user_init

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
    //uint8_t *packet = (uint8_t *)data;
    //static int cnt=0;
    oam_pdu_hdr_t *p_pdu = (oam_pdu_hdr_t *) data;
    oam_err_e status = OAM_NO_ERROR;
    ifindex_s ifindex = xhdr->value;
    
    if (xipc) {}
    if (param) {}

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


