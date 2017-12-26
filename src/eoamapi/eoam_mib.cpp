#include <stdio.h>
#include <stdint.h>

#include "xutl_dbg.h"
#include "xutl_ipc.h"

#include "eoam_xipc.h"
#include "eoam_params.h"


oam_err_e eoam_set_cfg(dot3_oam_cfg_s *oam_cfg)
{
    xipc_s *xipc;
    xipc_hdr_s hdr;
    oam_err_e status = OAM_NO_ERROR;
    xipc_status_s ret_status;
    BOOLEAN retval;

    if (oam_cfg == NULL)
	return INVALID_CONFIG;

    if ((xipc = xipc_unix_client(XIPC_STREAM, (char *)EOAM_CFG_PATH)) == NULL)
	{
	    xdbg_log(XDBG_ERR, "eoam_set_cfg: socket error");
	    return OAM_INTERNAL_ERROR;
	}

    xdbg_log(XDBG_DEBUG, "eoam_set_cfg %d admin %d mode %d",
             oam_cfg->ifindex, oam_cfg->oamAdminState, oam_cfg->oamMode);


    // header
    memset(&hdr, 0, sizeof(xipc_hdr_s));
    hdr.op = EOAM_OP_SET;
    hdr.mtype = EOAM_CONFIG;
    //hdr.dsize = sizeof(dot3_oam_cfg_s);

    retval = xipc_client_put(xipc, &hdr, oam_cfg, sizeof(dot3_oam_cfg_s), &ret_status);
    if (retval == FALSE)
	{
	    xdbg_log(XDBG_ERR, "eoam_set_cfg: xipc_client_put error !!!\n");
	}

    status = (oam_err_e) ret_status;

    xipc_close(xipc);

    return status;
}

oam_err_e eoam_get_cfg(dot3_oam_cfg_s *p_cfg)
{
    xipc_s *xipc;
    xipc_hdr_s hdr;
    oam_err_e status = OAM_NO_ERROR;
    xipc_status_s ret_status;
    BOOLEAN retval;

    if (p_cfg == NULL)
	return INVALID_CONFIG;

    if ((xipc = xipc_unix_client(XIPC_STREAM, (char *)EOAM_CFG_PATH)) == NULL)
	{
	    xdbg_log(XDBG_ERR, "eoam_get_cfg: socket error");
	    return OAM_INTERNAL_ERROR;
	}

    // header
    memset(&hdr, 0, sizeof(xipc_hdr_s));
    hdr.op = EOAM_OP_GET;
    hdr.mtype = EOAM_CONFIG;

    retval = xipc_client_data(xipc, &hdr, p_cfg, sizeof(dot3_oam_cfg_s), &ret_status);
    if (retval == FALSE)
	{
	    xdbg_log(XDBG_ERR, "eoam_get_cfg: xipc_client_data error !!!\n");
	}

    xdbg_log(XDBG_DEBUG, "eoam_get_cfg %d admin %d mode %d",
             p_cfg->ifindex, p_cfg->oamAdminState, p_cfg->oamMode);

    status = (oam_err_e) ret_status;

    xipc_close(xipc);

    return status;
}

oam_err_e eoam_getnext_cfg(dot3_oam_cfg_s *p_cfg)
{
    dot3_oam_cfg_s cfg;
    oam_err_e status;

    if (p_cfg == NULL)
	{
	    xdbg_log(XDBG_ERR, "eoam_getnext_cfg: null pointer !!!");
	    return INVALID_CONFIG;
	}

    memcpy(&cfg, p_cfg, sizeof(dot3_oam_cfg_s));
    cfg.ifindex = p_cfg->ifindex + 1;

    status = eoam_get_cfg(&cfg);

    if (status == OAM_NO_ERROR)
	memcpy(p_cfg, &cfg, sizeof(dot3_oam_cfg_s));

    return status;
}

oam_err_e eoam_get_peer(dot3_peer_s *p_peer)
{
    xipc_s *xipc;
    xipc_hdr_s hdr;
    oam_err_e status = OAM_NO_ERROR;
    xipc_status_s ret_status;
    BOOLEAN retval;

    if (p_peer == NULL)
	return INVALID_CONFIG;

    if ((xipc = xipc_unix_client(XIPC_STREAM, (char *)EOAM_CFG_PATH)) == NULL)
	{
	    xdbg_log(XDBG_ERR, "eoam_get_peer: xipc_unix_client error");
	    return OAM_INTERNAL_ERROR;
	}

    // header
    memset(&hdr, 0, sizeof(xipc_hdr_s));
    hdr.op = EOAM_OP_GET;
    hdr.mtype = EOAM_PEER;

    retval = xipc_client_data(xipc, &hdr, p_peer, sizeof(dot3_peer_s), &ret_status);
    if (retval == FALSE)
	{
	    xdbg_log(XDBG_ERR, "eoam_get_peer: xipc_client_data error !!!\n");
	}

    status = (oam_err_e) ret_status;

    xipc_close(xipc);

    return status;
}

oam_err_e eoam_getnext_peer(dot3_peer_s *p_peer)
{
    dot3_peer_s peer;
    oam_err_e status;

    if (p_peer == NULL)
	{
	    xdbg_log(XDBG_ERR, "eoam_getnext_cfg: null pointer !!!");
	    return INVALID_CONFIG;
	}

    memcpy(&peer, p_peer, sizeof(dot3_peer_s));
    peer.ifindex = p_peer->ifindex + 1;

    status = eoam_get_peer(&peer);

    if (status == OAM_NO_ERROR)
	memcpy(p_peer, &peer, sizeof(dot3_peer_s));

    return status;
}

oam_err_e eoam_set_lpbk(dot3_lpbk_cfg_s *p_lpbk)
{
    xipc_s *xipc;
    xipc_hdr_s hdr;
    oam_err_e status = OAM_NO_ERROR;
    xipc_status_s ret_status;
    BOOLEAN retval;

    if (p_lpbk == NULL)
	{
	    xdbg_log(XDBG_ERR, "eoam_set_lpbk: null pointer !!!");
	    return INVALID_CONFIG;
	}

    if ((xipc = xipc_unix_client(XIPC_STREAM, (char *)EOAM_CFG_PATH)) == NULL)
	{
	    xdbg_log(XDBG_ERR, "eoam_set_lpbk: xipc_unix_client error");
	    return OAM_INTERNAL_ERROR;
	}

    xdbg_log(XDBG_DEBUG, "eoam_set_lpbk %d status %d ignore-rx %d",
             p_lpbk->ifindex, p_lpbk->oamLoopbackStatus, p_lpbk->oamLoopbackIgnoreRx);


    // header
    memset(&hdr, 0, sizeof(xipc_hdr_s));
    hdr.op = EOAM_OP_SET;
    hdr.mtype = EOAM_LPBK;

    retval = xipc_client_put(xipc, &hdr, p_lpbk, sizeof(dot3_lpbk_cfg_s), &ret_status);
    if (retval == FALSE)
	{
	    xdbg_log(XDBG_ERR, "eoam_set_lpbk: xipc_client_put error !!!\n");
	}

    status = (oam_err_e) ret_status;

    xipc_close(xipc);

    return status;
}

oam_err_e eoam_get_lpbk(dot3_lpbk_cfg_s *p_lpbk)
{
    xipc_s *xipc;
    xipc_hdr_s hdr;
    oam_err_e status = OAM_NO_ERROR;
    xipc_status_s ret_status;
    BOOLEAN retval;

    if (p_lpbk == NULL)
	{
	    xdbg_log(XDBG_ERR, "eoam_get_lpbk: null pointer !!!");
	    return INVALID_CONFIG;
	}

    if ((xipc = xipc_unix_client(XIPC_STREAM, (char *)EOAM_CFG_PATH)) == NULL)
	{
	    xdbg_log(XDBG_ERR, "eoam_get_lpbk: xipc_unix_client error");
	    return OAM_INTERNAL_ERROR;
	}

    // header
    memset(&hdr, 0, sizeof(xipc_hdr_s));
    hdr.op = EOAM_OP_GET;
    hdr.mtype = EOAM_LPBK;

    retval = xipc_client_data(xipc, &hdr, p_lpbk, sizeof(dot3_lpbk_cfg_s), &ret_status);
    if (retval == FALSE)
	{
	    xdbg_log(XDBG_ERR, "eoam_get_lpbk: xipc_client_data error !!!\n");
	}

    xdbg_log(XDBG_DEBUG, "eoam_get_lpbk %d status %d ignore-rx %d",
             p_lpbk->ifindex, p_lpbk->oamLoopbackStatus, p_lpbk->oamLoopbackIgnoreRx);

    status = (oam_err_e) ret_status;

    xipc_close(xipc);

    return status;
}

oam_err_e eoam_getnext_lpbk(dot3_lpbk_cfg_s *p_lpbk)
{
    dot3_lpbk_cfg_s lpbk;
    oam_err_e status;

    if (p_lpbk == NULL)
	{
	    xdbg_log(XDBG_ERR, "eoam_getnext_lpbk: null pointer !!!");
	    return INVALID_CONFIG;
	}

    memcpy(&lpbk, p_lpbk, sizeof(dot3_lpbk_cfg_s));
    lpbk.ifindex = p_lpbk->ifindex + 1;

    status = eoam_get_lpbk(&lpbk);

    if (status == OAM_NO_ERROR)
	memcpy(p_lpbk, &lpbk, sizeof(dot3_lpbk_cfg_s));

    return status;
}

oam_err_e eoam_get_stats(dot3_oam_stats_s *p_stats)
{
    xipc_s *xipc;
    xipc_hdr_s hdr;
    oam_err_e status = OAM_NO_ERROR;
    xipc_status_s ret_status;
    BOOLEAN retval;

    if (p_stats == NULL)
	{
	    xdbg_log(XDBG_ERR, "eoam_get_stats: null pointer !!!");
	    return INVALID_CONFIG;
	}

    if ((xipc = xipc_unix_client(XIPC_STREAM, (char *)EOAM_CFG_PATH)) == NULL)
	{
	    xdbg_log(XDBG_ERR, "eoam_get_stats: xipc_unix_client error");
	    return OAM_INTERNAL_ERROR;
	}

    // header
    memset(&hdr, 0, sizeof(xipc_hdr_s));
    hdr.op = EOAM_OP_GET;
    hdr.mtype = EOAM_STATS;

    retval = xipc_client_data(xipc, &hdr, p_stats, sizeof(dot3_oam_stats_s), &ret_status);
    if (retval == FALSE)
	{
	    xdbg_log(XDBG_ERR, "eoam_get_stats: xipc_client_data error !!!\n");
	}

    status = (oam_err_e) ret_status;

    xipc_close(xipc);

    return status;
}

oam_err_e eoam_getnext_stats(dot3_oam_stats_s *p_stats)
{
    dot3_oam_stats_s stats;
    oam_err_e status;

    if (p_stats == NULL)
	{
	    xdbg_log(XDBG_ERR, "eoam_getnext_lpbk: null pointer !!!");
	    return INVALID_CONFIG;
	}

    memcpy(&stats, p_stats, sizeof(dot3_oam_stats_s));
    stats.ifindex = p_stats->ifindex + 1;

    status = eoam_get_stats(&stats);

    if (status == OAM_NO_ERROR)
	memcpy(p_stats, &stats, sizeof(dot3_oam_stats_s));

    return status;
}

oam_err_e eoam_set_evt_cfg(dot3_evt_cfg_s *p_evtcfg)
{
    xipc_s *xipc;
    xipc_hdr_s hdr;
    oam_err_e status = OAM_NO_ERROR;
    xipc_status_s ret_status;
    BOOLEAN retval;

    if (p_evtcfg == NULL)
	{
	    xdbg_log(XDBG_ERR, "eoam_set_evt_cfg: null pointer !!!");
	    return INVALID_CONFIG;
	}

    if ((xipc = xipc_unix_client(XIPC_STREAM, (char *)EOAM_CFG_PATH)) == NULL)
	{
	    xdbg_log(XDBG_ERR, "eoam_set_evt_cfg: xipc_unix_client error");
	    return OAM_INTERNAL_ERROR;
	}

    // header
    memset(&hdr, 0, sizeof(xipc_hdr_s));
    hdr.op = EOAM_OP_SET;
    hdr.mtype = EOAM_EVENT_CFG;

    retval = xipc_client_put(xipc, &hdr, p_evtcfg, sizeof(dot3_evt_cfg_s), &ret_status);
    if (retval == FALSE)
	{
	    xdbg_log(XDBG_ERR, "eoam_set_evt_cfg: xipc_client_put error !!!\n");
	}

    status = (oam_err_e) ret_status;

    xipc_close(xipc);

    return status;
}

oam_err_e eoam_get_evt_cfg(dot3_evt_cfg_s *p_evtcfg)
{
    xipc_s *xipc;
    xipc_hdr_s hdr;
    oam_err_e status = OAM_NO_ERROR;
    xipc_status_s ret_status;
    BOOLEAN retval;

    if (p_evtcfg == NULL)
	{
	    xdbg_log(XDBG_ERR, "eoam_get_evt_cfg: null pointer !!!");
	    return INVALID_CONFIG;
	}

    if ((xipc = xipc_unix_client(XIPC_STREAM, (char *)EOAM_CFG_PATH)) == NULL)
	{
	    xdbg_log(XDBG_ERR, "eoam_get_evt_cfg: xipc_unix_client error");
	    return OAM_INTERNAL_ERROR;
	}

    // header
    memset(&hdr, 0, sizeof(xipc_hdr_s));
    hdr.op = EOAM_OP_GET;
    hdr.mtype = EOAM_EVENT_CFG;

    retval = xipc_client_data(xipc, &hdr, p_evtcfg, sizeof(dot3_evt_cfg_s), &ret_status);
    if (retval == FALSE)
	{
	    xdbg_log(XDBG_ERR, "eoam_get_evt_cfg: xipc_client_data error !!!\n");
	}

    status = (oam_err_e) ret_status;

    xipc_close(xipc);

    return status;
}

oam_err_e eoam_getnext_evt_cfg(dot3_evt_cfg_s *p_evtcfg)
{
    dot3_evt_cfg_s evtcfg;
    oam_err_e status;

    if (p_evtcfg == NULL)
	{
	    xdbg_log(XDBG_ERR, "eoam_getnext_evt_cfg: null pointer !!!");
	    return INVALID_CONFIG;
	}

    memcpy(&evtcfg, p_evtcfg, sizeof(dot3_evt_cfg_s));
    evtcfg.ifindex = p_evtcfg->ifindex + 1;

    status = eoam_get_evt_cfg(&evtcfg);

    if (status == OAM_NO_ERROR)
	memcpy(p_evtcfg, &evtcfg, sizeof(dot3_evt_cfg_s));

    return status;
}

oam_err_e eoam_get_evt_log(dot3_evt_log_s *p_log)
{
    xipc_s *xipc;
    xipc_hdr_s hdr;
    oam_err_e status = OAM_NO_ERROR;
    xipc_status_s ret_status;
    BOOLEAN retval;
    
    if (p_log == NULL)
    {
        xdbg_log(XDBG_ERR, "eoam_get_evt_log: null pointer !!!");
        return INVALID_CONFIG;
    }
    
    if ((xipc = xipc_unix_client(XIPC_STREAM, (char *)EOAM_CFG_PATH)) == NULL)
    {
        xdbg_log(XDBG_ERR, "eoam_get_evt_log: xipc_unix_client error");
        return OAM_INTERNAL_ERROR;
    }
    
    // header
    memset(&hdr, 0, sizeof(xipc_hdr_s));
    hdr.op = EOAM_OP_GET;
    hdr.mtype = EOAM_EVENT_LOG;
    
    retval = xipc_client_data(xipc, &hdr, p_log, sizeof(dot3_evt_log_s), &ret_status);
    if (retval == FALSE)
    {
        xdbg_log(XDBG_ERR, "eoam_get_evt_log: xipc_client_data error !!!\n");
    }
    
    status = (oam_err_e) ret_status;
    
    xipc_close(xipc);
    
    return status;
}

oam_err_e eoam_getnext_evt_log(dot3_evt_log_s *p_log)
{
    xipc_s *xipc;
    xipc_hdr_s hdr;
    oam_err_e status = OAM_NO_ERROR;
    xipc_status_s ret_status;
    BOOLEAN retval;
    
    if (p_log == NULL)
    {
        xdbg_log(XDBG_ERR, "eoam_get_evt_log: null pointer !!!");
        return INVALID_CONFIG;
    }
    
    if ((xipc = xipc_unix_client(XIPC_STREAM, (char *)EOAM_CFG_PATH)) == NULL)
    {
        xdbg_log(XDBG_ERR, "eoam_get_evt_log: xipc_unix_client error");
        return OAM_INTERNAL_ERROR;
    }
    
    // header
    memset(&hdr, 0, sizeof(xipc_hdr_s));
    hdr.op = EOAM_OP_GETNEXT;
    hdr.mtype = EOAM_EVENT_LOG;
    
    retval = xipc_client_data(xipc, &hdr, p_log, sizeof(dot3_evt_log_s), &ret_status);
    if (retval == FALSE)
    {
        xdbg_log(XDBG_ERR, "eoam_get_evt_log: xipc_client_data error !!!\n");
    }
    
    status = (oam_err_e) ret_status;
    
    xipc_close(xipc);
    
    return status;
}

BOOLEAN eoam_set_evt_mask(dot3_evt_cfg_s *p_evtcfg, mib_evt_type_e evt_type, 
    mib_truth_e flag)
{
    BOOLEAN retval = TRUE;

    if (p_evtcfg == NULL)
        return FALSE;

    if (flag != MIB_TRUE && flag != MIB_FALSE)
        return FALSE;

    switch (evt_type)
    {
    case EVT_ERR_SYMBOL_PERIOD:
        p_evtcfg->dot3OamErrSymPeriodEvNotifEnable = flag;
        break;
    case EVT_ERR_FRAME_PERIOD:
        p_evtcfg->dot3OamErrFramePeriodEvNotifEnable = flag;
        break;
    case EVT_ERR_FRAME_EVENT:
        p_evtcfg->dot3OamErrFrameEvNotifEnable = flag;
        break;
    case EVT_ERR_FRAME_SEC_EVENT:
        p_evtcfg->dot3OamErrFrameSecsEvNotifEnable = flag;
        break;
    case EVT_LINK_FAULT:
        if (flag != MIB_TRUE)
            retval = FALSE;
        break;
    case EVT_DYING_GASP:
        p_evtcfg->dot3OamDyingGaspEnable = flag;
        break;
    case EVT_CRITICAL:
        p_evtcfg->dot3OamCriticalEventEnable = flag;
        break;
    default:
        retval = FALSE;
        break;
    }

    return retval; 
}

BOOLEAN eoam_get_evt_mask(dot3_evt_cfg_s *p_evtcfg, mib_evt_type_e evt_type, 
    mib_truth_e *p_flag)
{
    BOOLEAN retval = TRUE;

    if (p_evtcfg == NULL || p_flag == NULL)
        return FALSE;
    
    switch (evt_type)
    {
    case EVT_ERR_SYMBOL_PERIOD:
        *p_flag = p_evtcfg->dot3OamErrSymPeriodEvNotifEnable ;
        break;
    case EVT_ERR_FRAME_PERIOD:
        *p_flag = p_evtcfg->dot3OamErrFramePeriodEvNotifEnable ;
        break;
    case EVT_ERR_FRAME_EVENT:
        *p_flag = p_evtcfg->dot3OamErrFrameEvNotifEnable ;
        break;
    case EVT_ERR_FRAME_SEC_EVENT:
        *p_flag = p_evtcfg->dot3OamErrFrameSecsEvNotifEnable ;
        break;
    case EVT_LINK_FAULT:
        *p_flag = MIB_TRUE;
        break;
    case EVT_DYING_GASP:
        *p_flag = p_evtcfg->dot3OamDyingGaspEnable ;
        break;
    case EVT_CRITICAL:
        *p_flag = p_evtcfg->dot3OamCriticalEventEnable ;
        break;
    default:
        retval = FALSE;
        break;
    }

    return retval; 
}

BOOLEAN eoam_get_cevt_status(dot3_evt_cfg_s *p_evtcfg, mib_evt_type_e evt_type,
                          mib_truth_e *p_flag)
{
    BOOLEAN retval = TRUE;
    
    if (p_evtcfg == NULL || p_flag == NULL)
        return FALSE;
    
    switch (evt_type)
    {
        case EVT_LINK_FAULT:
            *p_flag = p_evtcfg->dot3OamLinkFaultStatus;
            break;
        case EVT_DYING_GASP:
            *p_flag = p_evtcfg->dot3OamDyingGaspStatus ;
            break;
        case EVT_CRITICAL:
            *p_flag = p_evtcfg->dot3OamCriticalEventStatus ;
            break;
        default:
            retval = FALSE;
            break;
    }
    
    return retval;
}



