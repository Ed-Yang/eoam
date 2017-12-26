/**
 * @file    eoam_if.c
 * @brief  the public function for user to interact with oam
 *
 * 
 */

#include <stdio.h>

#include "xutl_os.h"
#include "xutl_ipc.h"

#include "eoam_mib.h"
#include "eoam_if.h"
#include "eoam_xipc.h"

#include "eoam_params.h"

oam_err_e eoam_req_report_event(eoam_rpt_evt_s *p_rpt)
{
    xipc_s *xipc;
    xipc_hdr_s hdr;
    oam_err_e status = OAM_NO_ERROR;
    BOOLEAN retval ;
    xipc_status_s ret_status;

    // data    
    if ((xipc = xipc_unix_client(XIPC_STREAM, (char *)EOAM_CFG_PATH)) == NULL)
    {
        xdbg_log(XDBG_ERR, "eoam_req_report_event: socket client !!!\n");
        return OAM_INTERNAL_ERROR;
    }

    // header
    memset(&hdr, 0, sizeof(xipc_hdr_s));
    hdr.op = EOAM_OP_SET;
    hdr.mtype = EOAM_REPORT_EVENT;

    retval = xipc_client_put(xipc, &hdr, p_rpt, sizeof(eoam_rpt_evt_s), &ret_status);
    if (retval == FALSE)
    {
        xdbg_log(XDBG_ERR, "eoam_req_report_event: xipc_client_event error !!!\n");
    }
    
    status = (oam_err_e) ret_status;
    
    xipc_close(xipc);

    return status;
}

/**
 * eoam_req_set_event (deprecated)
 * 
 *  @ifindex
 *  @dot3OamEventLogType
 *  @dot3OamEventLogValue
 * 
 * Comment:
 *
 *  if the listed filed value is 0, it will be caculated or filled in with lower layer:
 *
 *  @dot3OamEventLogTimestamp
 *  @dot3OamEventLogOui
 *  @dot3OamEventLogLocation
 *  @dot3OamEventLogWindowHi
 *  @dot3OamEventLogWindowLo
 *  @dot3OamEventLogThresholdHi
 *  @dot3OamEventLogThresholdLo
 *  @dot3OamEventLogRunningTotal (sum of EventLogValue)
 *  @dot3OamEventLogEventTotal (sum of number of event occurred)
 */
oam_err_e eoam_req_set_event(dot3_evt_log_s *p_evt)
{
    xipc_s *xipc;
    xipc_hdr_s hdr;
    oam_err_e status = OAM_NO_ERROR;
    BOOLEAN retval ;
    xipc_status_s ret_status;

    // data    
    if ((xipc = xipc_unix_client(XIPC_STREAM, (char *)EOAM_CFG_PATH)) == NULL)
    {
        xdbg_log(XDBG_ERR, "eoam_set_event: socket client !!!\n");
        return OAM_INTERNAL_ERROR;
    }

    // header
    memset(&hdr, 0, sizeof(xipc_hdr_s));
    hdr.op = EOAM_OP_SET;
    hdr.mtype = EOAM_EVENT_LOG;

    retval = xipc_client_put(xipc, &hdr, p_evt, sizeof(dot3_evt_log_s), &ret_status);
    if (retval == FALSE)
    {
        xdbg_log(XDBG_ERR, "eoam_set_event: xipc_client_event error !!!\n");
    }
    
    status = (oam_err_e) ret_status;
    
    xipc_close(xipc);

    return status;
}

/**
 * @brief 
 * 
 * @param ifindex 0 for clear all
 * @return oam_err_e 
 * 
 */
oam_err_e eoam_req_clear_stats(ifindex_s ifindex)
{
    xipc_s *xipc;
    xipc_hdr_s hdr;
    oam_err_e status = OAM_NO_ERROR;
    BOOLEAN retval ;
    xipc_status_s ret_status;

    // data    
    if ((xipc = xipc_unix_client(XIPC_STREAM, (char *)EOAM_CFG_PATH)) == NULL)
    {
        xdbg_log(XDBG_ERR, "eoam_clear_stats: socket client !!!\n");
        return OAM_INTERNAL_ERROR;
    }

    // header
    memset(&hdr, 0, sizeof(xipc_hdr_s));
    hdr.op = EOAM_OP_EXEC;
    hdr.mtype = EOAM_STATS;
    hdr.value = ifindex;

    retval = xipc_client_exec(xipc, &hdr, &ret_status);
    if (retval == FALSE)
    {
        xdbg_log(XDBG_ERR, "eoam_clear_stats: xipc_client_event error !!!\n");
    }
    
    status = (oam_err_e) ret_status;
    
    xipc_close(xipc);

    return status;
}

oam_err_e eoam_req_clear_log(void)
{
    xipc_s *xipc;
    xipc_hdr_s hdr;
    oam_err_e status = OAM_NO_ERROR;
    BOOLEAN retval ;
    xipc_status_s ret_status;

    // data    
    if ((xipc = xipc_unix_client(XIPC_STREAM, (char *)EOAM_CFG_PATH)) == NULL)
    {
        xdbg_log(XDBG_ERR, "eoam_clear_log: socket client !!!\n");
        return OAM_INTERNAL_ERROR;
    }

    // header
    memset(&hdr, 0, sizeof(xipc_hdr_s));
    hdr.op = EOAM_OP_EXEC;
    hdr.mtype = EOAM_EVENT_LOG;
    hdr.value = 777; /* just for test, no meaning */

    retval = xipc_client_exec(xipc, &hdr, &ret_status);
    if (retval == FALSE)
    {
        xdbg_log(XDBG_ERR, "eoam_clear_log: xipc_client_event error !!!\n");
    }
    
    status = (oam_err_e) ret_status;
    
    xipc_close(xipc);

    return status;
}

oam_err_e eoam_req_quit(void)
{
    xipc_s *xipc;
    xipc_hdr_s hdr;
    oam_err_e status = OAM_NO_ERROR;
    BOOLEAN retval ;
    xipc_status_s ret_status;

    // data    
    if ((xipc = xipc_unix_client(XIPC_STREAM, (char *)EOAM_CFG_PATH)) == NULL)
    {
        xdbg_log(XDBG_ERR, "eoam_clear_log: socket client !!!\n");
        return OAM_INTERNAL_ERROR;
    }

    /*
     * extend the timeout, so the client will not close the xnet and then the eoam
     * is not able to send the response.
     */
    xipc_set_timeout(xipc, 2000);
    
    // header
    memset(&hdr, 0, sizeof(xipc_hdr_s));
    hdr.op = EOAM_OP_EXEC;
    hdr.mtype = EOAM_EVENT_QUIT;
    hdr.value = 777; /* just for test, no meaning */

    retval = xipc_client_exec(xipc, &hdr, &ret_status);
    if (retval == FALSE)
    {
        xdbg_log(XDBG_ERR, "eoam_clear_log: xipc_client_event error !!!\n");
    }
    
    status = (oam_err_e) ret_status;
    
    xipc_close(xipc);

    return status;
}

oam_err_e eoam_req_debug_priority(xdbg_prio_e priority)
{
    xipc_s *xipc;
    xipc_hdr_s hdr;
    oam_err_e status = OAM_NO_ERROR;
    BOOLEAN retval ;
    xipc_status_s ret_status;

    xdbg_log(XDBG_NOTICE, "eoam_req_debug_priority: priority = %d\n",
        priority);

    // data    
    if ((xipc = xipc_unix_client(XIPC_STREAM, (char *)EOAM_CFG_PATH)) == NULL)
    {
        xdbg_log(XDBG_ERR, "eoam_clear_log: socket client !!!\n");
        return OAM_INTERNAL_ERROR;
    }

    /*
     * extend the timeout, so the client will not close the xnet and then the eoam
     * is not able to send the response.
     */
    xipc_set_timeout(xipc, 2000);
    
    // header
    memset(&hdr, 0, sizeof(xipc_hdr_s));
    hdr.op = EOAM_OP_EXEC;
    hdr.mtype = EOAM_EVENT_DEBUG;
    hdr.value = priority; /* just for test, no meaning */

    retval = xipc_client_exec(xipc, &hdr, &ret_status);
    if (retval == FALSE)
    {
        xdbg_log(XDBG_ERR, "eoam_clear_log: xipc_client_event error !!!\n");
    }
    
    status = (oam_err_e) ret_status;
    
    xipc_close(xipc);

    return status;    
}