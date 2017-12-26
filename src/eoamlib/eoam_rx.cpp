#include <stdio.h>
#include <stdint.h>

#include "xutl_dbg.h"
#include "xutl_ipc.h"

#include "eoam_xipc.h"
#include "eoam_rx.h"
//#include "eoam_params.h"

static xipc_s *g_rx_xipc = NULL;

BOOLEAN eoam_rx_init(char *xipc_path)
{
    if (xipc_path == NULL)
        return FALSE;

    if (g_rx_xipc != NULL)
    {
         xdbg_log(XDBG_ERR, "eoam_rx_init: already init !!!");
        return FALSE;       
    }

    g_rx_xipc = xipc_unix_client(XIPC_DGRAM, (char *)xipc_path);
    if (g_rx_xipc == NULL)
    {
        xdbg_log(XDBG_ERR, "eoam_rx_init: cannot open client xipc !!!");
        return FALSE;
    }

    return TRUE;
}

BOOLEAN eoam_rx_terminate(void)
{
    if (g_rx_xipc == NULL)
        return FALSE;
    
    xipc_close(g_rx_xipc);

    g_rx_xipc = NULL;


    return TRUE;
}

BOOLEAN eoam_rx_indication(ifindex_s ifindex, const uint8_t *packet, size_t length)
{
    xipc_hdr_s hdr;
    BOOLEAN retval = TRUE ;
    xipc_status_s status = 0;
    
    if (status) {}
    if (packet) {}
    if (length) {}
    
    if (g_rx_xipc == NULL)
    {
        xdbg_log(XDBG_INFO, "eoam_rx_indication: xipc not yet open  ... ");
        return TRUE;
    }

#if OAM_PARAM_DEBUG_PKT
        xdbg_log(XDBG_INFO, "<-- [%2d:%d]- %02x:%02x:%02x:%02x:%02x:%02x-%02x:%02x:%02x:%02x:%02x:%02x",
                 port, length,
                 packet[0], packet[1], packet[2], packet[3], packet[4], packet[5],
                 packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
#endif
    
    memset((char *)&hdr, 0, sizeof(hdr));
    hdr.op = EOAM_OP_EVENT;
    hdr.mtype = EOAM_PACKET;
    hdr.value = ifindex;

    retval = xipc_client_event(g_rx_xipc, &hdr, (void *)packet, length, &status);
    if (retval == FALSE)
    {
        xdbg_log(XDBG_ERR, "eoam_rx_indication: xipc_client_event error !!!\n");
    }
    
    return retval;
}


