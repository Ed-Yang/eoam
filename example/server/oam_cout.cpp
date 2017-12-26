#include <pthread.h>
#include <pcap.h>
#include <sys/socket.h>

#include "eoam_cout.h"
#include "eoam_str.h"
#include "eoam_rx.h"
#include <pcap.h>

#include "xutl_os.h"
#include "xutl_net.h"
#include "xutl_dev.h"
#include "xutl_mem.h"

#include "eoam_params.h"


static xdev_s *g_eoam_xdev = NULL;
static BOOLEAN g_fill_smac = FALSE;

static uint8_t g_dev_mac[XDEV_MAC_SIZE];

static BOOLEAN eoam_cout_rx_cb(xdev_s *xdev, uint32_t ifindex, uint8_t *packet, size_t len)
{
    BOOLEAN retval = TRUE;

    if (xdev == NULL)
    {
        xdbg_log(XDBG_ERR, "eoam_cout_rx_cb: null device pointer!!!");
        return FALSE;
    }

    if (g_fill_smac == FALSE && memcmp(&packet[6], g_dev_mac, 5) == 0)
    {
#if OAM_PARAM_DEBUG_PKT
        /* lower layer have not device's mac, so drop the OSX loopback traffic
         * in OSX, it will receive the loopback page, but not in Linux */
        xdbg_log(XDBG_INFO, "xxxx: drop loopback %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
                 packet[0], packet[1], packet[2], packet[3], packet[4], packet[5],
                 packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
#endif

        return TRUE;
    }

    retval = eoam_rx_indication(ifindex, packet, len);

    /* return FALSE will break the upper layer loop */
    if (retval != TRUE)
    {
        xdbg_log(XDBG_ERR, "eoam_rx_indication failure, cannot send to fsm !!!");
    }

    return TRUE;
}

/*
 * pcap
 *
 */
BOOLEAN eoam_cout_init(char *dev_name, uint8_t *dev_mac, void *dev_filter)
{
    xdev_mac_s mac_flt, *p_mac_flt = NULL;

    /* dev_name is NULL, it will auto select interface */

    /*
     * in this porting, this layer will fill in source mac, so if not provided,
     * just return failure
     */
    if (dev_mac == NULL)
    {
        xdbg_log(XDBG_ERR, "eoam_cout_init: no interface mac provided !!!");
        return FALSE;
    }

    p_mac_flt = &mac_flt;
    memcpy(mac_flt.mac, dev_mac, 6);
    mac_flt.mask_bytes = 5; /* the last byte will be filled with ifindex */
    memcpy(g_dev_mac, dev_mac, XDEV_MAC_SIZE);

    /* upper layer fill in source mac */
    g_eoam_xdev = xdev_open(dev_name, p_mac_flt, g_fill_smac, dev_filter);
    if (g_eoam_xdev == NULL)
    {
        if (dev_name)
            xdbg_log(XDBG_ERR, "eoam_cout_init: cannot open devie (%s) !!!", dev_name);
        else
            xdbg_log(XDBG_ERR, "eoam_cout_init: cannot open devie !!!");

        return FALSE;
    }

    return TRUE;
}

void eoam_cout_terminate(void)
{
    if (g_eoam_xdev == NULL)
    {
        xdbg_log(XDBG_ERR, "eoam_cout_teriminate: null device pointer!!!");
        return;
    }

    xdbg_log(XDBG_INFO, "eoam_cout_teriminate: close device.");

    xdev_close(g_eoam_xdev);

    return;
}

/*
 * callout
 *
 */
void eoam_cout_get_pmac(ifindex_s ifindex, uint8_t *pmac)
{
    memcpy(pmac, g_dev_mac, XDEV_MAC_SIZE);
    pmac[5] = ifindex; 

    return;
}

BOOLEAN eoam_cout_link_status(ifindex_s ifindex)
{
    if (g_eoam_xdev == NULL)
    {
        xdbg_log(XDBG_ERR, "eoam_cout_link_status: null device pointer!!!");
        return FALSE;
    }

    if (ifindex == DEBUG_IFINDEX) 
        return TRUE;

    return FALSE;
}

BOOLEAN eoam_cout_send(ifindex_s ifindex,
                       uint8_t *packet, size_t len)
{
    if (g_eoam_xdev == NULL)
    {
        xdbg_log(XDBG_ERR, "eoam_cout_send: null device pointer!!!");
        return FALSE;
    }

    xdev_send(g_eoam_xdev, ifindex, packet, len);

    return TRUE;
}

BOOLEAN eoam_cout_start_rx()
{
    if (g_eoam_xdev == NULL)
    {
        xdbg_log(XDBG_ERR, "eoam_cout_start_rx: null device pointer!!!");
        return FALSE;
    }

    xdev_start(g_eoam_xdev, eoam_cout_rx_cb);
    xdev_wait(g_eoam_xdev);

    return TRUE;
}

BOOLEAN eoam_cout_stop_rx()
{
    if (g_eoam_xdev == NULL)
    {
        xdbg_log(XDBG_ERR, "eoam_cout_stop_rx: null device pointer!!!");
        return FALSE;
    }

    xdev_stop(g_eoam_xdev);

    return TRUE;
}

BOOLEAN eoam_cout_state_change(ifindex_s ifindex,
                               oam_state_e prev, oam_state_e now)
{
    if (g_eoam_xdev == NULL)
    {
        xdbg_log(XDBG_ERR, "eoam_cout_state_change: null device pointer!!!");
        return FALSE;
    }

    xdbg_log(XDBG_INFO, "[%2d] CO: state changed old %s --> new %s",
             ifindex, eoam_str_fsm_state(prev), eoam_str_fsm_state(now));

    return TRUE;
}

BOOLEAN eoam_cout_peer_capability(ifindex_s ifindex,
                                  uint8_t config, uint8_t state)
{
    if (g_eoam_xdev == NULL)
    {
        xdbg_log(XDBG_ERR, "eoam_cout_state_change: null device pointer!!!");
        return FALSE;
    }

    xdbg_log(XDBG_INFO, "[%2d] peer config: %s state: %s", ifindex,
             eoam_str_oam_config(config), eoam_str_info_state(state));

    return TRUE;
}

/**
 * eoam_cout_loopbcak_req
 *
 * instruct hardware loopback for this port
 */

BOOLEAN eoam_cout_lpbk_req(ifindex_s ifindex,
                           oam_lpbk_e lpbk_status)
{
    if (g_eoam_xdev == NULL)
    {
        xdbg_log(XDBG_ERR, "eoam_cout_state_change: null device pointer!!!");
        return FALSE;
    }

    xdbg_log(XDBG_INFO, "[%2d] CO: loopback status - %s (%d)",
             ifindex, eoam_str_lpbk_status(lpbk_status), (int)lpbk_status);

    return TRUE;
}

BOOLEAN eoam_cout_report_evt(dot3_evt_log_s *p_evt)
{
    const char *ptr;

    if (p_evt->clear_flag)
        ptr = "clear";
    else
        ptr = "raise";

    if (g_eoam_xdev == NULL)
    {
        xdbg_log(XDBG_ERR, "eoam_cout_report_evt: null device pointer!!!");
        return FALSE;
    }

    if (p_evt == NULL)
    {
        xdbg_log(XDBG_ERR, "eoam_cout_report_evt: null p_evt pointer!!!");
        return FALSE;
    }

    if (p_evt->dot3OamEventLogType > 4)
    {
        xdbg_log(XDBG_INFO, "[%2d] CO: %s c-events: type %d ts %d loc %d r-total %llu, e-total %u",
             p_evt->ifindex, ptr,
             p_evt->dot3OamEventLogType, p_evt->dot3OamEventLogTimestamp,
             p_evt->dot3OamEventLogLocation,
             (long long unsigned int)p_evt->dot3OamEventLogRunningTotal,
             p_evt->dot3OamEventLogEventTotal);
    }
    else
    {
        xdbg_log(XDBG_INFO, "[%2d] CO: %s l-events: type %d ts %d loc %d value %llu r-total %llu, e-total %u",
             p_evt->ifindex, ptr,
             p_evt->dot3OamEventLogType, p_evt->dot3OamEventLogTimestamp,
             p_evt->dot3OamEventLogLocation, p_evt->dot3OamEventLogValue,
             (long long unsigned int)p_evt->dot3OamEventLogRunningTotal,
             p_evt->dot3OamEventLogEventTotal);
    }

    return TRUE;
}


