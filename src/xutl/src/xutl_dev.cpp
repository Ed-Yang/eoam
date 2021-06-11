#include <string.h>
#include <unistd.h>

#include "xutl_dev.h"
#include "xutl_mem.h"
#include "xutl_os.h"
#include <pthread.h>
#include "pcap.h"

#define XDEV_CAP_SIZE       1600
#define XDEV_LIVE_TIMEOUT   100 // for macOS, it cannot be 0

struct struct_xdev 
{
    pthread_mutex_t xdev_lock;
    pthread_cond_t start_cond;
    pthread_cond_t stop_cond;
    char dev_name[XDEV_MAX_NAME+1];
    BOOLEAN mac_flt_flag;
    xdev_mac_s src_mac_flt;
    BOOLEAN fill_smac;
    uint8_t dev_mac[XDEV_MAC_SIZE]; // xdev base mac
    BOOLEAN xdev_started;
    BOOLEAN xdev_running;
    BOOLEAN xdev_aborted;
    BOOLEAN xdev_wait;
    pthread_t xdev_tid;
    BOOLEAN (*rx_cb)(xdev_s *, uint32_t, uint8_t *, size_t);
    // pcap
    pcap_t *pcap_handle ;
    BOOLEAN pcap_fp_flag;
    struct bpf_program pcap_fp;
    char errbuf[PCAP_ERRBUF_SIZE];
}  ;

#ifdef __APPLE__
static uint8_t g_osx_mac[XDEV_MAC_SIZE];
#endif

static pthread_mutex_t g_pcap_mutex  = PTHREAD_MUTEX_INITIALIZER;

/*------------------------------------------------------------------------------
 * Local Function
 *------------------------------------------------------------------------------
 */
static BOOLEAN _xdev_valid_packet(xdev_s *xdev, uint8_t *packet)
{
    if (xdev == NULL || packet == NULL) return FALSE;

#ifdef __APPLE__
    /*
     * drop loopback.  For OSX, the Linux VM injecting packet will loopback to en0
     * with OSX en0's mac.
     */
    do 
    {
        if (memcmp((char *)&packet[6], (char *)g_osx_mac, 6) == 0)
        {
            xdbg_log(XDBG_DEBUG, "xdev: drop vm loopback %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
                     packet[0], packet[1], packet[2], packet[3], packet[4], packet[5],
                     packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
            return FALSE;
        }
    } while (0);
#endif

    if (xdev->mac_flt_flag)
    {
        if (memcmp(&packet[6], xdev->src_mac_flt.mac, xdev->src_mac_flt.mask_bytes) == 0)
        {
            /* in OSX, it will receive the loopback page, but not in Linux */
            xdbg_log(XDBG_DEBUG, "xdev: drop if loopback %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
                     packet[0], packet[1], packet[2], packet[3], packet[4], packet[5],
                     packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
            
            return FALSE;
        }
    }

    return TRUE;
}

#ifdef XDEV_PCAP_LOOP // for pcap_loop
static void _xdev_callback(u_char *user_data, const struct pcap_pkthdr *pkt_hdr,
    const u_char *packet) 
{   
    xdev_s *xdev = (xdev_s *) user_data;
    uint32_t ifindex;

    if (_xdev_valid_packet(xdev, (uint8_t *)packet))
    {
        ifindex = (uint32_t) packet[11] & 0x0f ;
        (xdev->rx_cb)(ifindex, (uint8_t *)packet, pkt_hdr->caplen);
    }

    return ;
}
#endif

static void _xdev_rx_loop(xdev_s *xdev)
{
    struct pcap_pkthdr *pkt_hdr;
    const u_char *packet;
    int rv ;
    BOOLEAN retval ;
    uint32_t ifindex ;
    struct timeval tv;
    fd_set readfds;
    int pcap_fd ;
    pcap_t *p_pcap;

    if (xdev == NULL) 
    {
        xdbg_log(XDBG_ERR, "_xdev_rx_loop: invalid device pointer, abort !!");
        return ;
    }

    pthread_mutex_lock(&xdev->xdev_lock);

    xdev->xdev_running = TRUE;
    
    if ((p_pcap = xdev->pcap_handle) == NULL)
    {
        xdbg_log(XDBG_ERR, "_xdev_rx_loop: pcap is NULL error, abort !!");
        xdev->xdev_aborted = TRUE;
        pthread_mutex_unlock(&xdev->xdev_lock);
        return ;
    }

    if ((pcap_fd = pcap_get_selectable_fd(p_pcap)) <= 0)
    {
        xdbg_log(XDBG_ERR, "_xdev_rx_loop: pcap_get_selectable_fd error, abort !!");
        xdev->xdev_aborted = TRUE;
        pthread_mutex_unlock(&xdev->xdev_lock);
        return ;
    }

    pthread_cond_signal(&xdev->start_cond);

    pthread_mutex_unlock(&xdev->xdev_lock);

    xdbg_log(XDBG_DEBUG, "_xdev_rx_loop: enter loop....");

    while (xdev->xdev_started == TRUE)
    {
        xdbg_log(XDBG_DEBUG, "_xdev_rx_loop: wait packet ....");

        FD_ZERO(&readfds);
        FD_SET(pcap_fd, &readfds);
        tv.tv_sec = 1; tv.tv_usec = 0;

        if (select(FD_SETSIZE, &readfds, NULL, NULL, &tv) == 0)
            continue;
        
        rv = pcap_next_ex(p_pcap, &pkt_hdr, &packet);
        if (rv > 0)
        {
            xdbg_log(XDBG_DEBUG, "<--- %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
                     packet[0], packet[1], packet[2], packet[3], packet[4], packet[5],
                     packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);

            if (_xdev_valid_packet(xdev, (uint8_t *)packet))
            {
                /* FIXME:pcap always map the rx packet to ifindex:2 */
                ifindex = DEBUG_IFINDEX; // FIXME:ifindex
                retval = (xdev->rx_cb)(xdev, ifindex, (uint8_t *)packet, 
                    pkt_hdr->caplen);
                if (retval != TRUE)
                {
                    xdbg_log(XDBG_ERR, "_xdev_rx_loop: callback return error, abort rx !!!\n");
                    xdev->xdev_aborted = TRUE;
                    break;
                }
            }
        }
        else 
        {
            if (rv < 0)
            {
                xdbg_log(XDBG_ERR, "_xdev_rx_loop: pcap_next_ex error (%s), STOP !!!\n", 
                    pcap_geterr(xdev->pcap_handle));
                xdev->xdev_aborted = TRUE;
                break;
            }
        }
    }
    
    pthread_mutex_lock(&xdev->xdev_lock);
    
    xdev->xdev_running = FALSE;
    pthread_cond_signal(&xdev->stop_cond);
    
    pthread_mutex_unlock(&xdev->xdev_lock);

    xdbg_log(XDBG_INFO, "_xdev_rx_loop: exit loop");
    
    return ;
}

void _xdev_close_pcap(xdev_s *xdev)
{
    xdbg_log(XDBG_DEBUG, "_xdev_close_pcap: close xdev 0x%08x", xdev);

    if (xdev == NULL)
    {
        xdbg_log(XDBG_ERR, "_xdev_close_pcap: null xdev pointer !!!");
        return ;
    }

    if (xdev->pcap_fp_flag)
    {
        pcap_freecode(&xdev->pcap_fp);
        xdev->pcap_fp_flag = FALSE;
    }

    pcap_close(xdev->pcap_handle);
    xdev->pcap_handle = NULL;
}

pcap_t *_xdev_setup_pcap(xdev_s *xdev, char *filter_exp)
{
    pcap_t *p_pcap ;
    char *dev;
    int timeout = XDEV_LIVE_TIMEOUT; // for macOS, it cannot be 0
    int rv;
 
    if (xdev == NULL)
    {
        xdbg_log(XDBG_ERR, "_xdev_setup_pcap: invalid xdev pointer !!");
        
        return NULL;
    }

    dev = xdev->dev_name;
    p_pcap = pcap_open_live(xdev->dev_name, BUFSIZ , TRUE /* promisc */,
                                       timeout, xdev->errbuf);
    if (p_pcap == NULL)
    {
        xdbg_log(XDBG_ERR, "_xdev_setup_pcap: open adaptor (dev %s) failed !!",
                 xdev->dev_name);
        
        return NULL;
    }
    
    /* 
     * pcap_compile is not thread-safe (google), if multiple thread call 
     * pcap_compile, it might crash 
     */
    pthread_mutex_lock(&g_pcap_mutex);
    xdev->pcap_fp_flag = FALSE;
    rv = pcap_compile(p_pcap, &xdev->pcap_fp, filter_exp, 0, 0);
    pthread_mutex_unlock(&g_pcap_mutex);

    if ( rv != 0)
    {
        xdbg_log(XDBG_ERR, "_xdev_setup_pcap: pcap_compile (dev %s) !!", dev);
        pcap_perror(p_pcap, (char *)"pcap_compile") ;
        _xdev_close_pcap(xdev);        
        return NULL;
    }
    
    if (pcap_setfilter(p_pcap, &xdev->pcap_fp) != 0)
    {
        xdbg_log(XDBG_ERR, "_xdev_setup_pcap: pcap_setfilter (dev %s) !!", dev);
        pcap_perror(p_pcap, (char *)"pcap_setfilter") ;

        _xdev_close_pcap(xdev);         

        return NULL;
    }

    xdev->pcap_fp_flag = TRUE;
    
    return p_pcap;
}

static void *_xdev_rx_thread(void *param)
{
    xdev_s *xdev = (xdev_s *)param;
    ifindex_s ifindex = 0;
    size_t len = 0;
    uint8_t *p_pkt = NULL;
    int s = 0;

    if (param) {}
    if (len) {}
    if (s) {}
    if (ifindex) {}
    if (p_pkt) {}
    
    xdbg_log(XDBG_TRACE, "[0x%08x, 0x%08x] >>> xdev rx thread started.",
        pthread_self(), xdev);
    
    _xdev_rx_loop(xdev);

    xdbg_log(XDBG_TRACE, "[0x%08x, 0x%08x] <<< xdev rx thread exit ",
        pthread_self(), xdev);

    return NULL;
}

void _xdev_free(xdev_s *xdev)
{
    if (xdev)
    {
        pthread_mutex_destroy(&xdev->xdev_lock);
        xmem_free(xdev, sizeof(xdev_s));
    }
}

/*------------------------------------------------------------------------------
 * Public Function
 *------------------------------------------------------------------------------
 */


/**
 * @brief 
 * 
 * @param dev_name 
 * @param src_mac_flt if set, drop traffic with matched source mac
 * @param param 
 * @return xdev_s* 
 */
xdev_s *xdev_open(char *dev_name, xdev_mac_s *src_mac_flt, BOOLEAN fill_smac,
    void *param)
{
    xdev_s *xdev;
    char *dev = NULL, namebuf[XDEV_MAX_NAME+1] = {0};
    int len;
    char *filter_exp = (char *)param;
    pcap_if_t *all_devs = NULL;

    if (filter_exp) {}

    if ( (xdev=(xdev_s *)xmem_malloc(sizeof(xdev_s))) == NULL)
    {
        xdbg_log(XDBG_ERR, "xdev_open: cannot allocate memory (size %d) !!",
            sizeof(xdev_s));
        return NULL;
    }

    memset(xdev, 0, sizeof(xdev_s));

    /* NOTE, in OSX, it must init the mutex and conditional variable */
    if (pthread_mutex_init(&xdev->xdev_lock, NULL) != 0)
    {
        perror("pthread_mutex_init");
        xmem_free(xdev, sizeof(xdev_s));
        return NULL;
    }

    if (pthread_cond_init(&xdev->start_cond, NULL) != 0)
    {
        perror("pthread_cond_init");
        xmem_free(xdev, sizeof(xdev_s));
        return NULL;
    }

    if (pthread_cond_init(&xdev->stop_cond, NULL) != 0)
    {
        perror("pthread_cond_init");
        xmem_free(xdev, sizeof(xdev_s));
        return NULL;
    }

    if (dev_name == NULL)
    {
        if (pcap_findalldevs(&all_devs, xdev->errbuf) == 0)
        {
            strncpy(namebuf, all_devs->name, XDEV_MAX_NAME);
            dev = namebuf;
            pcap_freealldevs(all_devs);
        }
    }
    else
    {
        dev = dev_name;
    }

    if (dev == NULL)
    {
        xdbg_log(XDBG_ERR, "xdev_open: open find capture adaptor !!");
        _xdev_free(xdev);
        return NULL;        
    }

    len = (strlen(dev) > XDEV_MAX_NAME) ? XDEV_MAX_NAME: (int)strlen(dev);
    memcpy(xdev->dev_name, dev, len);
    xdev->fill_smac = fill_smac;

#ifdef __APPLE__
    xos_get_mac((char *)"en0", (char *)g_osx_mac);
#endif

    // get base mac
    if (fill_smac)
    {
        xos_get_mac(xdev->dev_name, (char *)xdev->dev_mac);

        xdbg_log(XDBG_INFO, "[0x%08x, 0x%08x] xdev_open: dev %s  mac %02x:%02x:%02x:%02x:%02x:%02x",
            pthread_self(), xdev, xdev->dev_name,
            xdev->dev_mac[0], xdev->dev_mac[1], xdev->dev_mac[2],
            xdev->dev_mac[3], xdev->dev_mac[4], xdev->dev_mac[5]
            );
    }
    else 
    {
        xdbg_log(XDBG_INFO, "[0x%08x, 0x%08x] xdev_open:  src mac filled by upper layer", 
            pthread_self(), xdev);
    }

    if (src_mac_flt) // FIXME:mac-filter
    {
        xdbg_log(XDBG_INFO, "xdev_open: mac filter %02x:%02x:%02x:%02x:%02x:%02x (mask %d bytes)",
                 src_mac_flt->mac[0], src_mac_flt->mac[1], src_mac_flt->mac[2],
                 src_mac_flt->mac[3], src_mac_flt->mac[4], src_mac_flt->mac[5],
                 src_mac_flt->mask_bytes);

        xdev->mac_flt_flag = TRUE;
        memcpy(&xdev->src_mac_flt, src_mac_flt, sizeof(xdev_mac_s));
    }
    else 
    {
        xdev->mac_flt_flag = FALSE;
    }

    if ((xdev->pcap_handle = _xdev_setup_pcap(xdev, filter_exp)) == NULL)
    {
        xdbg_log(XDBG_ERR, "xdev_open: _xdev_setup_pcap fail !!!"); 
        _xdev_free(xdev);
        xdev = NULL;
    }
    
    return xdev;
}

BOOLEAN xdev_close(xdev_s *xdev)
{
    if (xdev == NULL) 
    {
        xdbg_log(XDBG_ERR, "xdev_close: invalid device pointer !!");
        return FALSE;
    }
    
    pthread_mutex_lock(&xdev->xdev_lock);

    if (xdev->xdev_started != FALSE)
    {
        xdbg_log(XDBG_ERR, "xdev_close: not stop yet !!");
        pthread_mutex_unlock(&xdev->xdev_lock);
        return FALSE;
    }

    xdbg_log(XDBG_INFO, "[0x%08x, 0x%08x]  xdev_close: close device %s starting ...",
             pthread_self(), xdev, xdev->dev_name);
    
    if (xdev->pcap_handle)
    {
        _xdev_close_pcap(xdev); 
    }

    xdbg_log(XDBG_INFO, "[0x%08x, 0x%08x]  xdev_close: close device %s done.",
             pthread_self(), xdev, xdev->dev_name);
    
    pthread_mutex_unlock(&xdev->xdev_lock);
    
    _xdev_free(xdev);

    return TRUE ;
}

BOOLEAN xdev_send(xdev_s *xdev, uint32_t ifindex, uint8_t *packet, size_t len)
{
    BOOLEAN retval = TRUE;

    if (xdev == NULL) 
    {
        xdbg_log(XDBG_ERR, "xdev_send: invalid device pointer !!");
        return FALSE;
    }
    
    pthread_mutex_lock(&xdev->xdev_lock);

    if (xdev->pcap_handle == NULL) 
    {
        xdbg_log(XDBG_ERR, "xdev_send: invalid pcap pointer !!");
        pthread_mutex_unlock(&xdev->xdev_lock);
        return FALSE;
    }

    // fill src mac
    if (xdev->fill_smac)
    {
        memcpy(&packet[XDEV_MAC_SIZE], xdev->dev_mac, XDEV_MAC_SIZE);
        packet[11] = ifindex & 0xff;
    }
    
    if ( pcap_sendpacket(xdev->pcap_handle, packet, (int)len) != 0)
    {
        xdbg_log(XDBG_ERR, "xdev_send: adaptor is closed or not open yet.");
        pcap_perror(xdev->pcap_handle, (char *)"pcap_sendpacket") ;
        retval = FALSE;
    }

    pthread_mutex_unlock(&xdev->xdev_lock);
    
    return retval;
}

BOOLEAN xdev_start(xdev_s *xdev, BOOLEAN (*rx_cb)(xdev_s *, uint32_t, uint8_t *, size_t))
{
    BOOLEAN retval = TRUE;    

    xdbg_log(XDBG_TRACE, "<<< xdev_start: enter function");

    if (xdev == NULL || rx_cb == NULL) 
    {
        xdbg_log(XDBG_ERR, "xdev_start: invalid device pointer !!");
        return FALSE;
    }

    pthread_mutex_lock(&xdev->xdev_lock);

    if (xdev->pcap_handle == NULL) 
    {
        xdbg_log(XDBG_ERR, "xdev_start: invalid pcap pointer !!");
        pthread_mutex_unlock(&xdev->xdev_lock);
        return FALSE;
    }

    xdbg_log(XDBG_TRACE, "[0x%08x, 0x%08x] <<< xdev_start: creating thread ...",
             pthread_self(), xdev);
    
    xdev->rx_cb = rx_cb;
    xdev->xdev_started = TRUE;

    pthread_create(&xdev->xdev_tid, NULL, _xdev_rx_thread, xdev);

    while (xdev->xdev_running != TRUE)
        pthread_cond_wait(&xdev->start_cond, &xdev->xdev_lock);

    xdbg_log(XDBG_TRACE, "[0x%08x, 0x%08x] <<< xdev_start: exit function.)",
        pthread_self(), xdev);
    
    pthread_mutex_unlock(&xdev->xdev_lock);
    
    return retval;
}

BOOLEAN xdev_stop(xdev_s *xdev)
{
    BOOLEAN retval = TRUE;

    xdbg_log(XDBG_TRACE, "[0x%08x, 0x%08x] ### xdev_stop: called",
             pthread_self(), xdev);

    if (xdev == NULL) 
    {
        xdbg_log(XDBG_ERR, "xdev_stop: invalid device pointer !!");
        return FALSE;
    }

    if (xdev->pcap_handle == NULL) 
    {
        xdbg_log(XDBG_ERR, "xdev_stop: invalid pcap pointer !!");
        return FALSE;
    }

    pthread_mutex_lock(&xdev->xdev_lock);
    
    if (xdev->xdev_started != TRUE)
    {
        xdbg_log(XDBG_ERR, "xdev_stop: thread is not running or stable !!");
        pthread_mutex_unlock(&xdev->xdev_lock);
        return FALSE;
    }
    
    xdev->xdev_started = FALSE; // requeest to stop
    while (xdev->xdev_running)
    {
        pthread_cond_wait(&xdev->stop_cond, &xdev->xdev_lock);
    }
    
    pthread_mutex_unlock(&xdev->xdev_lock);

    xdbg_log(XDBG_TRACE, "xdev_stop: wait xdev thread terminated ...");
    if (xdev->xdev_wait != TRUE &&
        pthread_join(xdev->xdev_tid, NULL) != 0)
    {
        xdbg_log(XDBG_ERR, "xdev_stop: pthread_join failed !!");
        retval = FALSE;
    }

    xdbg_log(XDBG_TRACE, "[0x%08x, 0x%08x] ### xdev_stop:  exit function",
             pthread_self(), xdev);

    return retval;

}

BOOLEAN xdev_wait(xdev_s *xdev)
{
    if (xdev == NULL)
        return FALSE;
    
    if (xdev->xdev_started != TRUE || xdev->xdev_running != TRUE)
        return FALSE;
    
    xdbg_log(XDBG_INFO, "xdev_wait: wait xdev thread terminated ...");
    
    xdev->xdev_wait = TRUE;
    
    if (pthread_join(xdev->xdev_tid, NULL) != 0)
        return FALSE;
    
    xdbg_log(XDBG_INFO, "xdev_wait: wait xdev thread - done.");
    
    return TRUE;
}

