/**
 * use xipc_set_group_handler api to simulate kinds of operation.
 * 
 * NOTE. The op or msg is just a name, it can freely to use any other name.  The
 * real operation is determined by supplied parameter to client API.
 * 
 */

#include <stdio.h>
#include <assert.h>
#include <stdlib.h> // exit
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h> // fork
#include <signal.h>

#include "xutl_net.h"
#include "xutl_dev.h"
#include "xutl_ipc.h"
#include "xutl_str.h"

#define SIMPLE_TEST

#define STREAM_SOCK_FILE    "/tmp/test_ipc.stream.sock"
#define DGRAM_SOCK_FILE     "/tmp/test_ipc.dgram.sock"

// op
typedef enum
{
    OP_EVENT  = 1,
    OP_PUT,
    OP_SET_GET,
    OP_GET,
    OP_GET_DATA,
    OP_MAX
} op_e;

typedef enum
{
    MSG_PKT = 1,
    MSG_CFG,
    MSG_HELLO,
    MSG_MAX
} msg_e;

#pragma pack(1)

typedef struct
{
    uint8_t pad[4];
    int seq;
} set_cfg_s;

typedef struct
{
    int seq;
    uint8_t pad[12];
} get_cfg_s;

#pragma pack()


//
// globals
//

// client
pthread_t g_client_tid;
xipc_s *g_cfg_ipc;

// server
static xtimer_s *recurr_timer, *once_timer;
static xnet_s *g_xnet;
xipc_s *g_rcfg_ipc;
xipc_s *g_rpkt_ipc;

// packet loop
static xdev_s *g_xdev;
static BOOLEAN g_rx_abort = FALSE;
xipc_s *g_pkt_ipc;

//
// local functions
//
void cleanup(void)
{
    xdev_stop(g_xdev);
    xdev_close(g_xdev);

    // client ipc    
    xipc_close(g_cfg_ipc);
    xipc_close(g_pkt_ipc);

    // server ipc
    xipc_close(g_rcfg_ipc);
    xipc_close(g_rpkt_ipc);

    xnet_stop(g_xnet);
    xnet_close(g_xnet);
    
    fclose( stdin );
    fclose( stdout );
    fclose( stderr );
}

static void signal_handler(int type)
{
    if (type) {}
    
    xdbg_log(XDBG_INFO, "CTRL-C received. terminating the xnet.");
    fflush(stderr);

    cleanup();

    /* reset and raise original signal again */
#if 1
    signal(SIGINT, SIG_DFL);
    raise(SIGINT);
#endif

    return ;
}

void register_signal_handler()
{
    struct sigaction handler; // signal handler specification structure 				

    // set InterruptSignalHandler as handler function 
    handler.sa_handler = signal_handler;

    sigfillset(&handler.sa_mask); // sigfillset is a macro, no return value
					
    handler.sa_flags = 0; // for pcap, it should not restart the system call
					
    // set signal handling for interrupt signals  
    if (sigaction(SIGINT, &handler, 0) < 0)
    {
	    perror("sigaction"); 
        exit(0);
    }

    // set signal handling for interrupt signals  
    if (sigaction(SIGHUP, &handler, 0) < 0)
    {
	    perror("sigaction"); 
        exit(0);
    }

    signal(SIGPIPE, SIG_IGN); // prevent got signal on send to a closing socket

    return ;
}

BOOLEAN run_once_function(xtimer_s *xtimer, void *param)
{
    xtimer_s *t = (xtimer_s *) param;
    
    if (xtimer) {}
    
    xdbg_log(XDBG_DEBUG, "+++++ recurrsing timer is called");

    xnet_start_timer(t);

    return FALSE;
}

BOOLEAN recurr_function(xtimer_s *xtimer, void *param)
{
    static int cnt = 5;

    if (xtimer) {}
    if (param) {}
    
    xdbg_log(XDBG_DEBUG, "---- recurr_function is called (%d)", cnt);

    if (cnt-- <= 0)
        g_rx_abort = TRUE;

    return TRUE;
}

void usr_init(void *xnet, void *param)
{
    if (xnet) {}
    if (param) {}
    
    xdbg_log(XDBG_DEBUG, "init timer, start recurrsing timer");
    
    xnet_start_timer(once_timer);
}

static BOOLEAN pkt_rx_cb(xdev_s *xdev, uint32_t ifindex, uint8_t *packet, size_t len)
{
    BOOLEAN retval = TRUE;
    static int cnt = 0;
    xipc_hdr_s hdr;
    
    xipc_status_s status = 0;

    if (xdev) {}
    if (ifindex) {}
    
    xdbg_log(XDBG_DEBUG, "<-- [%2d:%2d]- %02x:%02x:%02x:%02x:%02x:%02x-%02x:%02x:%02x:%02x:%02x:%02x",
        cnt++, len,
        packet[0], packet[1], packet[2], packet[3], packet[4], packet[5],
        packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]); 

    memset((char *)&hdr, 0, sizeof(hdr));
    hdr.op = OP_EVENT;
    hdr.mtype = MSG_PKT;
    //hdr.dsize = len;
    hdr.value = 0;
    
#ifdef SIMPLE_TEST
    {
        char *tdata = (char *)"012345678900123456789";
        
        if (cnt == 1)
            xipc_client_event(g_pkt_ipc, &hdr, tdata, strlen(tdata), &status);
    }
#else
    xipc_client_event(g_pkt_ipc, &hdr, packet, len, &status);
#endif
    
    if (g_rx_abort)
        retval = FALSE;

    return retval;
}

/**
 * event test
 * 
 * will only return failure on failure of sending
 */
void event_test()
{
    xipc_hdr_s hdr;
    xipc_status_s status = 999;
    char *hello = (char *)"hello";
    BOOLEAN retval;

    if (hello) {}

#if 1
    /**
     * invalid op + mtype
     */
    hdr.op = OP_MAX;
    hdr.mtype = MSG_MAX;
    hdr.value = 9999;
    
    xdbg_log(XDBG_NOTICE, "----> event test: (NULL, 0 [-1]) -- val = %d status = %d",
             hdr.value, status);
    retval = xipc_client_event(g_pkt_ipc, &hdr, NULL, 0, &status);
    xdbg_log(XDBG_NOTICE, "===== RESULT: %d  (NULL, 0 [-1]) -- val = %d status = %d",
             retval, hdr.value, status);
    assert(retval == TRUE);

#endif 

    hdr.op = OP_MAX;
    hdr.mtype = MSG_MAX;
    hdr.value = 9999;

    xdbg_log(XDBG_NOTICE, "----> event test: (NULL, 0 [-1]) -- val = %d status = %d",
             hdr.value, status);
    retval = xipc_client_event(g_cfg_ipc, &hdr, NULL, 0, &status);
    xdbg_log(XDBG_NOTICE, "===== RESULT: %d  (NULL, 0 [-1]) -- val = %d status = %d",
             retval, hdr.value, status);
    assert(retval == TRUE);


#if 1
    /**
     * event, no data
     */
    hdr.op = OP_EVENT;
    hdr.mtype = MSG_HELLO;
    hdr.value = 6666;

    xdbg_log(XDBG_NOTICE, "----> event test: (NULL, 0 [-1]) -- val = %d status = %d",
             hdr.value, status);
    retval = xipc_client_event(g_pkt_ipc, &hdr, NULL, 0, &status);
    xdbg_log(XDBG_NOTICE, "===== RESULT: %d  (NULL, 0 [-1]) -- val = %d status = %d",
             retval, hdr.value, status);
    assert(retval == TRUE);


    hdr.op = OP_EVENT;
    hdr.mtype = MSG_HELLO;
    hdr.value = 6666;

    xdbg_log(XDBG_NOTICE, "----> event test: (NULL, 0 [-1]) -- val = %d status = %d",
             hdr.value, status);
    retval = xipc_client_event(g_cfg_ipc, &hdr, NULL, 0, &status);
    xdbg_log(XDBG_NOTICE, "===== RESULT: %d  (NULL, 0 [-1]) -- val = %d status = %d",
             retval, hdr.value, status);
    assert(retval == TRUE);
   
    /**
     * event, with data
     */
    hdr.op = OP_EVENT;
    hdr.mtype = MSG_HELLO;
    hdr.value = 6666;
    
    xdbg_log(XDBG_NOTICE, "----> event test: (data, n [-1]) -- val = %d status = %d",
             hdr.value, status);
    retval = xipc_client_event(g_pkt_ipc, &hdr, hello, strlen(hello), &status);
    xdbg_log(XDBG_NOTICE, "===== RESULT: %d  (data, n [-1]) -- val = %d status = %d",
             retval, hdr.value, status);
    
    assert(retval == TRUE);



    hdr.op = OP_EVENT;
    hdr.mtype = MSG_HELLO;
    hdr.value = 9999;
    
    xdbg_log(XDBG_NOTICE, "----> event test: (data, n [-1]) -- val = %d status = %d",
             hdr.value, status);
    retval = xipc_client_event(g_cfg_ipc, &hdr, hello, strlen(hello), &status);
    xdbg_log(XDBG_NOTICE, "===== RESULT: %d  (data, n [-1]) -- val = %d status = %d",
             retval, hdr.value, status);
    
    assert(retval == TRUE);
#endif
}

/**
 * put test
 * 
 * 
 */
void put_test()
{
    xipc_hdr_s hdr;
    xipc_status_s status = 999;
    set_cfg_s cfg;
    BOOLEAN retval = TRUE;

#if 1
    /**
     * set data and ack header
     */
    hdr.op = OP_PUT;
    hdr.mtype = MSG_CFG;
    hdr.value = 9999;

    memset(&cfg, 0, sizeof(cfg));
    cfg.seq = 9999;

    xdbg_log(XDBG_NOTICE, "----> put test:   (data, n [-1]) -- val = %d status = %d",
             hdr.value, status);

    retval = xipc_client_put(g_pkt_ipc, &hdr, &cfg, sizeof(cfg), &status);
    xdbg_log(XDBG_NOTICE, "===== RESULT: %d  (data, n [-1]) -- val = %d status = %d",
             retval, hdr.value, status);
    assert(retval == TRUE && hdr.value == 9999 && cfg.seq == 9999);
#endif
    
    hdr.op = OP_PUT;
    hdr.mtype = MSG_CFG;
    hdr.value = 9999;

    memset(&cfg, 0, sizeof(cfg));
    cfg.seq = 9999;
    
    xdbg_log(XDBG_NOTICE, "----> put test:   (data, n [0]) -- val = %d status = %d",
             hdr.value, status);

    retval = xipc_client_put(g_cfg_ipc, &hdr, &cfg, sizeof(cfg), &status);
    xdbg_log(XDBG_NOTICE, "===== RESULT: %d  (data, n [0]) -- val = %d status = %d",
             retval, hdr.value, status);
    
    /* status is not zero, value is not copied */
    assert(retval == TRUE && hdr.value == 1111 && cfg.seq == 9999);
}

/**
 * set get test
 * 
 * 
 */
void set_get_test()
{
    xipc_hdr_s hdr;
    xipc_status_s status = 999;
    set_cfg_s cfg;
    BOOLEAN retval = TRUE;

#if 1
    /**
     * set data and get data
     */
    hdr.op = OP_SET_GET;
    hdr.mtype = MSG_CFG;
    hdr.value = 9999;

    memset(&cfg, 0, sizeof(cfg));
    cfg.seq = 9999;

    xdbg_log(XDBG_NOTICE, "----> data test:   (data, n [0]) -- val = %d status = %d",
             hdr.value, status);
    retval = xipc_client_data(g_pkt_ipc, &hdr, &cfg, sizeof(cfg), &status);
    xdbg_log(XDBG_NOTICE, "===== RESULT: %d  (data, n [0]) -- val = %d status = %d",
             retval, hdr.value, status);
    assert(retval == FALSE && hdr.value == 9999 && cfg.seq == 9999);

    hdr.op = OP_SET_GET;
    hdr.mtype = MSG_CFG;
    hdr.value = 9999;

    memset(&cfg, 0, sizeof(cfg));
    cfg.seq = 9999;
    
    xdbg_log(XDBG_NOTICE, "----> data test:   (data, n [0]) -- val = %d status = %d",
             hdr.value, status);
    retval = xipc_client_data(g_cfg_ipc, &hdr, &cfg, sizeof(cfg), &status);
    xdbg_log(XDBG_NOTICE, "===== RESULT: %d  (data, n [0]) -- val = %d status = %d",
             retval, hdr.value, status);
    assert(retval == TRUE && hdr.value == 1111 && cfg.seq == 1111);

#endif
}

void data_test()
{
    xipc_hdr_s hdr;
    xipc_status_s status = 999;
    get_cfg_s cfg;
    BOOLEAN retval = TRUE;
    
    /**
     * get pass only header (check server does not rx cfg)
     */
    hdr.op = OP_GET;
    hdr.mtype = MSG_CFG;
    hdr.value = 9999;
    cfg.seq = 9999;
    
#if 1
    xdbg_log(XDBG_NOTICE, "----> get test:   (data, 0 [n]) -- val = %d status = %d",
             hdr.value, status);
    retval = xipc_client_get(g_pkt_ipc, &hdr, &cfg, sizeof(cfg), &status);
    xdbg_log(XDBG_NOTICE, "===== RESULT: %d  (data, 0 [n]) -- val = %d status = %d",
             retval, hdr.value, status);
    assert(retval == FALSE && hdr.value == 9999 && cfg.seq == 9999);
#endif

    hdr.op = OP_GET;
    hdr.mtype = MSG_CFG;
    hdr.value = 9999;
    cfg.seq = 9999;
    
    xdbg_log(XDBG_NOTICE, "----> get test:   (data, 0 [n]) -- val = %d status = %d",
             hdr.value, status);
    retval = xipc_client_get(g_cfg_ipc, &hdr, &cfg, sizeof(cfg), &status);
    xdbg_log(XDBG_NOTICE, "===== RESULT: %d  (data, 0 [n]) -- val = %d status = %d",
             retval, hdr.value, status);
    assert(retval == TRUE && hdr.value == 2222 && cfg.seq == 2222);

    /**
     * get pass header + data
     */
#if 1
    hdr.op = OP_GET_DATA;
    hdr.mtype = MSG_CFG;
    hdr.value = 9999;
    cfg.seq = 9999;
    
    xdbg_log(XDBG_NOTICE, "----> data test:   (data, n [n]) -- val = %d status = %d",
             hdr.value, status);
    retval = xipc_client_data(g_pkt_ipc, &hdr, &cfg, sizeof(cfg), &status);
    xdbg_log(XDBG_NOTICE, "===== RESULT: %d  (data, n [n]) -- val = %d status = %d",
             retval, hdr.value, status);
    assert(retval == FALSE && hdr.value == 9999 && cfg.seq == 9999);
#endif

    hdr.op = OP_GET_DATA;
    hdr.mtype = MSG_CFG;
    hdr.value = 9999;
    cfg.seq = 9999;
    
    xdbg_log(XDBG_NOTICE, "----> data test:   (data, n [n]) -- val = %d status = %d",
             hdr.value, status);
    retval = xipc_client_data(g_cfg_ipc, &hdr, &cfg, sizeof(cfg), &status);
    xdbg_log(XDBG_NOTICE, "===== RESULT: %d  (data, n [n]) -- val = %d status = %d",
             retval, hdr.value, status);
    assert(retval == TRUE && hdr.value == 2222 && cfg.seq == 2222);
}

void xstr_test()
{
    char *p;
    uint8_t bin_buf[128];
    char hex_buf[128];
    uint8_t bin[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    char *hex = (char *)"aabbccddee";
    size_t n;
    
    p = xstr_bin2hex(hex_buf, bin, sizeof(bin));
    assert(strcmp(p, hex) == 0);
    
    n = xstr_hex2bin(bin_buf, hex, (size_t)strlen(hex));
    assert(memcmp(bin_buf, bin, n) == 0);
    
    memset(bin_buf, 0xaa, sizeof(bin_buf));
    xstr_dump(bin_buf, sizeof(bin_buf), 8);
    
    n = xstr_ipstr((char *)bin_buf, sizeof(bin_buf), hex);
    printf("\nip = %s (len = %d)", bin_buf, (int)n);
}

void do_test()
{
    xdbg_log(XDBG_NOTICE, "+++++ BEGIN TEST");

    event_test();

    put_test();

    set_get_test();

    data_test();

    xdbg_log(XDBG_NOTICE, "+++++ END TEST");
    xdbg_log(XDBG_NOTICE, "");
}

static void *client_thread(void *param)
{
    if (param) {}

    g_pkt_ipc = xipc_unix_client(XIPC_DGRAM, (char *)DGRAM_SOCK_FILE);
    g_cfg_ipc = xipc_unix_client(XIPC_STREAM, (char *)STREAM_SOCK_FILE);

    do_test();
    
    return NULL;
}

void start_client()
{
    pthread_create(&g_client_tid, NULL, client_thread, NULL);
}

xipc_status_s server_proc_pkt(xipc_s *xipc, xipc_hdr_s *xhdr,
                              void *data, size_t *size, // FIXME
                              void *param)
{
    uint8_t *packet = (uint8_t *)data;
    static int cnt=0;
    char *p = (char *)data;
    
    if (xipc) {}
    if (data) {}
    if (size) {}
    if (param) {}
    if (p) {}
    if (xhdr) {}

    xdbg_log(XDBG_INFO, "<== [%2d:%d]- %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
             cnt++, *size,
             packet[0], packet[1], packet[2], packet[3], packet[4], packet[5],
             packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);

    return TRUE;
}

xipc_status_s server_hello_handler(xipc_s *xipc, xipc_hdr_s *xhdr, void *data, size_t *size, void *param)
{
    int retval = 7777;
    
    if (xipc) {}
    if (data) {}
    if (size) {}
    if (param) {}

    xdbg_log(XDBG_NOTICE, "<---- server_hello_handler (size = %d) [op %d, mtype: %d, value: %d]",
                 *size, xhdr->op, xhdr->mtype, xhdr->value);
    
    return retval ;
}

xipc_status_s server_set_handler(xipc_s *xipc, xipc_hdr_s *xhdr, void *data, size_t *size, void *param)
{
    char *p = (char *)data;
    set_cfg_s *cfg = (set_cfg_s *)data;
    int retval;
    
    if (xipc) {}
    if (data) {}
    if (size) {}
    if (param) {}
    if (p) {}
    
    if (xhdr) {}
    
    xdbg_log(XDBG_NOTICE, "----> server_set_handler [op %d, mtype: %d, value: %d] cfg - seq = %d",
                 xhdr->op, xhdr->mtype, xhdr->value, cfg->seq);

    xhdr->value = 1111;
    if (data)
    {
        cfg->seq = 1111;
    }

    xdbg_log(XDBG_NOTICE, "<---- server_set_handler [op %d, mtype: %d, value: %d] cfg - seq = %d",
                 xhdr->op, xhdr->mtype, xhdr->value, cfg->seq);

    retval = XIPC_NO_ERROR;
    
    return retval ;
}

xipc_status_s server_get_handler(xipc_s *xipc, xipc_hdr_s *xhdr, void *data, size_t *size, void *param)
{
    char *p = (char *)data;
    volatile get_cfg_s *cfg = (get_cfg_s *)data;
    int retval;
    
    if (xipc) {}
    if (data) {}
    if (size) {}
    if (param) {}
    if (p) {}
    
    if (xhdr) {}
    
    xdbg_log(XDBG_NOTICE, "----> server_get_handler [op %d, mtype: %d, value: %d] seq = %d",
                 xhdr->op, xhdr->mtype, xhdr->value, cfg->seq);

    xhdr->value = 2222;
    if (data)
        cfg->seq = 2222;
        
    retval = XIPC_NO_ERROR;

    xdbg_log(XDBG_NOTICE, "<---- server_get_handler [op %d, mtype: %d, value: %d] - seq %d",
             xhdr->op, xhdr->mtype, xhdr->value, cfg->seq);

    *size = sizeof(get_cfg_s);
    
    return retval ;
}

void register_xipc_handler()
{
    xipc_hdr_s hdr;
    
    // event
    hdr.op = OP_EVENT;
    hdr.mtype = MSG_PKT;
    assert(xipc_set_group_handler(g_rpkt_ipc, &hdr, server_proc_pkt, 0, NULL) == TRUE);
    assert(xipc_set_group_handler(g_rcfg_ipc, &hdr, server_proc_pkt, 0, NULL) == TRUE);

    hdr.op = OP_EVENT;
    hdr.mtype = MSG_HELLO;
    assert(xipc_set_group_handler(g_rcfg_ipc, &hdr, server_hello_handler, 0, NULL) == TRUE);
    assert(xipc_set_group_handler(g_rpkt_ipc, &hdr, server_hello_handler, 0, NULL) == TRUE);

    hdr.op = OP_PUT;
    hdr.mtype = MSG_HELLO;
    assert(xipc_set_group_handler(g_rcfg_ipc, &hdr, server_hello_handler, 0, NULL) == TRUE);
    assert(xipc_set_group_handler(g_rpkt_ipc, &hdr, server_hello_handler, 0, NULL) == TRUE);

    hdr.op = OP_PUT;
    hdr.mtype = MSG_CFG;
    assert(xipc_set_group_handler(g_rcfg_ipc, &hdr, server_set_handler, sizeof(set_cfg_s), NULL) == TRUE);
    assert(xipc_set_group_handler(g_rpkt_ipc, &hdr, server_set_handler, sizeof(set_cfg_s), NULL) == TRUE);

    hdr.op = OP_SET_GET;
    hdr.mtype = MSG_CFG;
    assert(xipc_set_group_handler(g_rcfg_ipc, &hdr, server_set_handler, sizeof(set_cfg_s), NULL) == TRUE);
    assert(xipc_set_group_handler(g_rpkt_ipc, &hdr, server_set_handler, sizeof(set_cfg_s), NULL) == TRUE);

    hdr.op = OP_GET;
    hdr.mtype = MSG_CFG;
    assert(xipc_set_group_handler(g_rcfg_ipc, &hdr, server_get_handler, 0, NULL) == TRUE);
    assert(xipc_set_group_handler(g_rpkt_ipc, &hdr, server_get_handler, 0, NULL) == TRUE);

    hdr.op = OP_GET_DATA;
    hdr.mtype = MSG_CFG;
    assert(xipc_set_group_handler(g_rcfg_ipc, &hdr, server_get_handler, sizeof(get_cfg_s), NULL) == TRUE);
    assert(xipc_set_group_handler(g_rpkt_ipc, &hdr, server_get_handler, sizeof(get_cfg_s), NULL) == TRUE);
}

void start_server()
{
    g_xnet = xnet_open(usr_init, NULL);

    recurr_timer = xnet_add_timer(g_xnet, 1000,
                                  recurr_function, NULL, FALSE);

    once_timer = xnet_add_timer(g_xnet, 1000,
        run_once_function, recurr_timer, FALSE);


    // open server
    g_rpkt_ipc = xipc_unix_server(XIPC_DGRAM, (char *)DGRAM_SOCK_FILE, 0);
    g_rcfg_ipc = xipc_unix_server(XIPC_STREAM, (char *)STREAM_SOCK_FILE, 0);

    xnet_add_socket(g_xnet, xipc_get_fd(g_rpkt_ipc), xipc_process_trans, g_rpkt_ipc);
    xnet_add_socket(g_xnet, xipc_get_fd(g_rcfg_ipc), xipc_process_trans, g_rcfg_ipc);
    
    register_xipc_handler();
    
    xnet_start(g_xnet, NULL, NULL, 0);
}

void packet_loop()
{        
}

int main(int argc, char *argv[])
{
    if (argc || argv) {}

    register_signal_handler();

    xdbg_set_priority(XDBG_INFO);
    
    start_server();

    start_client();

    g_xdev = xdev_open((char *)XDEV_DEFAULT_DEV, NULL, TRUE, NULL);
    
    xdev_start(g_xdev, pkt_rx_cb);
    
    pthread_join(g_client_tid, NULL);

    xdbg_log(XDBG_NOTICE, "main routine - test completed. \n");

    cleanup();

    return 0;
}





