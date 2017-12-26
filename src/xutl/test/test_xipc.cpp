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

#define NA     0

#define STREAM_SOCK_FILE    "/tmp/test_ipc.stream.sock"
#define DGRAM_SOCK_FILE     "/tmp/test_ipc.dgram.sock"

// op
typedef enum
{
    OP_EVENT  = 1, //Yes
    OP_EXEC, // Yes
    OP_PUT, // Yes
    OP_DATA, // Yes
    OP_GET, // Yes
    OP_MAX
} op_e;

typedef enum
{
    MSG_CFG,
    MSG_MAX
} msg_e;

typedef struct
{
    uint32_t seq;
    uint8_t pad[12];
} test_cfg_s;

typedef struct
{
    BOOLEAN run_flag;
    const char *name;
    // api fields (the server will copy the hdr.value to status_code
    // and and copy seq to hdr.value and clear cfg.seq
    xipc_hdr_s hdr;
    void *data;
    uint32_t dsize;
    uint32_t rsp_data_size;
    // data
    uint32_t seq;
    // result
    uint32_t exp_value;
    uint32_t exp_seq;
    xipc_status_s exp_status;
    BOOLEAN exp_retval;
} test_item_s;

test_cfg_s cfg;
uint32_t ds = sizeof(cfg);

/**
 * @brief 
 * 
 * data && *size > 0:
 *  1. copy the hdr.value to status_code
 *  2. copy seq to hdr.value
 *  3. clear cfg.seq
 * else:
 *  1. status_code = hdr.value
 *  2. hdr.value = 0
 */
test_item_s g_stream_items[] =
{
    // OP_EXEC (OP <--> OP)
    //                 VAL    OP       MTYPE     DATA  dsize  r_dsize       seq   e_val e_seq e_st  e_ret
    {TRUE , "EXEC_OK", {0x00, OP_EXEC, MSG_CFG}, NULL, 0,     XIPC_RSP_ACK, 0xaa, 0x00, 0xaa, 0x00, TRUE}, // XIPC_NO_ERROR
    {TRUE , "EXEC_NG", {0x55, OP_EXEC, MSG_CFG}, NULL, 0,     XIPC_RSP_ACK, 0xaa, 0x55, 0xaa, 0x55, TRUE}, // Other
    // OP_PUT (OP + DATA <--> OP)
    //                 VAL   OP      MTYPE       DATA  dsize  r_dsize       seq   e_val e_seq e_st  e_ret
    {TRUE , "PUT_OK", {0x00, OP_PUT, MSG_CFG},   &cfg, ds,    XIPC_RSP_ACK, 0xaa, 0xaa, 0xaa, 0x00, TRUE}, // XIPC_NO_ERROR
    {TRUE , "PUT_NG", {0x55, OP_PUT, MSG_CFG},   &cfg, ds,    XIPC_RSP_ACK, 0xaa, 0x55, 0xaa, 0x55, TRUE}, // Other

    // OP_GET (OP <--> OP + DATA)
    //                 VAL   OP      MTYPE       DATA  dsize  r_dsize       seq   e_val e_seq e_st  e_ret
    {TRUE , "GET_OK", {0x00, OP_GET, MSG_CFG},   &cfg, 0,     ds,           0xaa, 0x00, 0x00, 0x00, TRUE}, // XIPC_NO_ERROR
    {TRUE , "GET_NG", {0x55, OP_GET, MSG_CFG},   &cfg, 0,     ds,           0xaa, 0x55, 0xaa, 0x55, TRUE}, // Other

    // OP_DATA (OP + DATA <--> OP + DATA
    //                VAL    OP       MTYPE       DATA  dsize   r_dsize       seq   e_val e_seq e_st  e_ret
    {TRUE , "DATA_OK",{0x00, OP_DATA, MSG_CFG},   &cfg, ds,     ds,           0xaa, 0xaa, 0x00, 0x00, TRUE}, // XIPC_NO_ERROR
    {TRUE , "DATA_NG",{0x55, OP_DATA, MSG_CFG},   &cfg, ds,     ds,           0xaa, 0x55, 0xaa, 0x55, TRUE}, // Other

};

//
// globals
//

// client
pthread_t g_client_tid;
xipc_s *g_stream_ipc;
xipc_s *g_dgram_ipc;

// server
static xnet_s *g_xnet;
xipc_s *g_serv_stream_ipc;
xipc_s *g_serv_dgram_ipc;


//
// local functions
//
void cleanup(void)
{
    //pthread_join(g_client_tid, NULL);

    // client ipc    
    xipc_close(g_stream_ipc);
    xipc_close(g_dgram_ipc);

    // server ipc
    xipc_close(g_serv_stream_ipc);
    xipc_close(g_serv_dgram_ipc);

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

    xnet_stop(g_xnet);

    /* reset and raise original signal again */
    signal(SIGINT, SIG_DFL);
    raise(SIGINT);

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

void usr_init(void *xnet, void *param)
{
    if (xnet) {}
    if (param) {}
    
    xdbg_log(XDBG_INFO, "user init called"); 
}

void do_test()
{
    xipc_hdr_s hdr;
    int i;
    xipc_status_s status;
    BOOLEAN retval;
    //test_cfg_s cfg;

    xdbg_log(XDBG_INFO, "+++++ BEGIN TEST");

    for (i=0; i < (int)(sizeof(g_stream_items)/sizeof(test_item_s)); i++)
    {
        if (g_stream_items[i].run_flag != TRUE)
            continue;
        
        xdbg_log(XDBG_INFO, "ITEM: %s", g_stream_items[i].name);
        
        memcpy(&hdr, &g_stream_items[i].hdr, sizeof(xipc_hdr_s));
        
        cfg.seq = g_stream_items[i].seq;
        retval = xipc_client_trans(
            g_stream_ipc, &hdr, 
            g_stream_items[i].data, g_stream_items[i].dsize,
            g_stream_items[i].rsp_data_size,
            &status);
        
        assert(g_stream_items[i].exp_seq == cfg.seq);
        assert(g_stream_items[i].exp_value == hdr.value);
        assert(g_stream_items[i].exp_status == status) ;
        assert(g_stream_items[i].exp_retval == retval);
    }

    xdbg_log(XDBG_INFO, "+++++ END TEST");
    xdbg_log(XDBG_INFO, "");
}

static void *client_thread(void *param)
{
    if (param) {}

    g_dgram_ipc = xipc_unix_client(XIPC_DGRAM, (char *)DGRAM_SOCK_FILE);
    g_stream_ipc = xipc_unix_client(XIPC_STREAM, (char *)STREAM_SOCK_FILE);

    do_test();
    
    xnet_stop(g_xnet);
    
    return NULL;
}

void start_client()
{
    pthread_create(&g_client_tid, NULL, client_thread, NULL);
}

/**
 * @brief 
 * 
 * @param xipc 
 * @param xhdr 
 * @param data 
 * @param size 
 * @param param 
 * @return xipc_status_s 
 *
 * data && *size > 0:
 *  1. copy the hdr.value to status_code
 *  2. copy seq to hdr.value
 *  3. clear cfg.seq
 * else:
 *  1. status_code = hdr.value
 *  2. hdr.value = 0
 *  3. if set *size > 0, cfg->seq = 0
 * 
 */
xipc_status_s stream_handler(xipc_s *xipc, xipc_hdr_s *xhdr, void *data, size_t *size, void *param)
{
    char *p = (char *)data;
    test_cfg_s *p_cfg = (test_cfg_s *)data;
    int status_code = 0 /* 0 for success */;
    
    if (xipc) {}
    if (data) {}
    if (size) {}
    if (param) {}
    if (p) {}
    
    if (xhdr) {}
    
    if (data != NULL && *size > 0)
        xdbg_log(XDBG_INFO, "--> [value: %d, op %d, mtype: %d] *size = %d seq: %d",
                 xhdr->value, xhdr->op, xhdr->mtype, *size, p_cfg->seq);
    else
        xdbg_log(XDBG_INFO, "--> [value: %d, op %d, mtype: %d] *size = %d",
                 xhdr->value, xhdr->op, xhdr->mtype, *size);

    status_code = xhdr->value;
    
    if (xhdr->op == OP_GET)
    {
        memset(p_cfg, 0, sizeof(cfg));
        *size = sizeof(test_cfg_s);
    }
    
    if (data != NULL && *size > 0)
    {
        xhdr->value = p_cfg->seq ;
        p_cfg->seq = 0;
    }
    else
        xhdr->value = 0;

    if (data != NULL && *size > 0)
        xdbg_log(XDBG_INFO, "<-- [value: %d, op %d, mtype: %d] *size = %d seq: %d, status: %d",
                 xhdr->value, xhdr->op, xhdr->mtype, *size, p_cfg->seq, status_code);
    else
        xdbg_log(XDBG_INFO, "<-- [value: %d, op %d, mtype: %d] *size = %d, status: %d",
                 xhdr->value, xhdr->op, xhdr->mtype, *size, status_code);

    return status_code ;
}

void register_xipc_handler()
{
    xipc_hdr_s hdr;
    int i;
    BOOLEAN retval = TRUE;
    
    if (retval) {}

    for (i=0; i < (int)(sizeof(g_stream_items)/sizeof(test_item_s)); i++)
    {
        memcpy(&hdr, &g_stream_items[i].hdr, sizeof(xipc_hdr_s));
        
        retval = xipc_set_group_handler(
            g_serv_stream_ipc, &hdr, 
            stream_handler, 
            g_stream_items[i].dsize,
            NULL);

        //assert(retval == TRUE);
    }
}

void start_server()
{
    g_xnet = xnet_open(usr_init, NULL);

    // open server
    g_serv_stream_ipc = xipc_unix_server(XIPC_STREAM, (char *)STREAM_SOCK_FILE, 0);
    g_serv_dgram_ipc = xipc_unix_server(XIPC_DGRAM, (char *)DGRAM_SOCK_FILE, 0);

    xnet_add_socket(g_xnet, xipc_get_fd(g_serv_stream_ipc), xipc_process_trans, g_serv_stream_ipc);
    xnet_add_socket(g_xnet, xipc_get_fd(g_serv_dgram_ipc), xipc_process_trans, g_serv_dgram_ipc);
    
    register_xipc_handler();
    
}

/**
 * @brief 
 * 
 * main
 *  - start server
 *  - star client test thread
 *  - wait
 *  ......
 *  - cleanup 
 *      - stop/close xnet
 *      - close ipc
 * 
 * client test thread
 *  - do test
 *  - stop xnet
 */
int main(int argc, char *argv[])
{
    if (argc || argv) {}

    
    register_signal_handler();

    xdbg_set_priority(XDBG_INFO);
 
    start_server();

    start_client();
 
    xnet_start(g_xnet, NULL, NULL, 0);
    
    pthread_join(g_client_tid, NULL);
    
    xnet_wait(g_xnet);

    cleanup();


    return 0;
}





