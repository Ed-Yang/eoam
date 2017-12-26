#include <stdio.h>
#include <stdlib.h> /* exit */
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h> /* fork */
#include <signal.h>
#include <pcap.h>

#include "xutl_bits.h"
#include "xutl_os.h"
#include "xutl_dev.h"
#include "xutl_dbg.h"

#include "eoam_fsm.h"
#include "eoam_cout.h"
#include "eoam_params.h"

/*
 * globals
 *
 */

/*
 * local functions
 *
 */

#ifdef WRITE_PID
static int write_pidfile(char *pidpathname)
{

    return 0;
}
#endif

void *cleanup(void *param)
{
    if (param)
    {
    }

    xdbg_log(XDBG_INFO, "CTRL-C cleanup xnet ...");
    eoam_fsm_terminate();
    xdbg_log(XDBG_INFO, "CTRL-C cleanup xnet - done.");

    return NULL;
}

/**
 * signal_handler
 *
 * @param type
 *
 * NOTE, in signal handler, it is un-safe to invoke pthread functions, especially
 * the pthread_mutex_lock.
 */
static void signal_handler(int type)
{
    pthread_t tid;

    if (type)
    {
    }

    xdbg_log(XDBG_INFO, "CTRL-C received. terminating the eoam client.");
    fflush(stderr);

    /* spawn a thread to avoid call to pthread_mutex_lock directly. */
    pthread_create(&tid, NULL, cleanup, NULL);
    pthread_join(tid, NULL); 

    /* reset and raise original signal again */
    signal(SIGINT, SIG_DFL);
    raise(SIGINT);

#if 1
    /* close standard io */
    fclose( stdin );
    fclose( stdout );
    fclose( stderr );
#endif

    return;
}

void register_signal_handler()
{
    struct sigaction handler; /* signal handler specification structure */

    /* set InterruptSignalHandler as handler function */
    handler.sa_handler = signal_handler;

    sigfillset(&handler.sa_mask); /* sigfillset is a macro, no return value */

    handler.sa_flags = 0;

    /* set signal handling for interrupt signals */
    if (sigaction(SIGINT, &handler, 0) < 0)
    {
        perror("sigaction");
        exit(0);
    }

    /* set signal handling for interrupt signals */
    if (sigaction(SIGHUP, &handler, 0) < 0)
    {
        perror("sigaction");
        exit(0);
    }

    signal(SIGPIPE, SIG_IGN); /* prevent got signal on send to a closing socket */

    return;
}

int main(int argc, char *argv[])
{
    eoam_params_s oam_params;
    char oui[] = OAM_PARAM_OUI;

    /* change the file mode mask */
    umask(0);

    register_signal_handler();

    memset(&oam_params, 0, sizeof(oam_params));

    if (argc > 1)
    {
        strcpy(oam_params.dev_name, argv[1]);
        xos_get_mac(oam_params.dev_name, (char *)oam_params.dev_mac);
    }
    else
    {
        strcpy(oam_params.dev_name, xos_eth_dev());
        xos_get_mac(oam_params.dev_name, (char *)oam_params.dev_mac);
    }

    oam_params.filter_flag = TRUE;
    strcpy(oam_params.dev_filter, (char *)"ether dst 01:80:c2:00:00:02");

    strcpy(oam_params.pkt_sock_path, EOAM_PKT_PATH);
    strcpy(oam_params.cfg_sock_path, EOAM_CFG_PATH);
    oam_params.max_oam_ports = OAM_PARAM_MAX_PORTS;

    oam_params.admin_state = OAM_PARAM_ADMIN_STATE;
    oam_params.rx_mode = OAM_PARAM_RX_MODE;

    oam_params.oam_version = OAM_PARAM_OAM_VERSION;
    oam_params.support_var_retrieval = OAM_PARAM_VARREQ;
    oam_params.support_link_event = OAM_PARAM_LINK_EVENT;
    oam_params.support_lpbk = OAM_PARAM_LPBK;
    oam_params.support_unidirectional = OAM_PARAM_UNIDIRECT;
    oam_params.oam_mode = OAM_PARAM_OAM_MODE;
    oam_params.max_pdu_size = OAM_PARAM_PDU_SIZE;
    oam_params.oam_timeout = OAM_PARAM_OAM_TIMEOUT;
    oam_params.lpbk_timeout = OAM_PARAM_LPBK_TIMEOUT;
    oam_params.log_table_size = OAM_PARAM_LOG_TBL_SIZE;

    memcpy(oam_params.oui, oui, 3);

    oam_params.vendor_info = OAM_PARAM_VENDOR;
    
    xdbg_set_priority(XDBG_INFO);

    if (eoam_fsm_init(&oam_params) != TRUE)
    {
        fprintf(stderr, "\neoam_fsm_init: failed !!! (check previlidge)\n");
        return -1;
    }

    eoam_fsm_loop(NULL);

    sleep(2); /* FIXME:quit wait proce quit command */

    eoam_fsm_terminate();

    fprintf(stderr, "\neoam main program exit.\n");

    return 0;
}





