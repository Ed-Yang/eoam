#include <stdio.h>
#include <stdlib.h> // exit
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h> // fork
#include <signal.h>

#include "xutl_net.h"

//
// globals
//
static xtimer_s *recurr_timer, *once_timer;
static xnet_s *g_xnet;

//
// local functions
//
static void signal_handler(int type)
{
    if (type) {}
    
    xdbg_log(XDBG_INFO, "CTRL-C received. terminating the xnet.");
    fflush(stderr);

    xnet_stop(g_xnet);
    xnet_close(g_xnet);

    fclose( stdin );
    fclose( stdout );
    fclose( stderr );

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
					
    handler.sa_flags = 0;
					
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

    return ;
}

BOOLEAN dummy_function(xtimer_s *xtimer, void *param)
{
    if (xtimer) {}
    if (param) {}
    
    
    xdbg_log(XDBG_INFO, "-----");
    sleep(1);
    
    return TRUE;
}

BOOLEAN recurr_function(xtimer_s *xtimer, void *param)
{
    xtimer_s *t = (xtimer_s *) param;
    
    if (xtimer) {}
    
    xdbg_log(XDBG_INFO, "+++++ recurrsing timer get called");

    xnet_start_timer(t);

    return TRUE;
}

BOOLEAN runc_once_function(xtimer_s *xtimer, void *param)
{
    if (xtimer) {}
    if (param) {}
    
    xdbg_log(XDBG_DEBUG, "---- run once timer get called");

    return FALSE;
}

void usr_init(void *xnet, void *param)
{
    if (xnet) {}
    if (param) {}
    
    xdbg_log(XDBG_DEBUG, "init timer, start recurrsing timer"); 

    xnet_start_timer(recurr_timer);
}

int main(int argc, char *argv[])
{
    int timeout = 10;

    if (argc || argv) {}

    register_signal_handler();

    xdbg_set_priority(XDBG_INFO);

    g_xnet = xnet_open(usr_init, NULL);

    once_timer = xnet_add_timer(g_xnet, 1000,
        runc_once_function, NULL, FALSE);

    recurr_timer = xnet_add_timer(g_xnet, 2000,
        recurr_function, once_timer, FALSE);

    xnet_start_timer(once_timer);

    xdbg_log(XDBG_INFO, "xnet started"); 
    xnet_start(g_xnet, NULL, NULL, 0);

    timeout = 5;
    while (timeout > 0)
    {
        xdbg_log(XDBG_INFO, "running %d", timeout);
        timeout--;
        sleep(1);
    }

    xdbg_log(XDBG_INFO, "stop all timer"); 
    xnet_stop_timer(recurr_timer);
    xnet_stop_timer(once_timer);

    timeout = 5;
    while (timeout > 0)
    {
        xdbg_log(XDBG_INFO, "stopping %d", timeout);
        timeout--;
        sleep(1);
    }

    xdbg_log(XDBG_INFO, "remove all timer"); 
    xnet_remove_timer(recurr_timer);
    xnet_remove_timer(once_timer);
    
    timeout = 10;
    while (timeout-- > 0)
    {
        xdbg_log(XDBG_INFO, "add dummy timer    - %d", timeout);
        recurr_timer = xnet_add_timer(g_xnet, 10,
                                      dummy_function, NULL, TRUE);
        xdbg_log(XDBG_INFO, "remove dummy timer - %d", timeout);
    }
    xnet_stop(g_xnet);
    xnet_close(g_xnet);
    
    return 0;
}





