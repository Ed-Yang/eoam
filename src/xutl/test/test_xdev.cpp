#include <iostream>
#include <stdio.h>
#include <stdlib.h> // exit
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h> // fork
#include <signal.h>
#include <pthread.h>

#include "xutl_net.h"
#include "xutl_dev.h"
#include "xutl_ipc.h"


static BOOLEAN rx_ok_cb(xdev_s *xdev, uint32_t ifindex, uint8_t *packet, size_t len)
{
    BOOLEAN retval = TRUE;
    
    if (xdev) {}
    
    xdbg_log(XDBG_INFO, "<-- [%2d:%d]- %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
             ifindex, len,
             packet[0], packet[1], packet[2], packet[3], packet[4], packet[5],
             packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
    
    return retval;
}

#if 1
static BOOLEAN rx_ng_cb(xdev_s *xdev, uint32_t ifindex, uint8_t *packet, size_t len)
{
    BOOLEAN retval = TRUE;
    static int count = 5;

    if (xdev) {}

    xdbg_log(XDBG_INFO, "<-- [%2d:%d]- %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
             ifindex, len,
             packet[0], packet[1], packet[2], packet[3], packet[4], packet[5],
             packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);

    if (count-- <= 0)
        retval = FALSE;

    return retval;
}
#endif

static void *open_close_thread(void *param)
{
    xdev_s *xdev ;
    intptr_t p_int = (intptr_t)param;
    //static char *filter = (char *)"ether dst 01:80:c2:00:00:02";
    char *filter = NULL;

    if (param) {}
    
    xdbg_log(XDBG_INFO, "open_close_thread: thread %d 0x%08x running ...", p_int, pthread_self());
             
    xdbg_log(XDBG_INFO, "open_close_thread: open -------------------", p_int, pthread_self());
    xdev = xdev_open((char *)XDEV_DEFAULT_DEV, NULL, TRUE, filter);

    if (xdev == NULL)
    {
        xdbg_log(XDBG_INFO, "open_close_thread: thread %d 0x%08x, dev_open failed !!!", 
            p_int, pthread_self());
    }
    else
    {
        xdbg_log(XDBG_INFO, "open_close_thread: close ------------------", p_int, pthread_self());
        xdev_close(xdev);
    }
    
    return (void *)p_int; /* same as call pthread_exit */
}

static void *full_thread(void *param)
{
    xdev_s *xdev ;
    intptr_t p_int = (intptr_t)param;
    //static char *filter = (char *)"ether dst 01:80:c2:00:00:02";
    char *filter = NULL;

    if (param) {}
    
    xdbg_log(XDBG_INFO, "full_thread: thread %d 0x%08x running ...", p_int, pthread_self());
             
    xdev = xdev_open((char *)XDEV_DEFAULT_DEV, NULL, TRUE, filter);

    if (xdev == NULL)
    {
        xdbg_log(XDBG_INFO, "full_thread: thread %d 0x%08x, dev_open failed !!!", 
            p_int, pthread_self());
    }
    else
    {
        xdev_start(xdev, rx_ng_cb);

        xdev_stop(xdev);
    
        xdev_close(xdev);
    }
    
    return (void *)p_int; /* same as call pthread_exit */
}

static void *stop_thread(void *param)
{
    xdev_s *xdev = (xdev_s *)param;
    
    xdbg_log(XDBG_INFO, "[0x%08x, 0x%08x] thread stop rx running ...",
             pthread_self(), xdev);
    
    xdev_stop(xdev);
    
    xdev_close(xdev);
    
    return (void *)xdev;
}

#define TEST_NUM 10

void test_open_close()
{
    intptr_t v;
    void *r;
    
    pthread_t th[TEST_NUM];
    
    xdbg_log(XDBG_INFO, "######## test_open_close");
             
    for (int i=0; i < TEST_NUM; i++)
    {
        v = i ;
        pthread_create(&th[i], NULL, open_close_thread, (void *)v);
    }
    
    for (int i=0; i < TEST_NUM; i++)
    {
        pthread_join(th[i], &r);
        xdbg_log(XDBG_INFO, "thread %d 0x%08x exit ...", r, pthread_self());
    }
}

void test_full()
{
    intptr_t v;
    void *r;
    pthread_t th[TEST_NUM];
    
    xdbg_log(XDBG_INFO, "######## test_full");
    
    for (int i=0; i < TEST_NUM; i++)
    {
        v = i ;
        pthread_create(&th[i], NULL, full_thread, (void *)v);
    }
    
    for (int i=0; i < TEST_NUM; i++)
    {
        pthread_join(th[i], &r);
        xdbg_log(XDBG_INFO, "thread %d 0x%08x exit ...", r, pthread_self());
    }
}

pthread_t start_thr[TEST_NUM];
pthread_t stop_thr[TEST_NUM];

void test_start_stop()
{
    xdev_s *xdev[TEST_NUM];
    void *r;
    char *filter = NULL;
    
    xdbg_log(XDBG_INFO, "######## test_start_stop");
    
    // start
    for (int i=0; i < TEST_NUM; i++)
    {
        xdev[i] = xdev_open((char *)XDEV_DEFAULT_DEV, NULL, TRUE, filter);

        if (xdev[i] == NULL)
        {
            xdbg_log(XDBG_INFO, "test_start_stop: dev_open failed !!!");
            continue;
        }
        else
        {
            xdev_start(xdev[i], rx_ok_cb);
        }
    }

    // stop
    for (int i=0; i < TEST_NUM; i++)
    {
        if (xdev[i] != NULL)
            pthread_create(&stop_thr[i], NULL, stop_thread, (void *)xdev[i]);
    }

    // collect stop thread
    for (int i=0; i < TEST_NUM; i++)
    {
        if (xdev[i] != NULL)
        {
            pthread_join(stop_thr[i], &r);
            xdbg_log(XDBG_INFO, "thread stop %d 0x%08x exit ...", r, pthread_self());
        }
    }
}

void test_open_stop()
{
    xdev_s *xdev ;
    char *filter = NULL;
    
    xdbg_log(XDBG_INFO, "######## test_open_stop");
    
    xdev = xdev_open((char *)XDEV_DEFAULT_DEV, NULL, TRUE, filter);

    if (xdev == NULL)
    {
        xdbg_log(XDBG_INFO, "test_open_stop: dev_open failed !!!");
    }
    else
    {
        xdev_stop(xdev);
    
        xdev_close(xdev);
    }
}

void test_first_dev()
{
    xdev_s *xdev ;
    char *filter = NULL;
    
    xdbg_log(XDBG_INFO, "######## test_first_dev");
    
    xdev = xdev_open(NULL, NULL, TRUE, filter);

    if (xdev == NULL)
    {
        xdbg_log(XDBG_INFO, "test_first_dev: dev_open failed !!!");
    }
    else
    {
        xdev_stop(xdev);
        xdev_close(xdev);
    }
}

int main(int argc, char *argv[])
{
    //int i = 1;

    if (argc || argv) {}

    signal(SIGPIPE, SIG_IGN); // prevent got signal on send to a closing socket

    xdbg_set_priority(XDBG_INFO);
 
    test_open_close();
    test_first_dev();
    test_open_stop();
    full_thread(&argc);
    test_full();
    test_start_stop();

    fclose( stdin );
    fclose( stdout );
    fclose( stderr );

    return 0;
}



