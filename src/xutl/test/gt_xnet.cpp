#include <iostream>
#include <stdio.h>
#include <stdlib.h> // exit
#include <fcntl.h> // O_CREATE
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h> // fork
#include <signal.h>
#include <pthread.h>
#include <semaphore.h>


#include "xutl_net.h"
#include "xutl_dev.h"
#include "xutl_ipc.h"
#include "xutl_mem.h"

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#define TEST_STREAM_FILE  "/tmp/gt_xnet.stream.sock"
#define TEST_DGRAM_FILE  "/tmp/gt_xnet.dgram.sock"

void xnet_usr_init(void *xnet, void *param)
{
    xdbg_log(XDBG_INFO, "xnet_user_init: called xnet = 0x%08x, param = 0x%08x",
             xnet, param);

    return ;
}

void xnet_usr_timer(xnet_s *xnet, void *param)
{
    int *v = (int *)param;
    
    *v = *v + 1;
    
    xdbg_log(XDBG_TRACE, "xnet_usr_timer: called xnet = 0x%08x, param = %d",
             xnet, *v);
    
    return ;
}

TEST(XNET, OpenClose)
{
    xnet_s *xnet ;
    
    xnet = xnet_open(xnet_usr_init, NULL);
    EXPECT_TRUE( NULL != xnet);
    EXPECT_TRUE(xnet_close(xnet));
}

TEST(XNET, OpenStartStopClose)
{
    xnet_s *xnet ;

    xnet = xnet_open(NULL, NULL);
    EXPECT_TRUE( NULL != xnet);

    EXPECT_TRUE(xnet_start(xnet, NULL, NULL, 0));
    EXPECT_TRUE(xnet_stop(xnet));
    EXPECT_TRUE(xnet_close(xnet));
}

TEST(XDEF, DefaultTimer)
{
    xnet_s *xnet ;
    int v = 0;
    
    xnet = xnet_open(NULL, NULL);
    EXPECT_TRUE( NULL != xnet);
    
    EXPECT_TRUE(xnet_start(xnet, xnet_usr_timer, (void *)&v, 0));
    sleep(2);
    EXPECT_GT(v, 0);
    EXPECT_TRUE(xnet_stop(xnet));
    EXPECT_TRUE(xnet_close(xnet));
}


TEST(XNET, OpenStartClose)
{
    xnet_s *xnet ;

    xnet = xnet_open(xnet_usr_init, NULL);
    EXPECT_TRUE( NULL != xnet);
    
    EXPECT_TRUE(xnet_start(xnet, NULL, NULL, 0));    

    EXPECT_FALSE(xnet_close(xnet));
    EXPECT_TRUE(xnet_stop(xnet));
    EXPECT_TRUE(xnet_close(xnet));
}

BOOLEAN set_variable(xtimer_s *ti, void *v)
{
    BOOLEAN *ptr = (BOOLEAN *)v;
    
    if (ti) {}
    
    *ptr = TRUE;
    
    return TRUE;
}

TEST(XTIMER, AddDeleteTimer)
{
    xnet_s *xnet ;
    xtimer_s *t1;
    BOOLEAN flag = FALSE;
    
    xnet = xnet_open(NULL, NULL);
    EXPECT_TRUE( NULL != xnet);
    
    EXPECT_TRUE(xnet_start(xnet, NULL, NULL, 0));// non-blocking
    
    t1 = xnet_add_timer(xnet, 1000, set_variable, (void *)&flag, TRUE);
    
    sleep(2);
    
    EXPECT_TRUE(xnet_remove_timer(t1));
    EXPECT_EQ(flag, TRUE);
    EXPECT_TRUE(xnet_stop(xnet));
    EXPECT_TRUE(xnet_close(xnet));
}

BOOLEAN sleep_timer(xtimer_s *ti, void *v)
{
    int *ptr = (int *)v;
    
    if (ti) {}
    
    xdbg_log(XDBG_INFO, "sleep_timer: sleep %d seconds ...", *ptr);
             
    sleep(*ptr);
    
    xdbg_log(XDBG_INFO, "sleep_timer: sleep %d seconds - done.", *ptr);
    
    return TRUE;
}

BOOLEAN counter_timer(xtimer_s *ti, void *v)
{
    int *ptr = (int *)v;
    
    if (ti) {}
    
    *ptr = *ptr + 1;
    
    return TRUE;
}

BOOLEAN spawn_timer(xtimer_s *ti, void *param)
{
    xtimer_s *new_timer = (xtimer_s *)param;
    
    if (ti) {}
    
    xnet_start_timer(new_timer);
    
    return FALSE; /* foce timer to stop */
}

TEST(XTIMER, DelRunningTimer)
{
    xnet_s *xnet ;
    xtimer_s *timer;
    int sec = 5;
    
    xnet = xnet_open(NULL, NULL);
    EXPECT_TRUE( NULL != xnet);
    
    EXPECT_TRUE(xnet_start(xnet, NULL, NULL, 0));
    
    timer = xnet_add_timer(xnet, 10, sleep_timer, (void *)&sec, TRUE);
    
    sleep(1);
    
    EXPECT_TRUE(xnet_remove_timer(timer));

    EXPECT_TRUE(xnet_stop(xnet));
    EXPECT_TRUE(xnet_close(xnet));
}

TEST(XTIMER, TimerInTimerAutoStop)
{
    xnet_s *xnet ;
    xtimer_s *t, *timer;
    int counter = 0;
    int wait_sec = 2;
    
    xnet = xnet_open(NULL, NULL);
    EXPECT_TRUE( NULL != xnet);
    
    EXPECT_TRUE(xnet_start(xnet, NULL, NULL, 0));
    
    timer = xnet_add_timer(xnet, 1000, counter_timer, (void *)&counter, FALSE);
    t = xnet_add_timer(xnet, 1000, spawn_timer, (void *)timer, TRUE);
    
    sleep(wait_sec+1); // FIXME:timer currently timer is not accurate
    
    EXPECT_TRUE(xnet_remove_timer(t));
    EXPECT_TRUE(xnet_remove_timer(timer));
    
    EXPECT_TRUE((counter == wait_sec) || (counter == (wait_sec+1))) ;
    EXPECT_TRUE(xnet_stop(xnet));
    EXPECT_TRUE(xnet_close(xnet));
}

BOOLEAN serv_proce_func(void *p_xnet, int fd, void *param)
{
    xnet_s *xnet = (xnet_s *)p_xnet;
    
    if (xnet) {}
    if (fd) {}
    if (param) {}
    
    
    return TRUE;
}

TEST(XSOCK, AddDeleteSock)
{
    xnet_s *xnet ;
    xsocket_s *s1;
    xsocket_s *s2;
    xipc_s *stream_ipc;
    xipc_s *dgram_ipc;

    stream_ipc = xipc_unix_server(XIPC_DGRAM, (char *)TEST_STREAM_FILE, 0);
    dgram_ipc = xipc_unix_server(XIPC_DGRAM, (char *)TEST_STREAM_FILE, 0);

    xnet = xnet_open(NULL, NULL);
    EXPECT_TRUE( NULL != xnet);
    
    s1 = xnet_add_socket(xnet, xipc_get_fd(stream_ipc), xipc_process_trans, NULL);
    s2 = xnet_add_socket(xnet, xipc_get_fd(dgram_ipc), xipc_process_trans, NULL);
    
    EXPECT_TRUE(xnet_start(xnet, NULL, NULL, 0));// non-blocking
    
    EXPECT_TRUE(xnet_remove_socket(s1));
    EXPECT_TRUE(xnet_remove_socket(s2));

    EXPECT_TRUE(xnet_stop(xnet));
    EXPECT_TRUE(xnet_close(xnet));
    
    EXPECT_TRUE(xipc_close(stream_ipc));
    EXPECT_TRUE(xipc_close(dgram_ipc));

}

typedef enum
{
    OP_EXEC  = 1,
    OP_PUT,
    OP_GET,
    OP_DATA,
    OP_MAX
} op_e;

typedef enum
{
    MSG_ACTION,
    MSG_CFG,
    MSG_SLEEP,
    MSG_MAX
} msg_e;

typedef struct
{
    uint8_t pad[4];
    int seq;
} data_s;

xipc_status_s server_counter_handler(void *data)
{
    char *p = (char *)data;
    data_s *cfg = (data_s *)data;
    xipc_status_s status = XIPC_NO_ERROR;
    
    if (cfg) {}
    if (p) {}
    
    cfg->seq = cfg->seq + 1;
    
    return status ;
}

xipc_status_s server_sleep_handler(void *data)
{
    char *p = (char *)data;
    data_s *cfg = (data_s *)data;
    xipc_status_s status = XIPC_NO_ERROR;
    
    if (cfg) {}
    if (p) {}
    
    xdbg_log(XDBG_INFO, "server_sleep_handler: sleep %d seconds ...", cfg->seq);
    
    sleep(cfg->seq);
    
    xdbg_log(XDBG_INFO, "server_sleep_handler: sleep %d seconds - done.", cfg->seq);
    
    return status ;
}

TEST(XSOCK, Normal)
{
    xnet_s *xnet;
    xipc_hdr_s hdr;
    xipc_status_s status = 999;
    BOOLEAN retval = TRUE;
    data_s data;
    xipc_s *stream_ipc;
    xipc_s *xipc;
    
    memset(&data, 0, sizeof(data));
    
    stream_ipc = xipc_unix_server(XIPC_STREAM, (char *)TEST_STREAM_FILE, 0);
    xipc = xipc_unix_client(XIPC_STREAM, (char *)TEST_STREAM_FILE);
    
    hdr.op = OP_DATA;
    hdr.mtype = MSG_CFG;
    retval = xipc_set_data_handler(stream_ipc, &hdr, server_counter_handler, sizeof(data_s));
    EXPECT_TRUE(retval);

    xnet = xnet_open(NULL, NULL);
    EXPECT_TRUE( NULL != xnet);
    
    xnet_add_socket(xnet, xipc_get_fd(stream_ipc), xipc_process_trans, stream_ipc);

    EXPECT_TRUE(xnet_start(xnet, NULL, NULL, 0));// non-blocking
    
    hdr.op = OP_DATA;
    hdr.mtype = MSG_CFG;
    
    hdr.value = 9999;
    data.seq = 1111;
    retval = xipc_client_data(xipc, &hdr, &data, sizeof(data), &status);
    EXPECT_TRUE(retval);
    EXPECT_EQ(status, XIPC_NO_ERROR);
    EXPECT_EQ(data.seq, 1112);
    
    data.seq = 2222;
    retval = xipc_client_data(xipc, &hdr, &data, sizeof(data), &status);
    EXPECT_TRUE(retval);
    EXPECT_EQ(status, XIPC_NO_ERROR);
    EXPECT_EQ(data.seq, 2223);
    
    xipc_close(xipc);
    xipc_close(stream_ipc);
    
    EXPECT_TRUE(xnet_stop(xnet));
    EXPECT_TRUE(xnet_close(xnet));

}

TEST(XSOCK, LongDelay)
{
    xnet_s *xnet;
    xipc_hdr_s hdr;
    xipc_status_s status = 999;
    BOOLEAN retval = TRUE;
    data_s data;
    xipc_s *stream_ipc;
    xipc_s *xipc;
    uint32_t tout_sec = 3;
    
    memset(&data, 0, sizeof(data));
    
    stream_ipc = xipc_unix_server(XIPC_STREAM, (char *)TEST_STREAM_FILE, 0);
    xipc = xipc_unix_client(XIPC_STREAM, (char *)TEST_STREAM_FILE);
    
    hdr.op = OP_DATA;
    hdr.mtype = MSG_SLEEP;
    retval = xipc_set_data_handler(stream_ipc, &hdr, server_sleep_handler, sizeof(data_s));
    EXPECT_TRUE(retval);

    hdr.op = OP_DATA;
    hdr.mtype = MSG_CFG;
    retval = xipc_set_data_handler(stream_ipc, &hdr, server_counter_handler, sizeof(data_s));
    EXPECT_TRUE(retval);

    // test begin
    xnet = xnet_open(NULL, NULL);
    EXPECT_TRUE( NULL != xnet);
    
    xnet_add_socket(xnet, xipc_get_fd(stream_ipc), xipc_process_trans, stream_ipc);
    
    EXPECT_TRUE(xnet_start(xnet, NULL, NULL, 0));// non-blocking
    
    hdr.op = OP_DATA;
    hdr.mtype = MSG_SLEEP;
    
    hdr.value = 9999;
    data.seq = tout_sec;
    retval = xipc_client_data(xipc, &hdr, &data, sizeof(data), &status);
    EXPECT_FALSE(retval);
    EXPECT_NE(status, XIPC_NO_ERROR);
    
    // server still in exec sleep, so wait a moment
    sleep(tout_sec);
    
    data.seq = 2222;
    hdr.mtype = MSG_CFG;
    retval = xipc_client_data(xipc, &hdr, &data, sizeof(data), &status);
    EXPECT_TRUE(retval);
    EXPECT_EQ(status, XIPC_NO_ERROR);
    EXPECT_EQ(data.seq, 2223);
    
    xipc_close(xipc);
    xipc_close(stream_ipc);
    
    EXPECT_TRUE(xnet_stop(xnet));
    EXPECT_TRUE(xnet_close(xnet));
    
}

TEST(XSOCK, ChangeTimeout)
{
    xnet_s *xnet;
    xipc_hdr_s hdr;
    xipc_status_s status = 999;
    BOOLEAN retval = TRUE;
    data_s data;
    xipc_s *stream_ipc;
    xipc_s *xipc;
    uint32_t tout_sec = 3;
    
    memset(&data, 0, sizeof(data));
    
    stream_ipc = xipc_unix_server(XIPC_STREAM, (char *)TEST_STREAM_FILE, 0);
    xipc = xipc_unix_client(XIPC_STREAM, (char *)TEST_STREAM_FILE);
    
    hdr.op = OP_DATA;
    hdr.mtype = MSG_SLEEP;
    retval = xipc_set_data_handler(stream_ipc, &hdr, server_sleep_handler, sizeof(data_s));
    EXPECT_TRUE(retval);
    
    xnet = xnet_open(NULL, NULL);
    EXPECT_TRUE( NULL != xnet);
    
    xnet_add_socket(xnet, xipc_get_fd(stream_ipc), xipc_process_trans, stream_ipc);
    
    EXPECT_TRUE(xnet_start(xnet, NULL, NULL, 0));// non-blocking
    
    hdr.op = OP_DATA;
    hdr.mtype = MSG_SLEEP;
    
    hdr.value = 9999;
    data.seq = tout_sec;
    retval = xipc_client_data(xipc, &hdr, &data, sizeof(data), &status);
    EXPECT_FALSE(retval);
    EXPECT_NE(status, XIPC_NO_ERROR);

    // server still in exec sleep, so wait a moment
    sleep(tout_sec);

    xipc_set_timeout(xipc, (tout_sec + 1)*1000);
    
    hdr.value = 9999;
    data.seq = tout_sec;
    retval = xipc_client_data(xipc, &hdr, &data, sizeof(data), &status);
    EXPECT_TRUE(retval);
    EXPECT_EQ(status, XIPC_NO_ERROR);

    xipc_close(xipc);
    xipc_close(stream_ipc);
    
    EXPECT_TRUE(xnet_stop(xnet));
    EXPECT_TRUE(xnet_close(xnet));
}

TEST(XSOCK, DelBusySock)
{
    xnet_s *xnet;
    xipc_hdr_s hdr;
    xipc_status_s status = 999;
    BOOLEAN retval = TRUE;
    data_s data;
    xipc_s *stream_ipc;
    xipc_s *xipc;
    
    memset(&data, 0, sizeof(data));
    
    stream_ipc = xipc_unix_server(XIPC_STREAM, (char *)TEST_STREAM_FILE, 0);
    xipc = xipc_unix_client(XIPC_STREAM, (char *)TEST_STREAM_FILE);
    
    hdr.op = OP_DATA;
    hdr.mtype = MSG_SLEEP;
    retval = xipc_set_data_handler(stream_ipc, &hdr, server_sleep_handler, sizeof(data_s));
    EXPECT_TRUE(retval);
    
    xnet = xnet_open(NULL, NULL);
    EXPECT_TRUE( NULL != xnet);
    
    xnet_add_socket(xnet, xipc_get_fd(stream_ipc), xipc_process_trans, stream_ipc);
    
    EXPECT_TRUE(xnet_start(xnet, NULL, NULL, 0));// non-blocking
    
    hdr.op = OP_DATA;
    hdr.mtype = MSG_SLEEP;
    
    hdr.value = 9999;
    data.seq = 5;
    retval = xipc_client_data(xipc, &hdr, &data, sizeof(data), &status);
    EXPECT_FALSE(retval);
    EXPECT_NE(status, XIPC_NO_ERROR);
    
    xipc_close(xipc);
    xipc_close(stream_ipc);
    
    EXPECT_TRUE(xnet_stop(xnet));
    EXPECT_TRUE(xnet_close(xnet));
}

int main(int argc, char **argv)
{
    xdbg_set_priority(XDBG_INFO);

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}





