#include <iostream>
#include <chrono>
#include <thread>
#include <assert.h>
#include <signal.h>

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "xutl_net.h"
#include "xutl_ipc.h"


#define STREAM_SOCK_FILE    "/tmp/test_ipc.stream.sock"
#define DGRAM_SOCK_FILE     "/tmp/test_ipc.dgram.sock"

// op
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
    MSG_TOUT,
    MSG_MAX
} msg_e;

#pragma pack(1)

typedef struct
{
    uint8_t pad[4];
    int seq;
} data_s;

#pragma pack()


//
// globals
//

// client
pthread_t g_client_tid;

// server
static xnet_s *g_xnet;
xipc_s *g_stream_ipc;
xipc_s *g_dgram_ipc;


void usr_init(void *xnet, void *param)
{
    if (xnet) {}
    if (param) {}
    
    xdbg_log(XDBG_DEBUG, "init timer, start recurrsing timer");
    
    return ;
}

xipc_status_s server_exec_handler(uint32_t action)
{
    xipc_status_s status = XIPC_NO_ERROR;
    
    xdbg_log(XDBG_INFO, "server_log_handler: value = %dr", action);

    return status ;
}

xipc_status_s server_put_handler(void *data)
{
    char *p = (char *)data;
    data_s *cfg = (data_s *)data;
    xipc_status_s status = XIPC_NO_ERROR;
    
    if (cfg) {}
    if (p) {}
    
    cfg->seq = cfg->seq + 1;
    
    return status ;
}

xipc_status_s server_get_handler(void *data)
{
    char *p = (char *)data;
    data_s *cfg = (data_s *)data;
    xipc_status_s status = XIPC_NO_ERROR;
    
    if (cfg) {}
    if (p) {}
    
    /* no data in, just assign a value */
    cfg->seq = 7777;
    
    return status ;
}

xipc_status_s server_data_handler(void *data)
{
    char *p = (char *)data;
    data_s *cfg = (data_s *)data;
    xipc_status_s status = XIPC_NO_ERROR;
    
    if (cfg) {}
    if (p) {}
    
    cfg->seq = cfg->seq + 1;
    
    return status ;
}

xipc_status_s server_tout_handler(void *data)
{
    char *p = (char *)data;
    data_s *cfg = (data_s *)data;
    xipc_status_s status = XIPC_NO_ERROR;
    
    if (cfg) {}
    if (p) {}
    
    sleep(2);
    //std::this_thread::sleep_for(std::chrono::seconds(2));
    //std::chrono::seconds(10);
    
    return status ;
}



TEST(DGRAM_EXEC, Normal)
{
    xipc_s *xipc ;
    xipc_hdr_s hdr;
    xipc_status_s status = 999;
    BOOLEAN retval = TRUE;
    
    xipc = xipc_unix_client(XIPC_DGRAM, (char *)DGRAM_SOCK_FILE);
    
    hdr.op = OP_EXEC;
    hdr.mtype = MSG_ACTION;

    hdr.value = 7777;
    retval = xipc_client_exec(xipc, &hdr, &status);
    EXPECT_TRUE(retval);
    EXPECT_EQ(status, XIPC_NO_ERROR);

    hdr.value = 9999;
    retval = xipc_client_exec(xipc, &hdr, &status);
    EXPECT_TRUE(retval);
    EXPECT_EQ(status, XIPC_NO_ERROR);
    
    xipc_close(xipc);
}

TEST(STREAM_EXEC, Normal)
{
    xipc_s *xipc;
    xipc_hdr_s hdr;
    xipc_status_s status = 999;
    BOOLEAN retval = TRUE;
    
    xipc = xipc_unix_client(XIPC_STREAM, (char *)STREAM_SOCK_FILE);
    
    hdr.op = OP_EXEC;
    hdr.mtype = MSG_ACTION;

    hdr.value = 7777;
    retval = xipc_client_exec(xipc, &hdr, &status);
    EXPECT_TRUE(retval);
    EXPECT_EQ(status, XIPC_NO_ERROR);

    hdr.value = 9999;
    retval = xipc_client_exec(xipc, &hdr, &status);
    EXPECT_TRUE(retval);
    EXPECT_EQ(status, XIPC_NO_ERROR);
    
    xipc_close(xipc);
}

TEST(STREAM_GET, Normal)
{
    xipc_hdr_s hdr;
    xipc_status_s status = 999;
    BOOLEAN retval = TRUE;
    data_s data;
    xipc_s *xipc;
    
    memset(&data, 0, sizeof(data));
    
    xipc = xipc_unix_client(XIPC_STREAM, (char *)STREAM_SOCK_FILE);
    
    hdr.op = OP_GET;
    hdr.mtype = MSG_CFG;
    
    hdr.value = 9999;
    data.seq = 1111;
    retval = xipc_client_get(xipc, &hdr, &data, sizeof(data), &status);
    EXPECT_TRUE(retval);
    EXPECT_EQ(status, XIPC_NO_ERROR);
    EXPECT_EQ(data.seq , 7777); /* for get, data is not passed to server */
    
    data.seq = 2222;
    retval = xipc_client_get(xipc, &hdr, &data, sizeof(data), &status);
    EXPECT_TRUE(retval);
    EXPECT_EQ(status, XIPC_NO_ERROR);
    EXPECT_EQ(data.seq , 7777); /* for get, data is not passed to server */
    
    xipc_close(xipc);
}

TEST(DGRAM_PUT, Normal)
{
    xipc_hdr_s hdr;
    xipc_status_s status = 999;
    BOOLEAN retval = TRUE;
    data_s data;
    xipc_s *xipc;
    
    memset(&data, 0, sizeof(data));
    
    xipc = xipc_unix_client(XIPC_DGRAM, (char *)DGRAM_SOCK_FILE);
    
    hdr.op = OP_PUT;
    hdr.mtype = MSG_CFG;
    hdr.value = 9999;
    
    data.seq = 1111;
    retval = xipc_client_put(xipc, &hdr, &data, sizeof(data), &status);
    EXPECT_TRUE(retval);
    EXPECT_EQ(status, XIPC_NO_ERROR);
    
    data.seq = 2222;
    retval = xipc_client_put(xipc, &hdr, &data, sizeof(data), &status);
    EXPECT_TRUE(retval);
    EXPECT_EQ(status, XIPC_NO_ERROR);
    
    xipc_close(xipc);
}

TEST(STREAM_PUT, Normal)
{
    xipc_hdr_s hdr;
    xipc_status_s status = 999;
    BOOLEAN retval = TRUE;
    data_s data;
    xipc_s *xipc;
    
    memset(&data, 0, sizeof(data));
    
    xipc = xipc_unix_client(XIPC_STREAM, (char *)STREAM_SOCK_FILE);
    
    hdr.op = OP_PUT;
    hdr.mtype = MSG_CFG;
    hdr.value = 9999;
    
    data.seq = 1111;
    retval = xipc_client_put(xipc, &hdr, &data, sizeof(data), &status);
    EXPECT_TRUE(retval);
    EXPECT_EQ(status, XIPC_NO_ERROR);
    
    data.seq = 2222;
    retval = xipc_client_put(xipc, &hdr, &data, sizeof(data), &status);
    EXPECT_TRUE(retval);
    EXPECT_EQ(status, XIPC_NO_ERROR);
    
    xipc_close(xipc);
}

TEST(STREAM_DATA, NormalTwo)
{
    xipc_hdr_s hdr;
    xipc_status_s status = 999;
    BOOLEAN retval = TRUE;
    data_s data;
    xipc_s *xipc;
    
    memset(&data, 0, sizeof(data));
    
    xipc = xipc_unix_client(XIPC_STREAM, (char *)STREAM_SOCK_FILE);

    hdr.op = OP_DATA;
    hdr.mtype = MSG_CFG;
    
    hdr.value = 9999;
    data.seq = 1111;
    retval = xipc_client_data(xipc, &hdr, &data, sizeof(data), &status);
    EXPECT_TRUE(retval);
    EXPECT_EQ(status, XIPC_NO_ERROR);

    data.seq = 2222;
    retval = xipc_client_data(xipc, &hdr, &data, sizeof(data), &status);
    EXPECT_TRUE(retval);
    EXPECT_EQ(status, XIPC_NO_ERROR);

    xipc_close(xipc);
}

char temp_data[2000] = {0};

TEST(STREAM_DATA, MoreData)
{
    xipc_s *xipc;
    xipc_hdr_s hdr;
    xipc_status_s status = 999;
    BOOLEAN retval = TRUE;
    
    xipc = xipc_unix_client(XIPC_STREAM, (char *)STREAM_SOCK_FILE);
    
    hdr.op = OP_DATA;
    hdr.mtype = MSG_CFG;
    hdr.value = 9999;
    
    retval = xipc_client_data(xipc, &hdr, temp_data, sizeof(temp_data), &status);
    EXPECT_FALSE(retval);
    EXPECT_NE(status, XIPC_NO_ERROR);
    
    xipc_close(xipc);
}

TEST(STREAM_DATA, LessData)
{
    xipc_s *xipc;
    xipc_hdr_s hdr;
    xipc_status_s status = 999;
    BOOLEAN retval = TRUE;
    data_s data;
    
    xipc = xipc_unix_client(XIPC_STREAM, (char *)STREAM_SOCK_FILE);
    
    memset(&data, 0, sizeof(data));

    hdr.op = OP_DATA;
    hdr.mtype = MSG_CFG;
    hdr.value = 9999;
    
    retval = xipc_client_data(xipc, &hdr, &data, sizeof(data)-1, &status);
    EXPECT_FALSE(retval);
    EXPECT_NE(status, XIPC_NO_ERROR);
    
    xipc_close(xipc);
}

TEST(STREAM_DATA, ServerSlowResponse)
{
    xipc_s *xipc;
    xipc_hdr_s hdr;
    xipc_status_s status = 999;
    BOOLEAN retval = TRUE;
    data_s data;
    
    xipc = xipc_unix_client(XIPC_STREAM, (char *)STREAM_SOCK_FILE);
    
    memset(&data, 0, sizeof(data));
    
    hdr.op = OP_DATA;
    hdr.mtype = MSG_TOUT;
    hdr.value = 9999;
    
    retval = xipc_client_data(xipc, &hdr, &data, sizeof(data), &status);
    EXPECT_FALSE(retval);
    EXPECT_NE(status, XIPC_NO_ERROR);
    
    xipc_close(xipc);
}

TEST(STREAM_DATA, WrongOp)
{
    xipc_s *xipc;
    xipc_hdr_s hdr;
    xipc_status_s status = 999;
    BOOLEAN retval = TRUE;
    data_s data;
    
    xipc = xipc_unix_client(XIPC_STREAM, (char *)STREAM_SOCK_FILE);
    
    memset(&data, 0, sizeof(data));
    
    hdr.op = OP_MAX;
    hdr.mtype = MSG_MAX;
    hdr.value = 9999;
    
    retval = xipc_client_data(xipc, &hdr, &data, sizeof(data), &status);
    EXPECT_FALSE(retval);
    EXPECT_NE(status, XIPC_NO_ERROR);
    
    xipc_close(xipc);
}

TEST(STREAM_DATA, InactiveConnection)
{
}

void register_xipc_handler()
{
    xipc_hdr_s hdr;
    BOOLEAN retval;

    hdr.op = OP_EXEC;
    hdr.mtype = MSG_ACTION;
    retval = xipc_set_exec_handler(g_dgram_ipc, &hdr, server_exec_handler);
    assert(retval);

    hdr.op = OP_EXEC;
    hdr.mtype = MSG_ACTION;
    retval = xipc_set_exec_handler(g_stream_ipc, &hdr, server_exec_handler);
    assert(retval);

    hdr.op = OP_PUT;
    hdr.mtype = MSG_CFG;
    retval = xipc_set_data_handler(g_dgram_ipc, &hdr, server_put_handler, sizeof(data_s));
    assert(retval);

    hdr.op = OP_PUT;
    hdr.mtype = MSG_CFG;
    retval = xipc_set_data_handler(g_stream_ipc, &hdr, server_put_handler, sizeof(data_s));
    assert(retval);

    hdr.op = OP_GET;
    hdr.mtype = MSG_CFG;
    retval = xipc_set_data_handler(g_stream_ipc, &hdr, server_get_handler, 0);
    assert(retval);

    hdr.op = OP_DATA;
    hdr.mtype = MSG_CFG;
    retval = xipc_set_data_handler(g_stream_ipc, &hdr, server_data_handler, sizeof(data_s));
    assert(retval);

    hdr.op = OP_DATA;
    hdr.mtype = MSG_TOUT;
    retval = xipc_set_data_handler(g_stream_ipc, &hdr, server_tout_handler, sizeof(data_s));
    assert(retval);

}

void start_server()
{
    g_xnet = xnet_open(usr_init, NULL);

    // open server
    g_dgram_ipc = xipc_unix_server(XIPC_DGRAM, (char *)DGRAM_SOCK_FILE, 0);
    g_stream_ipc = xipc_unix_server(XIPC_STREAM, (char *)STREAM_SOCK_FILE, 0);

    xnet_add_socket(g_xnet, xipc_get_fd(g_dgram_ipc), xipc_process_trans, g_dgram_ipc);
    xnet_add_socket(g_xnet, xipc_get_fd(g_stream_ipc), xipc_process_trans, g_stream_ipc);
    
    register_xipc_handler();
    
    xnet_start(g_xnet, NULL, NULL, 0);
}

int main(int argc, char **argv)
{
    int retval ;

    signal(SIGPIPE, SIG_IGN); // prevent got signal on send to a closing socket
    
    xdbg_set_priority(XDBG_ERR);

    start_server();

    ::testing::InitGoogleTest(&argc, argv);
    retval = RUN_ALL_TESTS();

    //sleep(5);
    //std::chrono::seconds(5);
    
    xnet_stop(g_xnet);
    xnet_close(g_xnet);

    xipc_close(g_dgram_ipc);
    xipc_close(g_stream_ipc);

    return retval ;
}





