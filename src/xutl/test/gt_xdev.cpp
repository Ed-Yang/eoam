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

#include "gtest/gtest.h"
#include "gmock/gmock.h"


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

TEST(XDEV, OpenClose)
{
    xdev_s *xdev ;
    char *filter = NULL;
    
    xdev = xdev_open((char *)XDEV_DEFAULT_DEV, NULL, TRUE, filter);
    EXPECT_TRUE( NULL != xdev);
    EXPECT_TRUE(xdev_close(xdev));
}

TEST(XDEV, OpenStartStopClose)
{
    xdev_s *xdev ;
    char *filter = NULL;
    
    xdbg_log(XDBG_INFO, "thread 0x%08x running ...", pthread_self());
    
    xdev = xdev_open((char *)XDEV_DEFAULT_DEV, NULL, TRUE, filter);
    EXPECT_TRUE( NULL != xdev);
    
    EXPECT_TRUE(xdev_start(xdev, rx_ok_cb));
    EXPECT_TRUE(xdev_stop(xdev));
    EXPECT_TRUE(xdev_close(xdev));
}

TEST(XDEV, WaitRx)
{
    xdev_s *xdev ;
    char *filter = NULL;
    
    xdev = xdev_open((char *)XDEV_DEFAULT_DEV, NULL, TRUE, filter);
    EXPECT_TRUE( NULL != xdev);

    EXPECT_TRUE(xdev_start(xdev, rx_ok_cb));

    sleep(5);
    
    EXPECT_TRUE(xdev_stop(xdev));
    EXPECT_TRUE(xdev_close(xdev));
}

                
int main(int argc, char **argv)
{
    xdbg_set_priority(XDBG_DEBUG);

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}




