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
#include "eoam_if.h"

#include "gtest/gtest.h"
#include "gmock/gmock.h"

/*
 * globals
 *
 */
static pthread_t g_eoam_tid;
static int g_evt_type[] = {1, 2, 3, 4, 256, 257, 258};
/*
 * local functions
 *
 */

void *cleanup(void *param)
{
    if (param)
    {
    }

    xdbg_log(XDBG_INFO, "??? cleanup xnet ...");
    eoam_fsm_terminate();
    xdbg_log(XDBG_INFO, "??? cleanup xnet - done.");

    return NULL;
}

int start_eoam(void)
{
    eoam_params_s oam_params;
    char oui[] = OAM_PARAM_OUI;
    int rv;

    /* change the file mode mask */
    umask(0);

    memset(&oam_params, 0, sizeof(oam_params));

    strcpy(oam_params.dev_name, xos_eth_dev());
    xos_get_mac(oam_params.dev_name, (char *)oam_params.dev_mac);

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

    rv = pthread_create(&g_eoam_tid, NULL, eoam_fsm_loop, (void *)NULL);
    if (rv != 0)
    {
        perror("pthread_create");
        return -1;
    }

    sleep(2); /* FIXME:quit wait proce quit command */


    return 0;
}

TEST(OAM_ADMIN, ChangeAdminState) // DISABLED_
{
    dot3_oam_cfg_s cfg;
    dot3_oam_stats_s stats;
    
    memset(&cfg, 0, sizeof(cfg));
    cfg.ifindex = DEBUG_IFINDEX;
    
    EXPECT_EQ(eoam_get_cfg(&cfg), 0);
    
    /* set to disable */
    cfg.oamAdminState = OAM_ADMIN_DISABLED;
    EXPECT_EQ(eoam_set_cfg(&cfg), 0);
    EXPECT_EQ(eoam_get_cfg(&cfg), 0);
    EXPECT_EQ(cfg.oamAdminState, OAM_ADMIN_DISABLED);
    
    /* clear stats */
    EXPECT_EQ(eoam_req_clear_stats(DEBUG_IFINDEX), 0);
    
    sleep(2);
    
    stats.ifindex = DEBUG_IFINDEX;
    EXPECT_EQ(eoam_get_stats(&stats), 0);
    EXPECT_EQ(stats.oamInformationTx, (uint32_t)0);
    EXPECT_EQ(stats.oamInformationRx, (uint32_t)0);
    
    /* set to enable */
    cfg.oamAdminState = OAM_ADMIN_ENABLED;
    EXPECT_EQ(eoam_set_cfg(&cfg), 0);
    EXPECT_EQ(eoam_get_cfg(&cfg), 0);
    EXPECT_EQ(cfg.oamAdminState, OAM_ADMIN_ENABLED);
    
    sleep(2);

    EXPECT_EQ(eoam_get_stats(&stats), 0);
    EXPECT_NE(stats.oamInformationTx, (uint32_t)0);
}

/**
 * Change Mode. test switch oam mode and if the oam mode is passive, it does
 * not init discovery process (by checking tx counter)
 * 
 */
TEST(OAM_MODE, ChangeMode)
{
    dot3_oam_cfg_s cfg;
    dot3_oam_stats_s stats;
    
    memset(&cfg, 0, sizeof(cfg));
    cfg.ifindex = DEBUG_IFINDEX;
    
    EXPECT_EQ(eoam_get_cfg(&cfg), 0);
    
    /* change to slave */
    cfg.oamMode = OAM_MODE_PASSIVE;
    EXPECT_EQ(eoam_set_cfg(&cfg), 0);
    EXPECT_EQ(eoam_get_cfg(&cfg), 0);
    EXPECT_EQ(cfg.oamMode, OAM_MODE_PASSIVE);

    /* clear stats */
    EXPECT_EQ(eoam_req_clear_stats(DEBUG_IFINDEX), 0);
    
    sleep(2);
    
    /* check tx counter */
    stats.ifindex = DEBUG_IFINDEX;
    EXPECT_EQ(eoam_get_stats(&stats), 0);
    EXPECT_EQ(stats.oamInformationTx, (uint32_t)0);

    /* change to active */
    cfg.oamMode = OAM_MODE_ACTIVE;
    EXPECT_EQ(eoam_set_cfg(&cfg), 0);
    
    EXPECT_EQ(eoam_get_cfg(&cfg), 0);
    EXPECT_EQ(cfg.oamMode, OAM_MODE_ACTIVE);
}

/**
 * EventMask
 * 
 * if a specific event mask is disabled/enabled, it cannot/can
 * raise relevant event.
 *
 */
TEST(EVENT_MASK, SendNotification)
{
    dot3_evt_cfg_s evtcfg;
    eoam_rpt_evt_s rpt;
    dot3_evt_log_s log;
    uint32_t i;
    mib_truth_e flag;

    for (i=0 ; i < sizeof(g_evt_type)/sizeof(mib_evt_type_e); i++)
    {
        xdbg_log(XDBG_DEBUG, "EVT-CFG test %d (type %d) -----------------",
                 i, g_evt_type[i]);
        
        xdbg_log(XDBG_DEBUG, "EVT-CFG mask disable test %d +++++++++ ", i);
        memset(&evtcfg, 0, sizeof(evtcfg));
        evtcfg.ifindex = DEBUG_IFINDEX;
        EXPECT_EQ(eoam_get_evt_cfg(&evtcfg), 0);
        
        /* disable event mask */
        eoam_set_evt_mask(&evtcfg, (mib_evt_type_e)g_evt_type[i], MIB_FALSE);
        
        /* change mask */
        if (g_evt_type[i] != EVT_LINK_FAULT)
        {
            EXPECT_EQ(eoam_set_evt_cfg(&evtcfg), 0);
        
            /* validate set result */
            EXPECT_EQ(eoam_get_evt_cfg(&evtcfg), 0);
            EXPECT_EQ(eoam_get_evt_mask(&evtcfg, (mib_evt_type_e)g_evt_type[i], &flag), TRUE);
            EXPECT_EQ(flag, MIB_FALSE);
        }
        
        /* clear log */
        eoam_req_clear_log();
        
        /* generate event */
        memset(&rpt, 0, sizeof(rpt));
        rpt.ifindex = DEBUG_IFINDEX;
        rpt.evt_type = (mib_evt_type_e)g_evt_type[i];
        rpt.value64 = 100000;
        rpt.total64 = 7777777777;
        EXPECT_EQ(eoam_req_report_event(&rpt), 0);
        
        /* verify no log generated */
        memset(&log, 0, sizeof(log));
        if (g_evt_type[i] != EVT_LINK_FAULT)
            EXPECT_NE(eoam_getnext_evt_log(&log), 0);
        else
            EXPECT_EQ(eoam_getnext_evt_log(&log), 0);

        memset(&evtcfg, 0, sizeof(evtcfg));
        evtcfg.ifindex = DEBUG_IFINDEX;
        EXPECT_EQ(eoam_get_evt_cfg(&evtcfg), 0);

        /* enable event */
        xdbg_log(XDBG_DEBUG, "EVT-CFG mask enable test %d +++++++++ ", i);
        eoam_set_evt_mask(&evtcfg, (mib_evt_type_e)g_evt_type[i], MIB_TRUE);
        EXPECT_EQ(eoam_set_evt_cfg(&evtcfg), 0);
        EXPECT_EQ(eoam_get_evt_mask(&evtcfg, (mib_evt_type_e)g_evt_type[i], &flag), TRUE);
        EXPECT_EQ(flag, MIB_TRUE);
        
        /* clear log */
        eoam_req_clear_log();
        
        /* generate event */
        memset(&rpt, 0, sizeof(rpt));
        rpt.ifindex = DEBUG_IFINDEX;
        rpt.evt_type = (mib_evt_type_e)g_evt_type[i];
        
        if (g_evt_type[i] == EVT_LINK_FAULT) /* non-maskable, clear previous event */
        {
            rpt.clear_flag = TRUE;
            rpt.no_logging = TRUE;
            EXPECT_EQ(eoam_req_report_event(&rpt), 0);
            rpt.clear_flag = FALSE;
            rpt.no_logging = FALSE;
        }
        
        rpt.value64 = 100000;
        rpt.total64 = 7777777777;
        
        EXPECT_EQ(eoam_req_report_event(&rpt), 0);
        
        /* verify log is generated */
        memset(&log, 0, sizeof(log));
        EXPECT_EQ(eoam_getnext_evt_log(&log), 0);
        EXPECT_EQ(log.dot3OamEventLogType, g_evt_type[i]);
    }
}

/**
 * ClearCriticalEvent
 * 
 * if a specific critical event is raised, disable the relevant mask
 * will clear the critical event. (link failure cannot be cleared by mask)
 *
 */
TEST(CRIRICAL_EVENT, ClearByMask)
{
    dot3_evt_cfg_s evtcfg;
    eoam_rpt_evt_s rpt;
    dot3_evt_log_s log;
    uint32_t i;
    mib_truth_e flag;

    for (i=5 ; i < sizeof(g_evt_type)/sizeof(mib_evt_type_e); i++)
    {
        /* clear log */
        eoam_req_clear_log();

        /* generate event */
        memset(&rpt, 0, sizeof(rpt));
        rpt.ifindex = DEBUG_IFINDEX;
        rpt.evt_type = (mib_evt_type_e)g_evt_type[i];
        EXPECT_EQ(eoam_req_report_event(&rpt), 0);
        
        /* verify log is generated */
        memset(&log, 0, sizeof(log));
        EXPECT_EQ(eoam_getnext_evt_log(&log), 0);
        EXPECT_EQ(log.dot3OamEventLogType, g_evt_type[i]);
        
        /* verify internal event status */
        memset(&evtcfg, 0, sizeof(evtcfg));
        evtcfg.ifindex = DEBUG_IFINDEX;
        EXPECT_EQ(eoam_get_evt_cfg(&evtcfg), 0);
        EXPECT_EQ(eoam_get_cevt_status(&evtcfg, (mib_evt_type_e)g_evt_type[i], &flag), TRUE);
        EXPECT_EQ(flag, MIB_TRUE);
        
        /* disable event mask */
        eoam_set_evt_mask(&evtcfg, (mib_evt_type_e)g_evt_type[i], MIB_FALSE);
        EXPECT_EQ(eoam_set_evt_cfg(&evtcfg), 0);
        
        /* check if the event is cleared */
        EXPECT_EQ(eoam_get_evt_cfg(&evtcfg), 0);
        EXPECT_EQ(eoam_get_cevt_status(&evtcfg, (mib_evt_type_e)g_evt_type[i], &flag), TRUE);
        EXPECT_EQ(flag, MIB_FALSE);

        /* reset event mask to enabled */
        eoam_set_evt_mask(&evtcfg, (mib_evt_type_e)g_evt_type[i], MIB_TRUE);
        EXPECT_EQ(eoam_set_evt_cfg(&evtcfg), 0);
    }
}

/**
 * ClearCriticalEvent
 *
 * if a specific critical event is raised, disable the relevant mask
 * will clear the critical event. (link failure cannot be cleared by mask)
 *
 */
TEST(CRIRICAL_EVENT, ClearByOamAdmin)
{
    dot3_oam_cfg_s cfg;
    dot3_evt_cfg_s evtcfg;
    eoam_rpt_evt_s rpt;
    dot3_evt_log_s log;
    uint32_t i;
    mib_truth_e flag;
    
    for (i=4 ; i < sizeof(g_evt_type)/sizeof(mib_evt_type_e); i++)
    {
        /* clear log */
        eoam_req_clear_log();
        
        /* generate event */
        memset(&rpt, 0, sizeof(rpt));
        rpt.ifindex = DEBUG_IFINDEX;
        rpt.evt_type = (mib_evt_type_e)g_evt_type[i];
        EXPECT_EQ(eoam_req_report_event(&rpt), 0);
        
        /* verify log is generated */
        memset(&log, 0, sizeof(log));
        EXPECT_EQ(eoam_getnext_evt_log(&log), 0);
        EXPECT_EQ(log.dot3OamEventLogType, g_evt_type[i]);
        
        /* verify internal event status */
        memset(&evtcfg, 0, sizeof(evtcfg));
        evtcfg.ifindex = DEBUG_IFINDEX;
        EXPECT_EQ(eoam_get_evt_cfg(&evtcfg), 0);
        EXPECT_EQ(eoam_get_cevt_status(&evtcfg, (mib_evt_type_e)g_evt_type[i], &flag), TRUE);
        EXPECT_EQ(flag, MIB_TRUE);
        
        /* set to oam admin disabled to clear critical event */
        memset(&cfg, 0, sizeof(cfg));
        cfg.ifindex = DEBUG_IFINDEX;
        
        EXPECT_EQ(eoam_get_cfg(&cfg), 0);
        
        /* set oam admin to disable */
        cfg.oamAdminState = OAM_ADMIN_DISABLED;
        EXPECT_EQ(eoam_set_cfg(&cfg), 0);
        EXPECT_EQ(eoam_get_cfg(&cfg), 0);
        EXPECT_EQ(cfg.oamAdminState, OAM_ADMIN_DISABLED);
        
        /* check if the event is cleared */
        EXPECT_EQ(eoam_get_evt_cfg(&evtcfg), 0);
        EXPECT_EQ(eoam_get_cevt_status(&evtcfg, (mib_evt_type_e)g_evt_type[i], &flag), TRUE);
        EXPECT_EQ(flag, MIB_FALSE);

        /* reset oam admin to enable */
        cfg.oamAdminState = OAM_ADMIN_ENABLED;
        EXPECT_EQ(eoam_set_cfg(&cfg), 0);
    }
}

TEST(EVT_THRESHOLD, ErrSymPeriod)
{
    dot3_evt_cfg_s evtcfg;
    eoam_rpt_evt_s rpt;
    dot3_evt_log_s log;
    uint64_t threshold;

    /* clear log */
    eoam_req_clear_log();

    memset(&evtcfg, 0, sizeof(evtcfg));
    evtcfg.ifindex = DEBUG_IFINDEX;
    EXPECT_EQ(eoam_get_evt_cfg(&evtcfg), 0);
    threshold = evtcfg.dot3OamErrSymPeriodThresholdHi;
    threshold = (threshold << 32) | evtcfg.dot3OamErrSymPeriodThresholdLo;
    
    /* generate event */
    memset(&rpt, 0, sizeof(rpt));
    rpt.ifindex = DEBUG_IFINDEX;
    rpt.evt_type = EVT_ERR_SYMBOL_PERIOD;
    /* set value over threshold */
    rpt.value64 = threshold + 1;
    rpt.total64 = 0x0102030405060708;
    EXPECT_EQ(eoam_req_report_event(&rpt), 0);

    /* verify log is generated */
    memset(&log, 0, sizeof(log));
    EXPECT_EQ(eoam_getnext_evt_log(&log), 0);
    EXPECT_EQ(log.dot3OamEventLogType, EVT_ERR_SYMBOL_PERIOD);
    EXPECT_EQ(log.dot3OamEventLogValue, threshold + 1);
    EXPECT_EQ(log.dot3OamEventLogRunningTotal, (uint64_t)0x0102030405060708);

    /* clear log */
    eoam_req_clear_log();

    /* set value under threshold */
    rpt.value64 = threshold - 1;
    rpt.total64 = 0x0102030405060708;
    EXPECT_EQ(eoam_req_report_event(&rpt), 0);

    /* verify no log generated */
    memset(&log, 0, sizeof(log));
    EXPECT_NE(eoam_getnext_evt_log(&log), 0);
}

TEST(EVT_THRESHOLD, ErrFramePeriod)
{
    dot3_evt_cfg_s evtcfg;
    eoam_rpt_evt_s rpt;
    dot3_evt_log_s log;
    uint32_t threshold;

    /* clear log */
    eoam_req_clear_log();

    memset(&evtcfg, 0, sizeof(evtcfg));
    evtcfg.ifindex = DEBUG_IFINDEX;
    EXPECT_EQ(eoam_get_evt_cfg(&evtcfg), 0);
    threshold = evtcfg.dot3OamErrFramePeriodThreshold;
    
    /* generate event */
    memset(&rpt, 0, sizeof(rpt));
    rpt.ifindex = DEBUG_IFINDEX;
    rpt.evt_type = EVT_ERR_FRAME_PERIOD;
    /* set value over threshold */
    rpt.value64 = threshold + 1;
    rpt.total64 = 0x0102030405060708;
    EXPECT_EQ(eoam_req_report_event(&rpt), 0);

    /* verify log is generated */
    memset(&log, 0, sizeof(log));
    EXPECT_EQ(eoam_getnext_evt_log(&log), 0);
    EXPECT_EQ(log.dot3OamEventLogType, EVT_ERR_FRAME_PERIOD);
    EXPECT_EQ(log.dot3OamEventLogValue, threshold + 1);
    EXPECT_EQ(log.dot3OamEventLogRunningTotal, 0x0102030405060708ull); // C++11

    /* clear log */
    eoam_req_clear_log();

    /* set value under threshold */
    rpt.value64 = threshold - 1;
    rpt.total64 = 0x0102030405060708;
    EXPECT_EQ(eoam_req_report_event(&rpt), 0);

    /* verify no log generated */
    memset(&log, 0, sizeof(log));
    EXPECT_NE(eoam_getnext_evt_log(&log), 0);
}

TEST(EVT_THRESHOLD, ErrFrame)
{
    dot3_evt_cfg_s evtcfg;
    eoam_rpt_evt_s rpt;
    dot3_evt_log_s log;
    uint32_t threshold;

    /* clear log */
    eoam_req_clear_log();

    memset(&evtcfg, 0, sizeof(evtcfg));
    evtcfg.ifindex = DEBUG_IFINDEX;
    EXPECT_EQ(eoam_get_evt_cfg(&evtcfg), 0);
    threshold = evtcfg.dot3OamErrFrameThreshold;
    
    /* generate event */
    memset(&rpt, 0, sizeof(rpt));
    rpt.ifindex = DEBUG_IFINDEX;
    rpt.evt_type = EVT_ERR_FRAME_EVENT;
    /* set value over threshold */
    rpt.value64 = threshold + 1;
    rpt.total64 = 0x0102030405060708;
    EXPECT_EQ(eoam_req_report_event(&rpt), 0);

    /* verify log is generated */
    memset(&log, 0, sizeof(log));
    EXPECT_EQ(eoam_getnext_evt_log(&log), 0);
    EXPECT_EQ(log.dot3OamEventLogType, EVT_ERR_FRAME_EVENT);
    EXPECT_EQ(log.dot3OamEventLogValue, threshold + 1);
    EXPECT_EQ(log.dot3OamEventLogRunningTotal, 0x0102030405060708ull); // C++11
    /* clear log */
    eoam_req_clear_log();

    /* set value under threshold */
    rpt.value64 = threshold - 1;
    rpt.total64 = 0x0102030405060708;
    EXPECT_EQ(eoam_req_report_event(&rpt), 0);

    /* verify no log generated */
    memset(&log, 0, sizeof(log));
    EXPECT_NE(eoam_getnext_evt_log(&log), 0);
}

TEST(EVT_THRESHOLD, ErrFrameSecsSummary)
{
    dot3_evt_cfg_s evtcfg;
    eoam_rpt_evt_s rpt;
    dot3_evt_log_s log;
    uint32_t threshold;

    /* clear log */
    eoam_req_clear_log();

    memset(&evtcfg, 0, sizeof(evtcfg));
    evtcfg.ifindex = DEBUG_IFINDEX;
    EXPECT_EQ(eoam_get_evt_cfg(&evtcfg), 0);
    threshold = evtcfg.dot3OamErrFrameSecsSummaryThreshold;
    
    /* generate event */
    memset(&rpt, 0, sizeof(rpt));
    rpt.ifindex = DEBUG_IFINDEX;
    rpt.evt_type = EVT_ERR_FRAME_SEC_EVENT;
    /* set value over threshold */
    rpt.value64 = threshold + 1;
    rpt.total64 = 0x0102030405060708; 
    EXPECT_EQ(eoam_req_report_event(&rpt), 0);

    /* verify log is generated */
    memset(&log, 0, sizeof(log));
    EXPECT_EQ(eoam_getnext_evt_log(&log), 0);
    EXPECT_EQ(log.dot3OamEventLogType, EVT_ERR_FRAME_SEC_EVENT);
    EXPECT_EQ(log.dot3OamEventLogValue, threshold + 1);
    EXPECT_EQ(log.dot3OamEventLogRunningTotal, 0x0102030405060708ull); // C++11

    /* clear log */
    eoam_req_clear_log();

    /* set value under threshold */
    rpt.value64 = threshold - 1;
    EXPECT_EQ(eoam_req_report_event(&rpt), 0);

    /* verify no log generated */
    memset(&log, 0, sizeof(log));
    EXPECT_NE(eoam_getnext_evt_log(&log), 0);
}

TEST(EVT_LOG, WrapAround)
{
}

TEST(EVT_PEER, PeerEventCappability)
{
}



int main(int argc, char *argv[])
{
    int retval ;

    xdbg_set_priority(XDBG_ERR);

    /* start eoam */
    start_eoam();

    sleep(5);
    
    ::testing::InitGoogleTest(&argc, argv);

    retval = RUN_ALL_TESTS();

    /* stop eoam */
    eoam_req_quit();

    fprintf(stderr, "\neoam main program exit.\n");

    return retval;

}



