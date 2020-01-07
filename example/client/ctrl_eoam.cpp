#include "eoam_if.h"
#include "eoam_mib.h"
#include "getopt.h"
#include "eoam_str.h"

#include "xutl_dbg.h"

xdbg_prio_e g_dbg_pri = XDBG_INFO;

void usage(char **argv)
{
    if (argv) {}

    fprintf(stderr,"Usage:\n");
    fprintf(stderr,"    -i <ifindex>: interface: oam interface\n");
    fprintf(stderr,"    -a [1|2]: enable/disable admin mode\n");
    fprintf(stderr,"    -m [1|2]: active/passive\n");
    fprintf(stderr,"    -l [2|4]: start/stop loopback\n");
    fprintf(stderr,"    -r [1|2]: ignore/process loopback\n");
    fprintf(stderr,"    -s [1|2|3] set link failure/dying gasp/critical\n");
    fprintf(stderr,"    -c [1|2|3] clear link failure/dying gasp/critical\n");
    fprintf(stderr,"    -S [1|2|3|4] set link error event\n");
    fprintf(stderr,"    -e [1|2]: enable/disable link event\n");
    fprintf(stderr,"    -d [1-9] set debug level <XDBG_EMERG...XDBG_DEBUG>\n");
	fprintf(stderr,"    -q quit eoam program\n");
    fprintf(stderr,"    -x: show event log\n");

    return;
}

void show_event_log()
{
	dot3_evt_log_s evt_log;
	uint64_t window, threshold;

	memset(&evt_log, 0, sizeof(evt_log));

	fprintf(stderr,"\ntime     port idx  type loc window thresh value   run-total e-total");
	fprintf(stderr,"\n======== ==== ===  ==== === ====== ====== ======= ========= =========");

	while (eoam_getnext_evt_log(&evt_log) == OAM_NO_ERROR)
	{
		if (evt_log.dot3OamEventLogType > 4)
		{
			fprintf(stderr,"\n%8d %3d  %3d  %3d  %3d NA     NA     NA      NA        %9u",
				evt_log.dot3OamEventLogTimestamp,
				evt_log.ifindex, evt_log.dot3OamEventLogIndex,
				evt_log.dot3OamEventLogType, evt_log.dot3OamEventLogLocation,
				evt_log.dot3OamEventLogEventTotal);
		}
		else
		{
   			window = evt_log.dot3OamEventLogWindowHi;
    		window = (window << 32) | evt_log.dot3OamEventLogWindowLo;

   			threshold = evt_log.dot3OamEventLogThresholdHi;
    		threshold = (threshold << 32) | evt_log.dot3OamEventLogThresholdLo;

			fprintf(stderr,"\n%8d %3d  %3d  %3d  %3d %-6llu %-6llu %-7llu %-9llu %-9u",
				evt_log.dot3OamEventLogTimestamp,
				evt_log.ifindex, evt_log.dot3OamEventLogIndex,
				evt_log.dot3OamEventLogType, evt_log.dot3OamEventLogLocation,
				(long long unsigned int) window, 
				(long long unsigned int)threshold,
				(long long unsigned int)evt_log.dot3OamEventLogValue, 
				(long long unsigned int)evt_log.dot3OamEventLogRunningTotal,
				evt_log.dot3OamEventLogEventTotal);
		}
	}
	fprintf(stderr,"\n");
}

void show_status(uint32_t ifindex)
{
    dot3_oam_cfg_s cfg;
    dot3_oam_stats_s stats;
    dot3_evt_cfg_s evts;
    dot3_lpbk_cfg_s lpbk;
    dot3_peer_s peer;
	uint64_t window, threshold;

    // cfg
    cfg.ifindex = ifindex;
    eoam_get_cfg(&cfg);

    fprintf(stderr, "\nifindex:%d (state = %s)",
            cfg.ifindex, eoam_str_fsm_state((oam_state_e)cfg.oamOperStatus));

    fprintf(stderr, "\n  rev:%d admin:%s, oam-mode:%s max-pdu-size:%d func:0x%02x",
            cfg.oamConfigRevision, eoam_str_onoff(cfg.oamAdminState), 
			eoam_str_oam_mode(cfg.oamMode),
            cfg.oamMaxOamPduSize, cfg.oamFunctionsSupported);

    // peer
    peer.ifindex = ifindex;
    eoam_get_peer(&peer);

    fprintf(stderr, "\n Peer:");

    fprintf(stderr, "\n  mac:%02x:%02x:%02x:%02x:%02x:%02x oam-mode:%s max-pdu-size:%d",
            peer.dot3OamPeerMacAddress[0], peer.dot3OamPeerMacAddress[1],
            peer.dot3OamPeerMacAddress[2],peer.dot3OamPeerMacAddress[3],
            peer.dot3OamPeerMacAddress[4], peer.dot3OamPeerMacAddress[5],
            eoam_str_oam_mode(peer.dot3OamPeerMode), 
			peer.dot3OamPeerMaxOamPduSize);

    fprintf(stderr, "\n  rev:%d oui:%02x:%02x:%02x func:0x%02x",
            peer.dot3OamPeerConfigRevision,
            peer.dot3OamPeerVendorOui[0], peer.dot3OamPeerVendorOui[1],
            peer.dot3OamPeerVendorOui[2],
            peer.dot3OamPeerFunctionsSupported);

    // lpbk
    lpbk.ifindex = ifindex;
    eoam_get_lpbk(&lpbk);

    fprintf(stderr, "\n Loopback:");

    fprintf(stderr, "\n  lpbk-status:%s, ignore-lpbk:%s",
            eoam_str_lpbk_status(lpbk.oamLoopbackStatus), 
			eoam_str_onoff(lpbk.oamLoopbackIgnoreRx));

    stats.ifindex = ifindex;
    eoam_get_stats(&stats);

    fprintf(stderr, "\n  info-pdu:(tx %d: rx %d) lpbk:(tx %d:rx %d)",
            stats.oamInformationTx, stats.oamInformationRx,
            stats.oamLoopbackControlTx, stats.oamLoopbackControlRx);

    evts.ifindex = ifindex;
    eoam_get_evt_cfg(&evts);

    fprintf(stderr, "\n Events:  LF:%s, Dying Gasp:%s, Critical:%s", 
		eoam_str_onoff(evts.dot3OamLinkFaultStatus), 
		eoam_str_onoff(evts.dot3OamDyingGaspStatus), 
		eoam_str_onoff(evts.dot3OamCriticalEventStatus));
    
	window = evts.dot3OamErrSymPeriodWindowHi;
	window = (window << 32 ) | evts.dot3OamErrSymPeriodWindowLo;

	threshold = evts.dot3OamErrSymPeriodThresholdHi;
	threshold = (threshold << 32 ) | evts.dot3OamErrSymPeriodThresholdLo;

    fprintf(stderr, "\n  err-symbols-period evt win:(%llu) threshold:(%llu) enable:%s",
            (long long unsigned int)window,
            (long long unsigned int)threshold,
            eoam_str_onoff(evts.dot3OamErrSymPeriodEvNotifEnable));

    fprintf(stderr, "\n  err-frame--period evt win:(%d) threshold:(%d) enable:%s",
            evts.dot3OamErrFramePeriodWindow,
            evts.dot3OamErrFramePeriodThreshold,
            eoam_str_onoff(evts.dot3OamErrFramePeriodEvNotifEnable));

    fprintf(stderr, "\n  err-frame evt win:(%d) threshold:(%d) enable:%s",
            evts.dot3OamErrFrameWindow,
            evts.dot3OamErrFrameThreshold,
            eoam_str_onoff(evts.dot3OamErrFrameEvNotifEnable));

    fprintf(stderr, "\n  err-summary-sec evt win:(%d) threshold:(%d) enable:%s",
            evts.dot3OamErrFrameSecsSummaryWindow,
            evts.dot3OamErrFrameSecsSummaryThreshold,
            eoam_str_onoff(evts.dot3OamErrFrameSecsEvNotifEnable));

	fprintf(stderr,"\n");
	
	return;
}

BOOLEAN set_oam_cfg(ifindex_s ifindex, int admin, int oam_mode)
{
	dot3_oam_cfg_s cfg;
    oam_err_e status = OAM_NO_ERROR;

	memset(&cfg, 0, sizeof(cfg));

	cfg.ifindex = ifindex;
	status = eoam_get_cfg(&cfg);
	if (status != OAM_NO_ERROR)
	{
		fprintf(stderr, "\nget config failed (%d)", status);
		return FALSE;
	}
	else
	{
		fprintf(stderr, "\noriginal admin %s, mode %s", 
			eoam_str_onoff(cfg.oamAdminState), 
			eoam_str_onoff(cfg.oamMode));
	}

    if (admin)
    {
        cfg.oamAdminState = (oam_admin_e) admin;
    }

	if (oam_mode)
    {
		cfg.oamMode = (oam_mode_e)oam_mode;
    }

	status = eoam_set_cfg(&cfg);
	if (status == OAM_NO_ERROR)
	{
		fprintf(stderr, "\nset config success.");
	}
	else
	{
		fprintf(stderr, "\nset config failed (%d)", status);
		return FALSE;
	}

	return TRUE;
}

BOOLEAN set_lpbk(ifindex_s ifindex, int loopback, int ignore_lpbk)
{
	dot3_lpbk_cfg_s lpbk;
	oam_err_e status = OAM_NO_ERROR;

	memset(&lpbk, 0, sizeof(lpbk));
	lpbk.ifindex = ifindex;

	status = eoam_get_lpbk(&lpbk);
	if ( status != OAM_NO_ERROR)
	{
		fprintf(stderr, "\nget loopback failed (%d)", status);
		return FALSE;
	}

	if (loopback)
	{
		lpbk.oamLoopbackStatus = (oam_lpbk_e) loopback;
	}

	if (ignore_lpbk)
	{
		lpbk.oamLoopbackIgnoreRx = (dot3_rx_lpbk_e) ignore_lpbk;
	}

	status = eoam_set_lpbk(&lpbk);
	if (status == OAM_NO_ERROR)
	{
		fprintf(stderr, "\nset loopback success.");
	}
	else
	{
		fprintf(stderr, "\nset loopback failed (%d)", status);
		return FALSE;
	}

	return TRUE;
}

BOOLEAN set_link_evt_cfg(ifindex_s ifindex, int enable_levt_cfg)
{
	dot3_evt_cfg_s evt_cfg;
    oam_err_e status = OAM_NO_ERROR;

	if (enable_levt_cfg == 1)
	{
		evt_cfg.ifindex = ifindex;
		evt_cfg.dot3OamErrSymPeriodWindowHi = 10000;
		evt_cfg.dot3OamErrSymPeriodWindowLo = 100;
		evt_cfg.dot3OamErrSymPeriodThresholdHi = 10000;
		evt_cfg.dot3OamErrSymPeriodThresholdLo = 100;
		evt_cfg.dot3OamErrSymPeriodEvNotifEnable = MIB_TRUE;


		evt_cfg.dot3OamErrFramePeriodEvNotifEnable = MIB_TRUE;
		evt_cfg.dot3OamErrFrameEvNotifEnable = MIB_TRUE;
		evt_cfg.dot3OamErrFrameSecsEvNotifEnable = MIB_TRUE;

		evt_cfg.dot3OamDyingGaspEnable = MIB_TRUE;
		evt_cfg.dot3OamCriticalEventEnable = MIB_TRUE;

		if ((status=eoam_set_evt_cfg(&evt_cfg)) == OAM_NO_ERROR)
		{
			fprintf(stderr, "\nset link event cfg success.");
		}
		else
		{
			fprintf(stderr, "\nset link event cfg failed (%d)", status);
			return FALSE;
		}
	}
	else
	{
		evt_cfg.ifindex = ifindex;
		evt_cfg.dot3OamErrSymPeriodEvNotifEnable = MIB_FALSE;
		evt_cfg.dot3OamErrFramePeriodEvNotifEnable = MIB_FALSE;
		evt_cfg.dot3OamErrFrameEvNotifEnable = MIB_FALSE;
		evt_cfg.dot3OamErrFrameSecsEvNotifEnable = MIB_FALSE;

		evt_cfg.dot3OamDyingGaspEnable = MIB_FALSE;
		evt_cfg.dot3OamCriticalEventEnable = MIB_FALSE;

		if ((status=eoam_set_evt_cfg(&evt_cfg)) == OAM_NO_ERROR)
		{
			fprintf(stderr, "\nclear link event cfg sucess.");
		}
		else
		{
			fprintf(stderr, "\nclear link event cfg failed (%d)", status);
			return FALSE;
		}
	}

	return TRUE;
}

BOOLEAN set_critical_event(ifindex_s ifindex, mib_evt_type_e evt_type, uint32_t value)
{
	eoam_rpt_evt_s rpt;
    oam_err_e status = OAM_NO_ERROR;

	memset(&rpt, 0, sizeof(rpt));
	rpt.ifindex = ifindex;
	rpt.evt_type = evt_type;

	if (value)
	{
		rpt.clear_flag = FALSE;
		rpt.no_logging = FALSE;
	}
	else
	{
		rpt.clear_flag = TRUE;
		rpt.no_logging = TRUE;
	}

	if ((status=eoam_req_report_event(&rpt)) == OAM_NO_ERROR)
	{
		if (rpt.clear_flag)
			fprintf(stderr, "\nclear critical success.");
		else
			fprintf(stderr, "\nset critical success.");
	}
	else
	{
		fprintf(stderr, "\nset/clear critical failed (%d)", status);
		return FALSE;
	}

	return TRUE;
}

BOOLEAN set_link_event(ifindex_s ifindex, mib_evt_type_e evt_type, 
	uint32_t value, uint64_t run_total)
{
	eoam_rpt_evt_s rpt;
    oam_err_e status = OAM_NO_ERROR;

	memset(&rpt, 0, sizeof(rpt));
	rpt.ifindex = ifindex;
	rpt.evt_type = evt_type;
	rpt.value64 = value;
	rpt.total64 = run_total;

	if ((status=eoam_req_report_event(&rpt)) == OAM_NO_ERROR)
	{
		fprintf(stderr, "\nset link event success.");
	}
	else
	{
		fprintf(stderr, "\nset link event failed (%d)", status);
		return FALSE;
	}

	return TRUE;
}

int main(int argc, char *argv[])
{
    int c;
    uint8_t ifindex = DEBUG_IFINDEX;
    int status_flag = 0;
    int mode_flag = 0, admin = 0, oam_mode = 0;
    int lpbk_flag = 0, loopback = 0, ignore_lpbk = 0;
    int enable_levt_cfg = 0;
    int set_cevt_flag = 0, clear_cevt_flag = 0;
    int set_levt_flag = 0;
    xdbg_prio_e debug_priority = XDBG_INVALID;
	int clear_all_flag = 0;
	int quit_flag = 0;
	static uint64_t run_total = 10000;
	uint32_t value ;

    opterr = 0;

    while ((c = getopt(argc, argv, "i:a:m:l:e:d:s:r:c:S:Cxh?q")) != -1)
	{
	    switch (c)
		{
		case 'i':
		    ifindex = atoi(optarg);
		    break;

		case 'a':
		    mode_flag = 1;
		    admin = (oam_admin_e) atoi(optarg);
		    break;

		case 'm':
		    mode_flag = 1;
		    oam_mode = (oam_mode_e) atoi(optarg);
		    break;

		case 'l':
		    lpbk_flag = 1;
		    loopback = atoi(optarg);
		    break;

		case 'r':
			lpbk_flag = 1;
		    ignore_lpbk = atoi(optarg);
		    break;

		case 'e':
		    enable_levt_cfg = atoi(optarg);
		    break;

		case 'd':
		    debug_priority = (xdbg_prio_e)atoi(optarg);
		    break;

		case 's':
		    set_cevt_flag = atoi(optarg) + 255;
		    break;

		case 'c':
		    clear_cevt_flag = atoi(optarg) + 255;
		    break;

		case 'S':
		    set_levt_flag = atoi(optarg);
		    break;

		case 'C': /* clear and show status */
			clear_all_flag = 1;
            status_flag = 1; 
            break;
		case 'x':
		    status_flag = 1;
		    break;

		case 'q':
		    quit_flag = 1;
		    break;
		case 'h':
		case '?':
		default:
		    usage(argv);
		    return -1;
		}
	}

    if (debug_priority)
	{
		eoam_req_debug_priority(debug_priority);
	}

    if (mode_flag)
	{
		set_oam_cfg(ifindex, admin, oam_mode);
	}

    if (lpbk_flag)
	{
		set_lpbk(ifindex, loopback, ignore_lpbk);
	}

	/* enable/disable link event notification */
    if (enable_levt_cfg)
	{
		set_link_evt_cfg(ifindex, enable_levt_cfg);
	}

	/* set/clear critical event */
    if (set_cevt_flag || clear_cevt_flag)
	{
		mib_evt_type_e evt_type;

		evt_type = (mib_evt_type_e) ((set_cevt_flag) ? set_cevt_flag : clear_cevt_flag);
		value = (set_cevt_flag) ? 100 : 0;
		set_critical_event(ifindex, evt_type, value);
	}

	/* set link event */
    if (set_levt_flag)
	{
		value = 200;
		run_total += value;
        set_link_event(ifindex, (mib_evt_type_e) set_levt_flag, value, run_total);
	}

	if (quit_flag)
	{
		eoam_req_quit();	
	}

    if (argc == 1)
	{
		dot3_oam_cfg_s cfg;

		/* test next funciion */
		cfg.ifindex = ifindex;
		eoam_getnext_cfg(&cfg);
		
	    show_status(cfg.ifindex);
	}

    /* clear log and statistics */
	if (clear_all_flag)
	{
		eoam_req_clear_log();
		eoam_req_clear_stats(0); /* 0 for clear all */
	}
		
    /* show port's oam status */
	if (status_flag)
	{
		show_status(ifindex);
		show_event_log();
	}

    fprintf(stderr, "\n\n");

    return 0;
}
