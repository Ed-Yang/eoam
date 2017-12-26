#include <stdio.h>
#include <stdint.h>

#include "oam_defs.h"

#ifndef __EOAM_MIB_H
#define __EOAM_MIB_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Bit definition of OAM service capability
 *
 */
typedef enum
{
    UNIDIRETIONAL_SUPPORT = 0,
    LOOPBACK_SUPPORT,
    EVENT_SUPPORT,
    VARIABLE_SUPPORT
} dot3_oam_func_e;

/**
 * @brief
 *
 * @param oamConfigRevision 
 *      the revision of local tlv.
 *      IEEE 57.5.2.1 This two-octet field indicates the current revision of 
 *      the Information TLV. The value of this field shall start at zero and 
 *      be incremented each time something in the Information TLV changes.
 * 
 * @param oamFunctionsSupported read-only
 */
typedef struct
{
    uint32_t ifindex;
    oam_admin_e oamAdminState;
    oam_oper_e oamOperStatus; /* FIXME:mib */
    oam_mode_e oamMode;
    uint32_t oamMaxOamPduSize; /* readonly */
    uint16_t oamConfigRevision;  /* readonly */
    uint8_t oamFunctionsSupported;  /* readonly (BITS) FIXME:func */

    /* extensions */
    int oam_timeout; /* in ms, 2 to 30 seconds; the default is 5 seconds */
    uint8_t mac_adrs[MAC_ADRS_SIZE];
} dot3_oam_cfg_s;

/**
 *  dot3_peer_s
 *
 *  @dot3OamPeerVendorOui from peer's local tlv (3 bytes)
 *  @dot3OamPeerVendorInfo from peer's local tlv
 *  @dot3OamPeerFunctionsSupported
 *  @param dot3OamPeerConfigRevision the revision of remote tlv
 *
 * Peer information is not available when dot3OamOperStatus is disabled(1),
 * linkFault(2), passiveWait(3), activeSendLocal(4), or nonOperHalfDuplex(10).
 *
 */
typedef struct
{
    uint32_t ifindex;
    uint8_t dot3OamPeerMacAddress[MAC_ADRS_SIZE];
    uint8_t dot3OamPeerVendorOui[3]; /* from tlv oui field, not from mac */
    uint32_t dot3OamPeerVendorInfo;   /* FIXME:vendor */
    oam_mode_e dot3OamPeerMode;
    uint32_t dot3OamPeerMaxOamPduSize;
    uint16_t dot3OamPeerConfigRevision;
    uint8_t dot3OamPeerFunctionsSupported;  /* FIXME:func */
}  dot3_peer_s;

typedef enum
{
    IGNORED_LPBK = 1,
    PROCESS_LPBK,
} dot3_rx_lpbk_e;

/**
 * @param oamLoopbackStatus (RFC)
 *  The values initiatingLoopback(2) and terminatingLoopback(4)
 *  can be read or written. (just ignore other value, not error)
 *
 *  initiatingLoopback: This value can only be written when the status is noLoopback(1).
 *  When in remoteLoopback(3), writing terminatingLoopback(4) causes the local OAM
 *  entity to initiate the termination of the loopback state.
 * (values allowed for written: INIT_LOOPBACK, TERM_LOOPBACK)
 * @param timeout for lpbk operation in ms.  Its range is 1000ms ~ 10000ms.
 *
 * @comment This setting will only in effect while lpbk bit of dot3OamFunctionsSupported is set.
 */
typedef struct
{
    uint32_t ifindex;
    oam_lpbk_e oamLoopbackStatus;
    dot3_rx_lpbk_e oamLoopbackIgnoreRx;

    /* extension */
    uint32_t lpbk_timeout; /* ms */
    oam_err_e err_code;
} dot3_lpbk_cfg_s;

/**
 *  dot3_oam_stats_s
 *
 *
 */
typedef struct
{
    uint32_t ifindex;
    uint32_t oamInformationTx;   /* YES */
    uint32_t oamInformationRx;   /* YES */
    uint32_t oamUniqueEventNotificationTx;   /* Yes */
    uint32_t oamUniqueEventNotificationRx;   /* Yes */
    uint32_t oamDuplicateEventNotificationTx;  /* Yes */
    uint32_t oamDuplicateEventNotificationRx;  /* Yes */
    uint32_t oamLoopbackControlTx;      /* Yes */
    uint32_t oamLoopbackControlRx;      /* Yes */

    uint32_t oamVariableRequestTx;      /* Feature */
    uint32_t oamVariableRequestRx;      /* Feature */
    uint32_t oamVariableResponseTx;     /* Feature */
    uint32_t oamVariableResponseRx;     /* Feature */
    uint32_t oamOrgSpecificTx;          /* NA */
    uint32_t oamOrgSpecificRx;          /* NA */
    uint32_t oamUnsupportedCodesTx;     /* YES, should be always 0, or .... */
    uint32_t oamUnsupportedCodesRx;     /* YES */
    uint32_t oamFramesLostDueToOam;     /* TBC */
} dot3_oam_stats_s;

/**
 *  dot3_evt_cfg_s
 *  @param dot3OamXXXEvNotifEnable
 *      If true, the OAM entity should send an Event Notification OAMPDU when 
 *      an XXX Event occurs.
 *  @comment 
 *      This setting will only in effect while lpbk bit of 
 *      dot3OamFunctionsSupported is set.
 */
typedef struct
{
    uint32_t ifindex;

    /* error symbol period */
    uint32_t dot3OamErrSymPeriodWindowHi;
    uint32_t dot3OamErrSymPeriodWindowLo;
    uint32_t dot3OamErrSymPeriodThresholdHi;
    uint32_t dot3OamErrSymPeriodThresholdLo;
    mib_truth_e dot3OamErrSymPeriodEvNotifEnable;

    /* error frame period */
    uint32_t dot3OamErrFramePeriodWindow;
    uint32_t dot3OamErrFramePeriodThreshold;
    mib_truth_e dot3OamErrFramePeriodEvNotifEnable;

    /* error frame event */
    uint32_t dot3OamErrFrameWindow;
    uint32_t dot3OamErrFrameThreshold;
    mib_truth_e dot3OamErrFrameEvNotifEnable;

    /* error frame summary */
    uint32_t dot3OamErrFrameSecsSummaryWindow;
    uint32_t dot3OamErrFrameSecsSummaryThreshold;
    mib_truth_e dot3OamErrFrameSecsEvNotifEnable;

    /* critical events */
    mib_truth_e dot3OamDyingGaspEnable;
    mib_truth_e dot3OamCriticalEventEnable;

    /* extensions */
    mib_truth_e dot3OamLinkFaultStatus;
    mib_truth_e dot3OamDyingGaspStatus;
    mib_truth_e dot3OamCriticalEventStatus;

} dot3_evt_cfg_s;

typedef enum
{
    EVT_ERR_SYMBOL_PERIOD = 1,
    EVT_ERR_FRAME_PERIOD = 2,
    EVT_ERR_FRAME_EVENT = 3,
    EVT_ERR_FRAME_SEC_EVENT = 4,
    EVT_LINK_FAULT = 256,
    EVT_DYING_GASP = 257,
    EVT_CRITICAL = 258
} mib_evt_type_e;

typedef enum
{
    EVT_LOCAL = 1,
    EVT_REMOTE
} mib_location_e;

/**
 * @brief dot3_evt_log
 * 
 * @param dot3OamEventLogTimestamp
 *      For locally generated events, the time of the event can be accurately 
 *      retrieved from sysUpTime.  For remotely generated events, the time of 
 *      the  event is indicated by the reception of the Event Notification 
 *      OAMPDU indicating that the event occurred on the peer.
 *      ... may use the timestamp in event pdu
 * @param dot3OamEventLogValue
 *      If the event represents a threshold crossing event, this value indicates 
 *      the value of the parameter within the given window that generated this 
 *      event (for example, 11, when 11 occurrences happened in 5 seconds while 
 *      the threshold was 10).
 * @param dot3OamEventLogEventTotal
 *      Each Event Notification TLV contains a running total of thenumber of 
 *      times an event has occurred, as well as the number of times an Event 
 *      Notification for the event has been transmitted. 
 * @comment
 *      In RFC, it seems only log over threshold events.  For remote event log,
 *      the dot3OamEventLogRunningTotal and dot3OamEventLogEventTotal is not
 *      defined.
 */
typedef struct dot3_evt_log
{
    uint32_t ifindex; /* INDEX 1 */
    uint32_t dot3OamEventLogIndex;  /* INDEX 2 */
    oam_timestamp_s dot3OamEventLogTimestamp;
    uint8_t dot3OamEventLogOui[3]; /* EightOTwoOui (0x0180C2) */
    mib_evt_type_e dot3OamEventLogType;
    mib_location_e dot3OamEventLogLocation;
    uint32_t dot3OamEventLogWindowHi;
    uint32_t dot3OamEventLogWindowLo;
    uint32_t dot3OamEventLogThresholdHi;
    uint32_t dot3OamEventLogThresholdLo;
    oam_gauge64_s dot3OamEventLogValue;
    oam_gauge64_s dot3OamEventLogRunningTotal;    /* FIXME:log */
    uint32_t dot3OamEventLogEventTotal;   /* FIXME:log */

    /* internals */
    BOOLEAN clear_flag;
    struct dot3_evt_log *next, *prev; /* uthash */

} dot3_evt_log_s;

/*
 * OAM Config
 */ 

/**
 * @brief set OAM port configuration
 *
 * @param p_cfg Dot3OamEntry
 * @return oam_err_e
 */
oam_err_e eoam_set_cfg(dot3_oam_cfg_s *p_cfg);

/**
 * @brief Get OAM port configuration
 *
 * @param p_cfg Dot3OamEntry
 * @return oam_err_e
 */
oam_err_e eoam_get_cfg(dot3_oam_cfg_s *p_cfg);

/**
 * @brief Get next OAM port configuration
 *
 * @param p_cfg Dot3OamEntry
 * @return oam_err_e
 *
 * It will return the port configuration with index p_cfg->ifindex + 1
 *
 */
oam_err_e eoam_getnext_cfg(dot3_oam_cfg_s *p_cfg);


/*
 * Peer
 */ 
oam_err_e eoam_get_peer(dot3_peer_s *p_peer);
oam_err_e eoam_getnext_peer(dot3_peer_s *p_peer);

/*
 * loopback
 */ 

oam_err_e eoam_set_lpbk(dot3_lpbk_cfg_s *p_lpbk);
oam_err_e eoam_get_lpbk(dot3_lpbk_cfg_s *p_lpbk);
oam_err_e eoam_getnext_lpbk(dot3_lpbk_cfg_s *p_lpbk);

/*
 * Event Config
 */ 
oam_err_e eoam_set_evt_cfg(dot3_evt_cfg_s *p_evtcfg);
oam_err_e eoam_get_evt_cfg(dot3_evt_cfg_s *p_evtcfg);
oam_err_e eoam_getnext_evt_cfg(dot3_evt_cfg_s *p_evtcfg);

BOOLEAN eoam_set_evt_mask(dot3_evt_cfg_s *p_evtcfg, mib_evt_type_e evt_type, 
    mib_truth_e flag);

BOOLEAN eoam_get_evt_mask(dot3_evt_cfg_s *p_evtcfg, mib_evt_type_e evt_type, 
    mib_truth_e *p_flag);

BOOLEAN eoam_get_cevt_status(dot3_evt_cfg_s *p_evtcfg, mib_evt_type_e evt_type,
                          mib_truth_e *p_flag);
/*
 * Event stats
 */ 

oam_err_e eoam_get_stats(dot3_oam_stats_s *p_stats);
oam_err_e eoam_getnext_stats(dot3_oam_stats_s *p_stats);


/*
 * Event log
 */ 

oam_err_e eoam_get_evt_log(dot3_evt_log_s *p_evt);
oam_err_e eoam_getnext_evt_log(dot3_evt_log_s *p_evt);

/**
 * @brief eoam_rpt_evt_s
 *
* @param clear_flag
 *      experiment flag, set to TRUE to clear critical event
 * @param assert_flag
 *      for link error event only, if TRUE, bypass thershold comparison
 *      (that is, always raise)
 * @param no_logging
 *      TRUE for skipping logging
 * @param value
 *      critical event type: 0 is cleared (see comment), other for raised.
 *      link event type: the error count
 * @param err_run_total
 *      the total error counter
 * 
 * @comment 
 *      The clear function is only for critical events. If a critical event 
 *      occurred, the port might be putted in error-disabled state. 
 * 
 *      FIXME:err-disabled
 */
typedef struct
{
    ifindex_s ifindex;
    mib_evt_type_e evt_type;
    BOOLEAN clear_flag;
    BOOLEAN assert_flag;
    BOOLEAN no_logging;
    oam_gauge64_s value64;
    oam_gauge64_s total64;
} eoam_rpt_evt_s;

#ifdef __cplusplus
}
#endif

#endif /* __EOAM_MIB_H */
