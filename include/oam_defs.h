
#include <stdio.h>
#include <stdint.h>

#include "xutl_defs.h"


#ifndef __OAM_DEFS_H
#define __OAM_DEFS_H

#define OAM_ALL_PORTS       0xff
#define OAM_PDU_REFRESH_CNT 10
#define OAM_MAX_STR_LEN     128 /* device name, filter string */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    OAM_NO_ERROR = 0,
    OAM_NO_MEMORY,
    OAM_NO_NEXT, /* getnext */
    OAM_INTERNAL_ERROR,  /* socket */
    INVALID_VALUE, 
    INVALID_INDEX, /* get error */
    INVALID_CONFIG, /* null pointer */
    INVALID_OP,
    INVALID_TYPE,
    DROP_LOOPBACK,
    LOW_PRIORITY, /* lpbk, variable request (compare mac) */
    INVALID_OAM_PDU,
    INVALID_PORT,
    INVALID_MODE,
    INVALID_REQUEST,
    INVALID_EVENT = 14,
    OP_NOT_ALLOWED,
    LPBK_NOT_ALLOWED,
    LPBK_NOT_STARTED,
    /* FIXME peer capability */
    PEER_CAP_LPBK,
    PEER_CAP_EVENT
} oam_err_e;

#define OAM_MODE_DEFAULT    OAM_MODE_ACTIVE

#define MAC_ADRS_SIZE       6
#define OAM_INFO_TLV_SIZE   16

/* pdu */

#define OAM_PDU_TYPE        0x8809
#define OAM_PDU_SUBTYPE     0x03

/* flags */
#define PDU_FLAGS_EV_LF         0x01
#define PDU_FLAGS_EV_DGASP      0x02
#define PDU_FLAGS_EV_CEVT       0x04
#define PDU_FLAGS_EV_MASK       0x07

#define PDU_FLAGS_L_EVAL        0x08
#define PDU_FLAGS_L_STABLE      0x10
#define PDU_FLAGS_L_MASK        0x18

#define PDU_FLAGS_R_EVAL        0x20
#define PDU_FLAGS_R_STABLE      0x40
#define PDU_FLAGS_R_MASK        0x60

/* FIXME */
#define PDU_FLAGS_L_VALID(v)    ((v) & (PDU_FLAGS_L_EVAL | PDU_FLAGS_L_STABLE))
#define PDU_FLAGS_R_VALID(v)    ((v) & (PDU_FLAGS_R_EVAL | PDU_FLAGS_R_STABLE))

/* set value */
#define PDU_FLAGS_L_SETV(v, y)  (v = (v & ~PDU_FLAGS_L_MASK) | (y & PDU_FLAGS_L_MASK))
#define PDU_FLAGS_R_SETV(v, y)  (v = (v & ~PDU_FLAGS_R_MASK) | (y & PDU_FLAGS_R_MASK))

/* clear flags */
#define PDU_FLAGS_L_CLEAR(v)    ((v) &= ~(PDU_FLAGS_L_MASK))
#define PDU_FLAGS_R_CLEAR(v)    ((v) &= ~(PDU_FLAGS_R_MASK))

#define LOCAL_EQ_REMOTE(l, r)   ( \
        (l & (PDU_FLAGS_L_STABLE | PDU_FLAGS_L_STABLE)) == \
        ((r & (PDU_FLAGS_R_STABLE | PDU_FLAGS_R_STABLE)) >> 2))

#define REMOTE_EQ_LOCAL(r, l)   ( \
        (l & (PDU_FLAGS_L_STABLE | PDU_FLAGS_L_STABLE)) == \
        ((r & (PDU_FLAGS_R_STABLE | PDU_FLAGS_R_STABLE)) >> 2))

/* codes */
#define PDU_CODE_INFO       0x00
#define PDU_CODE_EVENT      0x01
#define PDU_CODE_VAR_REQ    0x02
#define PDU_CODE_VAR_RSP    0x03
#define PDU_CODE_LPBK       0x04
#define PDU_CODE_ORG        0xfe
#define PDI_CODE_RESERVED   0xff

typedef enum
{
    OAM_ADMIN_NONE = 0,
    OAM_ADMIN_ENABLED = 1,
    OAM_ADMIN_DISABLED
} oam_admin_e;

typedef enum
{
    OAM_LPBK_START = 1,
    OAM_LPBK_STOP
} oam_lpbk_cmd_e;

typedef enum
{
    OAM_MODE_NONE = 0,
    OAM_MODE_ACTIVE = 1,
    OAM_MODE_PASSIVE,
    OAM_MODE_UNKNOWN
} oam_mode_e;

/**
 * oam_oper_e (RFC)
 *
 * @OPER_LOCAL_REJECT mapped as sstate SEND_LOCAL_REMOTE
 * @OPER_REMOTE_REJECT mapped as state SEND_LOCAL_REMOTE_OK
 *
 * @comment
 *
 * The mechanism for rejecting a peer is not defined in the standard.
 */
typedef enum
{
    OPER_DISABLED = 1,
    OPER_LINK_FAULT,
    OPER_PASSIVE_WAIT,
    OPER_SEND_LOCAL,
    OPER_LOCAL_REMOTE,
    OPER_LOCAL_REMOTE_OK,
    OPER_LOCAL_REJECT, /* FIXME:reject */
    OPER_REMOTE_REJECT, /* FIXME:reject */
    OPER_OPERATIONAL, /* send any */
    OPER_HALF_DUPLEX /* FIXME:half */
} oam_oper_e;

typedef enum
{
    ST_DISABLED = OPER_DISABLED,
    ST_FAULT = OPER_LINK_FAULT, /* FIXME:NA start from 0 to skip the init code */
    ST_PASSIVE_WAIT = OPER_PASSIVE_WAIT,
    ST_ACTIVE_SEND_LOCAL = OPER_SEND_LOCAL,
    ST_SEND_LOCAL_REMOTE = OPER_LOCAL_REMOTE,
    ST_SEND_LOCAL_REMOTE_OK = OPER_LOCAL_REMOTE_OK,
    ST_SEND_ANY = OPER_OPERATIONAL
} oam_state_e;

/**
 * oam_loopback_e (RFC)
 *
 */
typedef enum
{
    NO_LPBK = 1,
    INIT_LPBK, /* 2 */
    REMOTE_LPBK,
    TERM_LPBK, /* 4 */
    LOCAL_LPBK,
    UNKOWN,
    MAX_LPBK
} oam_lpbk_e;

typedef uint16_t oam_timestamp_s;
typedef uint64_t oam_gauge64_s; /* RFC 2856 */

#ifdef __cplusplus
}
#endif

#endif /* __OAM_DEFS_H */

