#include <stdio.h>
#include <stdint.h>

#include "oam_defs.h"
#include "xutl_defs.h"

#ifndef __OAM_TLV_H
#define __OAM_TLV_H

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(1)

typedef struct
{
    uint8_t da[MAC_ADRS_SIZE];
    uint8_t sa[MAC_ADRS_SIZE];
    uint16_t type;
    uint8_t subtype;
    uint8_t flags_reserved;
    uint8_t flags; /* NOTE.  remote state is copy of remote's local flag */
    uint8_t code;
} oam_pdu_hdr_t;

typedef struct
{
    uint8_t type;
    uint8_t length;
} oam_tlv_hdr_t;

#define TLV_TYPE_END            0x00
/*
 * Information OAMPDU
 *
 */

/* info type */
#define INFO_TLV_TYPE_END       TLV_TYPE_END
#define INFO_TLV_TYPE_LOCAL     0x01
#define INFO_TLV_TYPE_REMOTE    0x02

/* state */
#define STATE_PAR_FWD           0x00
#define STATE_PAR_LPBK          0x01
#define STATE_PAR_DISCARD       0x02
#define STATE_PAR_RESERVED      0x03

#define STATE_MUX_FWD           0x00
#define STATE_MUX_DISCARD       0x04

#define STATE_NO_LPBK           (STATE_PAR_FWD | STATE_MUX_FWD)
#define STATE_INIT_LPBK         (STATE_PAR_DISCARD | STATE_MUX_DISCARD)
#define STATE_RMT_LPBK          (STATE_PAR_DISCARD | STATE_MUX_FWD)
#define STATE_LCL_LPBK          (STATE_PAR_LPBK | STATE_MUX_DISCARD)

#define OAMPDU_STATE(par, mux) ((par) | (mux))

#define CFG_MODE_ACTIVE         0x01 /* bit 0 */
#define CFG_UNIDIRECTIONAL      0x02 /* bit 1 */
#define CFG_LPBK                0x04
#define CFG_LINK_EVENTS         0x08
#define CFG_VAR_REQ             0x10


/* oam_config */
#define SET_OAMPDU_PDUSIZE(x, v) \
    do { \
        *(uint8_t *)(x) = v & 0 xff; \
        *(uint8_t *)(x + 1) = (v >> 8) & 0x3; \
    } while (0);

typedef struct
{
    oam_tlv_hdr_t hdr;
    uint8_t version;
    uint16_t tlv_revision;
    uint8_t state; /*0-1: par, 2: mux, 3-7: reserved */
    uint8_t config;
    uint16_t max_pdu_size;  /* reserved:6, pdu_size: 10 */

    uint8_t oui[3];
    uint32_t vendor_spec;
} oam_pdu_info_t;

/*
 * Event Notification OAMPDU
 * 
 * @param timestamp
 *      This two-octet field indicates the time reference when the event was 
 *      generated, in terms of 100 ms intervals.
 *      (XXX).... if it conains multiple event tlv, most recent timestamp is used.
 */

typedef struct
{
    oam_tlv_hdr_t hdr;
    uint16_t timestamp; /* 100 ms units*/
    uint32_t window_hi;
    uint32_t window_lo;
    uint32_t threshold_hi;
    uint32_t threshold_lo;
    uint32_t errors_hi;
    uint32_t errors_lo;
    uint32_t err_total_hi;
    uint32_t err_total_lo;
    uint32_t evt_total;
} sym_period_s;

typedef struct
{
    oam_tlv_hdr_t hdr;
    uint16_t timestamp; 
    uint16_t window;
    uint32_t threshold;
    uint32_t errors;
    uint32_t err_total_hi;
    uint32_t err_total_lo;
    uint32_t evt_total;
} frame_period_s;

typedef struct
{
    oam_tlv_hdr_t hdr;
    uint16_t timestamp; 
    uint32_t window;
    uint32_t threshold;
    uint32_t errors;
    uint32_t err_total_hi;
    uint32_t err_total_lo;
    uint32_t evt_total;
} err_frame_s;

typedef struct
{
    oam_tlv_hdr_t hdr;
    uint16_t timestamp; 
    uint16_t window;
    uint16_t threshold;
    uint16_t errors;
    uint32_t err_total;
    uint32_t evt_total;
} frame_sec_s;

/**
 *  type        1   2   3   4
 *  lenngth     40  26  28  18
 *  timestamp   2   2   2   2  
 *  window      8   2   4   2
 *  threshold   8   4   4   2
 *  err         8   4   4   2
 *  total       8   8   8   4
 *  evt total   4   4   4   4
 */
typedef union
{
    sym_period_s sym_prd;
    frame_period_s frame_prd;
    err_frame_s frame;
    frame_sec_s frame_sec;

} oam_event_tlv_s;

typedef struct
{
    uint16_t evt_seq;
    oam_event_tlv_s evt_tlv;
} oam_pdu_event_s;

/*
 * Loopback
 *
 */

#pragma pack()

#ifdef __cplusplus
}
#endif

#endif /* __OAM_TLV_H */

