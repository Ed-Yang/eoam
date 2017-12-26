/**
 *
 * @brief
 *
 * This file is used to redefine the default "reference" constants.  All of the
 * actual configurables should be supplied in invoking eoam_fsm_init(&oam_params).
 *
 */
#include "oam_defs.h"
#include "eoam_mib.h"


#ifndef __USER_PARAM_H
#define __USER_PARAM_H

#ifdef __cplusplus
extern "C" {
#endif

#define EOAM_PKT_PATH           "/tmp/gt_eoam.pkt.sock"
#define EOAM_CFG_PATH           "/tmp/gt_eoam.cfg.sock"

#define OAM_PARAM_MAX_PORTS     4 /* FIXME:ifindex */
#define OAM_PARAM_ADMIN_STATE   OAM_ADMIN_ENABLED
#define OAM_PARAM_OAM_TIMEOUT   (5000) 
#define OAM_PARAM_RX_MODE       PROCESS_LPBK /* lpbk cap. */

#define OAM_PARAM_OAM_MODE      OAM_MODE_ACTIVE
#define OAM_PARAM_OUI           {0x22, 0x22, 0x22} /* apple */
#define OAM_PARAM_VENDOR        0x77777777 /* */

#define OAM_PARAM_LOG_TBL_SIZE  10

#define OAM_PARAM_DEBUG         0
#define OAM_PARAM_DEBUG_PKT     0
#define OAM_PARAM_DROP_LPBK     0

#ifdef __cplusplus
}
#endif

#endif /* __USER_PARAM_H */

