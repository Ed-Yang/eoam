#include "oam_defs.h"
#include "eoam_mib.h"

/* include user's custom parameters */
#include "user_params.h"

#ifndef __EOAM_PARAM_H
#define __EOAM_PARAM_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief non-customizable setttings
 *
 */
#define OAM_PARAM_OAM_VERSION   1
#define OAM_PARAM_VARREQ        FALSE /* FIXME:  not implemented */
#define OAM_PARAM_LINK_EVENT    TRUE
#define OAM_PARAM_LPBK          TRUE
#define OAM_PARAM_UNIDIRECT     FALSE /* FIXME: not implemented */
#define OAM_PARAM_OAM_MODE      OAM_MODE_ACTIVE
#define OAM_PARAM_PDU_SIZE      1500


/**
 * @brief customizable setttings
 *
 */

/*
 * features
 */
#ifndef OAM_PARAM_MAX_PORTS
#define OAM_PARAM_MAX_PORTS     2 /* FIXME:ifindex */
#endif

#ifndef OAM_PARAM_ADMIN_STATE
#define OAM_PARAM_ADMIN_STATE   OAM_ADMIN_DISABLED
#endif

#ifndef OAM_PARAM_RX_MODE
#define OAM_PARAM_RX_MODE       IGNORED_LPBK /* lpbk cap. */
#endif

#ifndef OAM_PARAM_OUI
#define OAM_PARAM_OUI           {0x78, 0x7f, 0x43} /* apple */
#endif

#ifndef OAM_PARAM_VENDOR
#define OAM_PARAM_VENDOR        {0x00, 0x00, 0x00, 0x00} /* none */
#endif

#ifndef OAM_PARAM_OAM_TIMEOUT
#define OAM_PARAM_OAM_TIMEOUT   (5000) /* in ms, per interface */
#endif

#ifndef OAM_PARAM_LPBK_TIMEOUT
#define OAM_PARAM_LPBK_TIMEOUT  (3000) /* in ms, per interface */
#endif

#ifndef OAM_PARAM_LOG_TBL_SIZE
/* FIXME:log */
#define OAM_PARAM_LOG_TBL_SIZE  20
#endif

/*
 * debug
 * */
#ifndef OAM_PARAM_DEBUG
#define OAM_PARAM_DEBUG     0
#endif

#ifndef OAM_PARAM_DEBUG_PKT
#define OAM_PARAM_DEBUG_PKT  0 /* enable packet log */
#endif

#ifndef OAM_PARAM_DROP_LPBK
#define OAM_PARAM_DROP_LPBK 0
#endif

#ifdef __cplusplus
}
#endif

#endif /* __EOAM_PARAM_H */

