
#include <stdio.h>
#include <stdint.h>

#include "eoam_fsm.h"

#ifndef __EOAM_STR_H
#define __EOAM_STR_H

#ifdef __cplusplus
extern "C" {
#endif

const char *eoam_str_onoff(int onoff);
const char *eoam_str_oam_mode(oam_mode_e mode);
const char *eoam_str_fsm_state(oam_state_e state);
const char *eoam_str_oper(oam_oper_e oper);
const char *eoam_str_events(oam_fsm_evt_e evt);
const char *eoam_str_info_state(uint8_t state);
const char *eoam_str_oam_config(uint8_t config);
const char *eoam_str_info_flags(uint8_t flags, char *flags_buf);
const char *eoam_str_lpbk_status(oam_lpbk_e lpbk_status);

#ifdef __cplusplus
}
#endif

#endif /* __EOAM_STR_H */

