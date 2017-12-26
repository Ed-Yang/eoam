#include "oam_defs.h"

#include "eoam_mib.h"
#include "xutl_ipc.h"

#ifndef __EOAM_LOG_H
#define __EOAM_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

BOOLEAN eoam_log_init(uint16_t max_log_entries);
BOOLEAN eoam_log_terminate();
oam_err_e eoam_log_set_log(dot3_evt_log_s *p_evtlog);
oam_err_e eoam_proc_get_log(dot3_evt_log_s *p_evtlog);
oam_err_e eoam_proc_getnext_log(dot3_evt_log_s *p_evtlog);
xipc_status_s eoam_proc_clear_log(uint32_t dummy);

#ifdef __cplusplus
}
#endif

#endif /* __EOAM_LOG_H */

