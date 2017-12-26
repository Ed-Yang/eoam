#include "xutl_dbg.h"

#include "oam_defs.h"
#include "eoam_mib.h"

#ifndef __EOAM_IF_H
#define __EOAM_IF_H

#ifdef __cplusplus
extern "C" {
#endif

/* FIXME:evt */
oam_err_e eoam_req_report_event(eoam_rpt_evt_s *p_rpt); 
oam_err_e eoam_req_clear_log(void);
oam_err_e eoam_req_clear_stats(ifindex_s ifindex);
oam_err_e eoam_req_debug_priority(xdbg_prio_e priority);
oam_err_e eoam_req_quit(void);

#ifdef __cplusplus
}
#endif

#endif /* __EOAM_IF_H */

