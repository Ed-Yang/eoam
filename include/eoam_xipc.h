


#include "xutl_ipc.h"

#ifndef __EOAM_XIPC_H
#define __EOAM_XIPC_H

#ifdef __cplusplus
extern "C" {
#endif

/* op */
typedef enum
{
    EOAM_OP_EXEC,
    EOAM_OP_EVENT, /* pkt */
    EOAM_OP_SET,
    EOAM_OP_GET,
    EOAM_OP_GETNEXT,
    EOAM_OP_MAX
} eoam_op_e;

/* mtype */
typedef enum
{
    EOAM_END = 0,
    EOAM_CONFIG,
    EOAM_PEER,
    EOAM_LPBK,
    EOAM_REPORT_EVENT,
    EOAM_EVENT_CFG,
    EOAM_EVENT_LOG,
    EOAM_EVENT_QUIT,
    EOAM_EVENT_DEBUG,
    EOAM_STATS,
    EOAM_PACKET,
    EOAM_MTYPE_MAX
} eoam_mtype_e;

int eoam_xipc_cfg_fd();
int eoam_xipc_pkt_fd();
xipc_s *eoam_xipc_cfg();
xipc_s *eoam_xipc_pkt();

BOOLEAN eoam_xipc_init(char *pkt_path, char *cfg_path);
BOOLEAN eoam_xipc_terminate();


xipc_status_s eoam_xipc_handle_packet(xipc_s *xipc, xipc_hdr_s *xhdr,
                                      void *data, size_t *size, /* FIXME */
                                      void *param);

#ifdef __cplusplus
}
#endif

#endif /* __EOAM_XIPC_H */

