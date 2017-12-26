#include "xutl_defs.h"
#include "xutl_dbg.h"

#ifndef __XUTL_DEV_H
#define __XUTL_DEV_H

#ifdef __cplusplus
extern "C" {
#endif

#define XDEV_MAX_NAME   64
#define XDEV_MAC_SIZE   6

#ifdef __linux__
#define XDEV_DEFAULT_DEV    "eth0"
#else
#define XDEV_DEFAULT_DEV    "en0"
#endif

/* src mac filter */
typedef struct
{
    uint8_t mac[XDEV_MAC_SIZE];
    int mask_bytes;
} xdev_mac_s;

typedef struct struct_xdev xdev_s;

xdev_s *xdev_open(char *name, xdev_mac_s *src_mac_flt, BOOLEAN fill_smac, 
    void *param);
BOOLEAN xdev_close(xdev_s *xdev);

/*eoam_rx_indication(ifindex_s ifindex, const uint8_t *packet, size_t length) */

BOOLEAN xdev_send(xdev_s *xdev, uint32_t ifindex, uint8_t *packet, size_t len);
BOOLEAN xdev_recv(xdev_s *xdev, uint8_t *port, uint8_t **buf, size_t *len);
BOOLEAN xdev_start(xdev_s *xdev, BOOLEAN (*rx_cb)(xdev_s *, uint32_t, uint8_t *, size_t));
BOOLEAN xdev_stop(xdev_s *xdev);
BOOLEAN xdev_wait(xdev_s *xdev);

BOOLEAN xdev_link_status(uint32_t ifindex);

#ifdef __cplusplus
}
#endif

#endif /* __XUTL_DEV_H */
