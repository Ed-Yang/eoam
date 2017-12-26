
#include <stdio.h>
#include <stdint.h>


#include "oam_defs.h"
#include "oam_tlv.h"
#include "eoam_cout.h"

#ifndef __EOAM_PDU_H
#define __EOAM_PDU_H

#define PDU_LF_INFO     0
#define PDU_RX_INFO     1
#define PDU_INFO        2
#define PDU_ANY         3

void eoam_pdu_rx_start();
void eoam_pdu_rx_stop(void);

BOOLEAN eoam_pdu_send(ifindex_s ifindex, uint8_t code,
                      uint8_t flags,uint8_t *payload, size_t payload_len);

#endif /* __EOAM_PDU_H */

