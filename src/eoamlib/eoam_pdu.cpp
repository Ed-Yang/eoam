#include <arpa/inet.h> // ntohs
#include <pthread.h>

#include "xutl_os.h"
#include "xutl_net.h"

#include "eoam_pdu.h"
#include "eoam_cout.h"
#include "eoam_rx.h"
#include "eoam_str.h"
//#include "eoam_params.h"


#define MAX_OAM_PDU_SIZE    512


static uint8_t g_oam_mac_da[] = {0x01,0x80,0xc2,0x00,0x00,0x02};

/**
 * eoam_pdu_send
 * @param payload - tlv payload
 * @param payload_len - total tlv payload length
 */
BOOLEAN eoam_pdu_send(ifindex_s ifindex, uint8_t code, uint8_t flags,
    uint8_t *payload, size_t payload_len)
{
    size_t pkt_len;
    uint8_t pkt_buf[MAX_OAM_PDU_SIZE], *ptr;
    oam_pdu_hdr_t *p_pdu ;
    static uint8_t last_flags = 0;

    memset(pkt_buf, 0, sizeof(pkt_buf));

    p_pdu = (oam_pdu_hdr_t *) pkt_buf;
    ptr = (uint8_t *) (p_pdu + 1);

    // mac da
    memcpy(&p_pdu->da[0], g_oam_mac_da, MAC_ADRS_SIZE);
    
    // mac a: fill by lower layer

    // type 
    p_pdu->type = htons(OAM_PDU_TYPE);

    // subtype
    p_pdu->subtype = OAM_PDU_SUBTYPE;

    // flags
    p_pdu->flags = flags;

    // code
    p_pdu->code = code;

    // tlv
    if (payload != NULL && payload_len > 0)
        memcpy(ptr, payload, payload_len);

    pkt_len = sizeof(oam_pdu_hdr_t) + payload_len;

    /* fill in source mac */
    eoam_cout_get_pmac(ifindex, (uint8_t *)&pkt_buf[6]);

#if OAM_PARAM_DEBUG_PKT
    xdbg_log(XDBG_INFO, "--> [%2d:%d]- %02x:%02x:%02x:%02x:%02x:%02x-%02x:%02x:%02x:%02x:%02x:%02x",
        ifindex, pkt_len,
        pkt_buf[0], pkt_buf[1], pkt_buf[2], pkt_buf[3], pkt_buf[4], pkt_buf[5],
        pkt_buf[6], pkt_buf[7], pkt_buf[8], pkt_buf[9], pkt_buf[10], pkt_buf[11]); 
#endif

    if (last_flags != flags)
    {
        char buf[32];
        xdbg_log(XDBG_INFO, "[%2d] SEND INFO: flags %s",
                 ifindex, eoam_str_info_flags(flags, buf));
        last_flags = flags;
    }

    /* send packet */
    eoam_cout_send(ifindex, pkt_buf, pkt_len);

    return TRUE;
}


