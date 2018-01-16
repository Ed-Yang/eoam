#include "eoam_timer.h"
#include "eoam_cout.h"
#include "eoam_fsm.h"

BOOLEAN eoam_fsm_timer_handler(xtimer_s *xtimer, void *param)
{
    ifindex_s ifindex;

    if (xtimer == NULL)
    {
        return FALSE;
    }

    if (param == NULL) {}

    for (ifindex = 1; ifindex <= eoam_max_ports(); ifindex++)
    {
        eoam_fsm_pdu_timeout(ifindex);
    }

    return TRUE;
}
 


