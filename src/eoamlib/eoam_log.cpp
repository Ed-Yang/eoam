/**
 * @brief
 *
 * RFC.  when the table becomes full, older events are automatically deleted
 * to make room for newer events.  The table index dot3OamEventLogIndex
 * increments for each new entry, and when the maximum value is reached,
 * the value restarts at zero.
 *
 * NOTE. add/remove in timestamp ordr, but getnext in ifindex + logindex order
 *
 */

#include <stdio.h>
#include "utringbuffer.h"
 #include "utlist.h"

#include "xutl_dbg.h"
#include "xutl_os.h"
#include "xutl_mem.h"

#include "eoam_log.h"

UT_ringbuffer *g_oeam_log_table = NULL;
dot3_evt_log_s *g_oeam_log_list = NULL;
uint32_t g_max_logs = 0;
uint32_t g_cur_log_index = 0;


typedef struct
{
    uint32_t ifindex;
    uint32_t log_index;
} eoam_rb_s;

UT_icd log_table_icd = {sizeof(eoam_rb_s), NULL, NULL, NULL }; /* store the log index */

int eoam_log_cmp(dot3_evt_log_s *l1, dot3_evt_log_s *l2)
{
    int32_t retval;

    if ((l1->ifindex - l2->ifindex) != 0)
        retval = (l1->ifindex - l2->ifindex);
    else
        retval = (l1->dot3OamEventLogIndex - l2->dot3OamEventLogIndex);

    return retval;
}

BOOLEAN eoam_log_init(uint16_t max_log_entries)
{
    if (g_oeam_log_table != NULL)
        return FALSE;

    utringbuffer_new(g_oeam_log_table, max_log_entries, &log_table_icd);

    g_max_logs = max_log_entries;

    return TRUE;
}

BOOLEAN eoam_log_terminate()
{
    dot3_evt_log_s *p_log, *p_tmp;

    if (g_oeam_log_table != NULL)
        utringbuffer_free(g_oeam_log_table);

    LL_FOREACH_SAFE(g_oeam_log_list, p_log, p_tmp)
    {
        LL_DELETE(g_oeam_log_list, p_log);
        xmem_free(p_log, sizeof(dot3_evt_log_s));
    }

    g_oeam_log_list = NULL;

    return TRUE;
}

/**
 * @brief
 *
 * @param p_evtlog
 * @return oam_err_e
 *
 * add/remove in ring buffer order
 */
oam_err_e eoam_log_set_log(dot3_evt_log_s *p_evtlog)
{
    dot3_evt_log_s evtlog, *p_log;
    eoam_rb_s rb_entry, *p_old;
    oam_err_e status = OAM_NO_ERROR;

    if (p_evtlog == NULL || g_oeam_log_table == NULL)
    {
        xdbg_log(XDBG_ERR, "eoam_log_set_log: ifindex %d type %d null pointer !!!",
                 p_evtlog->ifindex, p_evtlog->dot3OamEventLogType);
        
        return INVALID_CONFIG;
    }

    xdbg_log(XDBG_DEBUG, "eoam_log_set_log: ifindex %d type %d value %llu",
             p_evtlog->ifindex, p_evtlog->dot3OamEventLogType, p_evtlog->dot3OamEventLogValue);
             
    /* FIXME:log check parameters */

    /* if table is full, remove oldest from ordered linked list */
    p_old = (eoam_rb_s *)utringbuffer_front(g_oeam_log_table);
    if (utringbuffer_full(g_oeam_log_table) && p_old != NULL)
    {
        evtlog.ifindex = p_old->ifindex;
        evtlog.dot3OamEventLogIndex = p_old->log_index;

        LL_SEARCH(g_oeam_log_list,p_log, &evtlog, eoam_log_cmp);
        if (p_log)
        {
            LL_DELETE(g_oeam_log_list, p_log);
        }
        else
        {
            xdbg_log(XDBG_ERR, "eoam_log_set_log: cannot find log in linked list !!!");
        }
    }
    else
    {
        if ((p_log = (dot3_evt_log_s *)xmem_malloc(sizeof(dot3_evt_log_s))) == NULL)
            return OAM_NO_MEMORY;
    }

    /* put into ringbuffer */
    g_cur_log_index++;

    rb_entry.ifindex = p_evtlog->ifindex;
    rb_entry.log_index = g_cur_log_index;
    utringbuffer_push_back(g_oeam_log_table, &rb_entry);

    /* insert to ordered linked list */
    memcpy(p_log, p_evtlog, sizeof(dot3_evt_log_s));

    /* update log entry */
    p_log->dot3OamEventLogIndex = g_cur_log_index;
    /* timestamp, local: system, remote: rx time (this is called from pdu rx) */
    p_log->dot3OamEventLogTimestamp = xos_get_uptime();
    
    LL_INSERT_INORDER(g_oeam_log_list, p_log, eoam_log_cmp);

    return status;
}

oam_err_e eoam_proc_get_log(dot3_evt_log_s *p_evtlog)
{
    dot3_evt_log_s evtlog, *p_log;
    oam_err_e status = OAM_NO_ERROR;

    if (p_evtlog == NULL || g_oeam_log_table == NULL)
        return INVALID_CONFIG;

    evtlog.ifindex = p_evtlog->ifindex;
    evtlog.dot3OamEventLogIndex = p_evtlog->dot3OamEventLogIndex;

    LL_SEARCH(g_oeam_log_list,p_log, &evtlog, eoam_log_cmp);
    if (p_log == NULL)
        return INVALID_INDEX;

    memcpy(p_evtlog, p_log, sizeof(dot3_evt_log_s));

    /* if it is remote log, or critical event log, update some values */
    if (p_log->dot3OamEventLogLocation == EVT_REMOTE || 
        p_log->dot3OamEventLogType > 4)
    {
        /* rfc, set win/thr/value of non-cross events to all 0xff */
        p_evtlog->dot3OamEventLogThresholdHi = 0xffffffff;
        p_evtlog->dot3OamEventLogThresholdLo = 0xffffffff;
        p_evtlog->dot3OamEventLogWindowHi = 0xffffffff;
        p_evtlog->dot3OamEventLogWindowLo = 0xffffffff;
        p_evtlog->dot3OamEventLogValue = 0xffffffffffffffff;
    }

    return status;
}

oam_err_e eoam_proc_getnext_log(dot3_evt_log_s *p_evtlog)
{
    dot3_evt_log_s *p_log;
    oam_err_e status = OAM_NO_NEXT;

    xdbg_log(XDBG_DEBUG, "[0x%08x] eoam_proc_getnext_log: enter - ifindex %d logindex %d type %d",
             pthread_self(), p_evtlog->ifindex, p_evtlog->dot3OamEventLogIndex, p_evtlog->dot3OamEventLogType);
             
    if (p_evtlog == NULL)
        return INVALID_CONFIG;

    if (g_oeam_log_table == NULL)
    {
        xdbg_log(XDBG_INFO, "eoam_proc_getnext_log: no next. ifindex %d logindex %d type %d",
                 p_evtlog->ifindex, p_evtlog->dot3OamEventLogIndex, p_evtlog->dot3OamEventLogType);
        
        return OAM_NO_NEXT;
    }

    LL_FOREACH(g_oeam_log_list, p_log)
    {
        if (p_log && eoam_log_cmp(p_log, p_evtlog) > 0)
        {
            memcpy(p_evtlog, p_log, sizeof(dot3_evt_log_s));
            status = OAM_NO_ERROR;
            break;
        }
    }

    xdbg_log(XDBG_DEBUG, "eoam_proc_getnext_log: status %d ifindex %d logindex %d type %d",
             status, p_evtlog->ifindex, p_evtlog->dot3OamEventLogIndex, p_evtlog->dot3OamEventLogType);

    return status;
}

xipc_status_s eoam_proc_clear_log(uint32_t dummy)
{
    dot3_evt_log_s *p_log, *p_tmp;

    xdbg_log(XDBG_DEBUG, "[0x%08x] eoam_proc_clear_log: dummy input = %d",
        pthread_self(), dummy);

    /* clear log buffer */
    if (g_oeam_log_table != NULL)
        utringbuffer_clear(g_oeam_log_table);

    LL_FOREACH_SAFE(g_oeam_log_list, p_log, p_tmp)
    {
        LL_DELETE(g_oeam_log_list, p_log);
        xmem_free(p_log, sizeof(dot3_evt_log_s));
    }

    g_oeam_log_list = NULL;

    return XIPC_NO_ERROR;
}





