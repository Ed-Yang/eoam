#include <stdarg.h>
#include "xutl_dbg.h"

#define XUTL_DBG_BUFSIZE    128
#define MAX_TAG_LEN         18

/* use variable, so it can be changed in debug */
static xdbg_prio_e g_xdbg_prio = XDBG_DEF_PRIO;  
static char g_logbuf[XUTL_DBG_BUFSIZE + 1];
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

void xdbg_log(xdbg_prio_e prio, const char *format, ...)
{
    va_list arglist;
    int retval;
    int taglen;

    pthread_mutex_lock(&g_log_mutex);
    
    if (g_xdbg_prio >= prio)
    {
        time_t t = time(NULL);
        struct tm *tme, ti;
        struct timeval tv;
        uint32_t msec;

        memset(&ti, 0, sizeof(ti));
        memset(g_logbuf, 0, sizeof(g_logbuf));

        tme = localtime_r(&t, &ti);
        gettimeofday(&tv, NULL);
        msec = tv.tv_usec / 1000;

        taglen = snprintf(g_logbuf, MAX_TAG_LEN, "\n%02d:%02d:%02d.%03d ",
                          tme->tm_hour, tme->tm_min, tme->tm_sec, msec);

        va_start(arglist, format);
        if ((retval = vsnprintf(&g_logbuf[taglen], XUTL_DBG_BUFSIZE - taglen,
                                format, arglist)) > 0)
            g_logbuf[taglen + retval] = 0;
        va_end(arglist);

        fprintf(stderr, "%s", g_logbuf);
    }

    pthread_mutex_unlock(&g_log_mutex);
    
    return;
}

BOOLEAN xdbg_set_priority(xdbg_prio_e priority)
{
    if (priority < XDBG_EMERG || priority > XDBG_DEBUG)
        return FALSE;

    g_xdbg_prio = priority;

    return TRUE;
}
