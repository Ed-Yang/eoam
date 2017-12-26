
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <pthread.h>
#include <time.h>
#include <sys/time.h>

#include "xutl_defs.h"

#ifndef __XUTL_DBG_H
#define __XUTL_DBG_H

#define DEBUG_IFINDEX   2 /* test interface */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    XDBG_INVALID = 0,
    XDBG_EMERG = 1,  /* system is unusable */
    XDBG_ALERT,  /* action must be taken immediately */
    XDBG_CRIT,   /* critical conditions */
    XDBG_ERR,    /* error conditions */
    XDBG_WARNING,/* warning conditions */
    XDBG_NOTICE, /* normal, but significant, condition */
    XDBG_INFO,   /* informational message */
    XDBG_TRACE,
    XDBG_DEBUG,  /* debug */
    XDBG_MAX,
} xdbg_prio_e;

#define XDBG_DEF_PRIO   XDBG_INFO

void xdbg_log(xdbg_prio_e priority, const char *format, ...);
BOOLEAN xdbg_set_priority(xdbg_prio_e priority);

#ifdef __cplusplus
}
#endif

#endif /* __XUTL_DBG_H */

