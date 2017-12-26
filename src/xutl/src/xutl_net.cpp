#include <pthread.h>
#include <signal.h>

#include "xutl_net.h"
#include "xutl_mem.h"
#include "xutl_os.h"

#include "utlist.h" /* uthash */

#define XNET_DEBUG          1

#define TIME_DELTA          10
#define XNET_MAX_NAME_SIZE  8

struct xnet_timer
{
    xnet_s *xnet_handler;
    xtimer_s *xtimer_handler;
    struct timeval base_time;  /* if base_time is zero, the timer is stopped */
    struct timeval timeout;
    BOOLEAN started;
    pthread_t creator;
    uint32_t interval;
    BOOLEAN recurrsing;
    BOOLEAN (*tmr_cb)(xtimer_s *, void *);
    void *param;
    int count;
    struct xnet_timer *next, *prev; /* uthash */
};

struct xnet_socket
{
    xnet_s *xnet_handler;
    pthread_t creator;
    int sockfd;
    BOOLEAN (*sock_cb)(void *, int, void *);
    void *param;
    struct xnet_socket *next, *prev; /* uthash */
};

struct xnet_session
{
    /* thread */
    pthread_t xnet_tid;
    pthread_t lock_tid;
    pthread_mutex_t xnet_lock;
    pthread_cond_t start_cond;
    pthread_cond_t stop_cond;
    BOOLEAN xnet_initialized;
    BOOLEAN xnet_started;
    BOOLEAN xnet_running;
    BOOLEAN xnet_wait;
    fd_set readfds;

    /* user init */
    void (*usr_init)(void *xnet, void *param);
    void *usr_param;

    /* user default timer */
    uint32_t def_timeout; /* ms */
    void (*def_timer)(xnet_s *xnet, void *param);
    void *def_timer_param;

    /* socket */
    struct xnet_socket *xsock_list;

    /* timer */
    struct xnet_timer *xtimer_running;
    struct xnet_timer *xtimer_expired;
};

static int g_lock_cnt = 0;

static void XNET_LOCK(xnet_s *xnet)
{
    if (xnet->lock_tid != 0 && xnet->lock_tid == pthread_self())
    {
        xdbg_log(XDBG_ERR, "XNET_LOCK: double locked  (0x%08x, 0x%08x) !!!",
            xnet->lock_tid, pthread_self());
    }

    pthread_mutex_lock(&xnet->xnet_lock);
    xnet->lock_tid = pthread_self();
    g_lock_cnt++;
}

static void XNET_UNLOCK(xnet_s *xnet)
{
#if 0 /* lock, lock, unlock --> set to 0 */
    if (xnet->lock_tid != pthread_self())
    {
        xdbg_log(XDBG_ERR, "XNET_UNLOCK: diff thread (0x%08x, 0x%08x) !!!",
            xnet->lock_tid, pthread_self());
    }
#endif

    xnet->lock_tid = 0;
    g_lock_cnt--;
    pthread_mutex_unlock(&xnet->xnet_lock);
}

static inline void timer_add_offset(struct timeval *t2, struct timeval *t1, uint32_t msec)
{
    t2->tv_sec = t1->tv_sec + msec / 1000;
    t2->tv_usec = t1->tv_usec + (msec % 1000) * 1000;

    if (t2->tv_usec >= 1000000)
    {
        t2->tv_sec += 1;
        t2->tv_usec -= 1000000;
    }

    return;
}

int xnet_time_diff(struct timeval *t1, struct timeval *t2)
{
    int32_t msec;
    int32_t s, usec;

    s = (int32_t) (t2->tv_sec - t1->tv_sec);
    usec = t2->tv_usec - t1->tv_usec;

    msec = (s) * 1000 + (usec) / 1000;

    return msec;
}

/**
 * @brief   set the next timeout and return the remaining msec
 *
 * @return - remaining msec before expire
 *
 */
static uint32_t calc_next_timeout(struct timeval *next, struct timeval *base,
                                  struct timeval *now, uint32_t interval)
{
    int round, timeout_ms;
    int ms;

    ms = xnet_time_diff(base, now);
    round = ( ms + interval) / interval;
    timer_add_offset(next, base, round * interval);

    timeout_ms = xnet_time_diff(now, next);

    xdbg_log(XDBG_DEBUG, "recalc timeout (r=%d, interval = %d, timeout msec=%d)",
             round, interval, timeout_ms);

    return timeout_ms;
}

static void inline next_wait_time(xtimer_s *head, struct timeval *wait_time, 
    uint32_t def_timeout)
{
    uint32_t min_diff_ms = 0xffffffff;
    uint32_t msec;
    xtimer_s *p_timer;
    struct timeval cur_time;
    int runner_cnt = 0;

    gettimeofday(&cur_time, NULL);

    LL_FOREACH(head, p_timer)
    {
        runner_cnt++;

        msec = calc_next_timeout(&p_timer->timeout, &p_timer->base_time,
                                 &cur_time, p_timer->interval);

#if XNET_DEBUG
        xdbg_log(XDBG_DEBUG, "==> next_wait_time: msec = %d", msec);
#endif
        if ( msec < min_diff_ms)
            min_diff_ms = msec;
    }

    if (runner_cnt > 0)
    {
        wait_time->tv_sec = min_diff_ms / 1000;
        wait_time->tv_usec = (min_diff_ms % 1000) * 1000;
    }
    else
    {
        /** TODO remove busy loop when there is no active timer */
        wait_time->tv_sec = def_timeout / 1000;
        wait_time->tv_usec = (def_timeout % 1000) * 1000;
    }

#if XNET_DEBUG
    if (wait_time->tv_sec > 10)
    {
        xdbg_log(XDBG_ERR, "==> next_wait_time: return tv = (%d, %d)",
                 wait_time->tv_sec, wait_time->tv_usec);
    }
#endif

    return;
}

static int _xnet_proc_io_callback(xnet_s *xnet)
{
    struct xnet_socket *p_sock = NULL;
    BOOLEAN retval ;
    int cnt = 0;

    LL_FOREACH(xnet->xsock_list,p_sock)
    {
        if (FD_ISSET(p_sock->sockfd, &xnet->readfds))
        {
            retval = (*p_sock->sock_cb)(xnet, p_sock->sockfd, p_sock->param);
            if (retval != TRUE)
            {
                xdbg_log(XDBG_WARNING, "INFO: xnet callback return error !!");
            }
            FD_CLR(p_sock->sockfd, &xnet->readfds);
            cnt++;
        }
    }

    return cnt ;    
}

/**
 * _xnet_proc_timer_callback
 * 
 * assuem entering in locked state
 */ 
static int _xnet_proc_timer_callback(xnet_s *xnet, struct timeval *p_tv)
{
    xtimer_s *p_timer, *exp_timer, *tmp_timer;
    struct timeval cur_time;
    int32_t msec;
    BOOLEAN retval;
    int cnt = 0;

#ifdef DEBUG_XNET
    int exp_cnt, run_cnt;
#endif

#ifdef DEBUG_XNET
        LL_COUNT(xnet->xtimer_expired, exp_timer, exp_cnt);
        LL_COUNT(xnet->xtimer_running, p_timer, run_cnt);

        xdbg_log(XDBG_DEBUG, "0. ===> xtimer: exp %d, run %d",
                 exp_cnt, run_cnt);
#endif
        /* add expired timer to expired list */

        gettimeofday(&cur_time, NULL);

        LL_FOREACH(xnet->xtimer_running, p_timer)
        {
            if (p_timer->started != TRUE)
                continue;

            msec = xnet_time_diff(&cur_time, &p_timer->timeout);
            //xdbg_log(XDBG_DEBUG, "check timer, diff = %d", msec); 
            if ( msec <= TIME_DELTA)
            {
                if ((exp_timer = (xtimer_s *)xmem_malloc(sizeof(xtimer_s))) == NULL)
                {
                    xdbg_log(XDBG_ERR, "xnet: cannot alloc memory size %d !!!",
                             sizeof(xtimer_s));
                }
                else
                {
                    xdbg_log(XDBG_DEBUG, "1.1:  +e %08x", p_timer);

                    memcpy(exp_timer, p_timer, sizeof(xtimer_s));
                    LL_APPEND(xnet->xtimer_expired, exp_timer);
                }
            }
        }
        

#ifdef DEBUG_XNET
        LL_COUNT(xnet->xtimer_expired, exp_timer, exp_cnt);
        LL_COUNT(xnet->xtimer_running, p_timer, run_cnt);

        xdbg_log(XDBG_DEBUG, "1. ===> xtimer: exp %d, run %d",
                 exp_cnt, run_cnt);
#endif

        /* 
         * invoke timer function. If xnet is terminationg, skip callbcak to avoid
         * sync issue, or error log
         * */
        XNET_UNLOCK(xnet);

        if (xnet->xnet_started == TRUE)
        {
            LL_FOREACH(xnet->xtimer_expired, exp_timer)
            {
                /*
                 * it is possible to call timer function in timer callback, so
                 * unlock before invoking callback
                 */
                //xdbg_log(XDBG_DEBUG, "timeout, exec callback (msec = %d)", msec);
                retval = (*exp_timer->tmr_cb)(exp_timer->xtimer_handler, exp_timer->param);
                if (retval == FALSE)
                {
                    tmp_timer = exp_timer->xtimer_handler;
                    if (tmp_timer)
                        tmp_timer->started = FALSE;
                }
                cnt ++;
            }
        }

        XNET_LOCK(xnet);
        
#ifdef DEBUG_XNET
        LL_COUNT(xnet->xtimer_expired, exp_timer, exp_cnt);
        LL_COUNT(xnet->xtimer_running, p_timer, run_cnt);

        xdbg_log(XDBG_DEBUG, "2. ===> xtimer: exp %d, run %d",
                 exp_cnt, run_cnt);
#endif

        /* remove expired timer */
        LL_FOREACH_SAFE(xnet->xtimer_expired,exp_timer,tmp_timer)
        {
            LL_DELETE(xnet->xtimer_expired,exp_timer);
            xmem_free(exp_timer, sizeof(xtimer_s));
        }

        /* calc next wait time */
        //XNET_LOCK(xnet);

        gettimeofday(&cur_time, NULL);
        LL_FOREACH(xnet->xtimer_running, p_timer)
        {
            if (p_timer->started == TRUE)
            {
                calc_next_timeout(&p_timer->timeout, &p_timer->base_time,
                                  &cur_time, p_timer->interval);
                xdbg_log(XDBG_DEBUG, "2.1: +r %08x", p_timer);
            }
        }

#ifdef DEBUG_XNET
        LL_COUNT(xnet->xtimer_expired, exp_timer, exp_cnt);
        LL_COUNT(xnet->xtimer_running, p_timer, run_cnt);

        xdbg_log(XDBG_DEBUG, "3. ===> xtimer: exp %d, run %d",
                 exp_cnt, run_cnt);
#endif

        /* calc next wait interval */
        next_wait_time(xnet->xtimer_running, p_tv, xnet->def_timeout);

        return cnt ;
}

static void *xnet_thread(void *param)
{
    struct xnet_socket *p_sock = NULL;
    struct timeval tv;
    //fd_set readfds;
    int count = -1;
    int c=0, m, n;
    /*void (*usr_init)(void) = (void (*)(void))param; */
    xnet_s *xnet = (xnet_s *)param;

    /* prevent got signal on send to a closing socket */
    signal(SIGPIPE, SIG_IGN); // FIXNE:sock only need in main
    
    /* init next timeout value */
    XNET_LOCK(xnet);

    xnet->xnet_running = TRUE;
    next_wait_time(xnet->xtimer_running, &tv, xnet->def_timeout);

    pthread_cond_signal(&xnet->start_cond);
    
    XNET_UNLOCK(xnet);

    xdbg_log(XDBG_INFO, "xnet thread run user_init ...",
             tv.tv_sec, tv.tv_usec);

    /* call user init */
    if (xnet->usr_init)
        (*xnet->usr_init)(xnet, xnet->usr_param);

    xdbg_log(XDBG_INFO, "xnet thread enter loop (sec = %d, wait time: usec = %d).",
             tv.tv_sec, tv.tv_usec);

    while (xnet->xnet_started == TRUE)
    {
        XNET_LOCK(xnet);

        FD_ZERO(&xnet->readfds);

        LL_FOREACH(xnet->xsock_list,p_sock)
            FD_SET(p_sock->sockfd, &xnet->readfds);

        LL_COUNT(xnet->xsock_list, p_sock, c);
        //if (count != c)
        {
            count = c;
            xdbg_log(XDBG_DEBUG, "wait in select (# of io %d, tv.sec %d, tv.usec = %d)",
                 count, tv.tv_sec, tv.tv_usec);
        }
        XNET_UNLOCK(xnet);

        if ((m=select(FD_SETSIZE, &xnet->readfds, NULL, NULL, &tv)) > 0)
        {
            XNET_LOCK(xnet);
            m = _xnet_proc_io_callback(xnet);
            XNET_UNLOCK(xnet);
        }

        XNET_LOCK(xnet);
        /* handle timeer callback */
        n = _xnet_proc_timer_callback(xnet, &tv);

        XNET_UNLOCK(xnet);

        if ((m == 0 && n == 0) && xnet->def_timer != NULL)
        {
            xdbg_log(XDBG_DEBUG, "xnet thread: exec user timer");
            (*xnet->def_timer)(xnet, xnet->def_timer_param);
        }
    }

    xdbg_log(XDBG_INFO, "[%08x] xnet thread, wait to signal terminate request ...", pthread_self());
    XNET_LOCK(xnet);

    xnet->xnet_running = FALSE;
    pthread_cond_signal(&xnet->stop_cond);

    xdbg_log(XDBG_INFO, "[%08x] xnet thread, signal terminate request - done.", pthread_self());
    XNET_UNLOCK(xnet);

    /* detach thread, so valgrind will not complain memory leak
     * pthread_detach(pthread_self());
     */

    xdbg_log(XDBG_INFO, "[%08x] xnet thread exit.", pthread_self());

    pthread_exit((void *)xnet);

    return NULL;
}

xnet_s *xnet_open(void (*usr_init)(void *, void *), void *param)
{
    xnet_s *xnet;

    if ((xnet = (xnet_s *) xmem_malloc(sizeof(xnet_s))) == NULL)
    {
        perror("xmem_alloc");
        return NULL;
    }

    memset(xnet, 0, sizeof(xnet_s));

    if (pthread_mutex_init(&xnet->xnet_lock, NULL) != 0)
    {
        perror("pthread_mutex_init");
        return FALSE;
    }

    if (pthread_cond_init(&xnet->start_cond, NULL) != 0)
    {
        perror("pthread_cond_init");
        return FALSE;
    }

    if (pthread_cond_init(&xnet->stop_cond, NULL) != 0)
    {
        perror("pthread_cond_init");
        return FALSE;
    }

    xnet->usr_init = usr_init;
    xnet->usr_param = param;
    xnet->xnet_initialized = TRUE;

    return xnet;
}

BOOLEAN xnet_start(xnet_s *xnet, void (*usr_timer)(xnet_s *, void *),
                   void *param, uint32_t timeout)
{
    int err;

    if (xnet->xnet_initialized != TRUE)
    {
        xdbg_log(XDBG_ERR, "xnet_start: xnet is not initialized yet !!");
        return FALSE;
    }

    XNET_LOCK(xnet);
    
    xnet->xnet_started = TRUE;
    xnet->def_timer = usr_timer;
    xnet->def_timer_param = param;
    
    if (timeout == 0)
        xnet->def_timeout = XNET_DEF_WAIT_MSEC;
    else
        xnet->def_timeout = timeout;

    err = pthread_create(&xnet->xnet_tid, NULL, xnet_thread, (void *)xnet);
    if (err != 0)
    {
        perror("pthread_create");
        XNET_UNLOCK(xnet);
        return FALSE;
    }

    while (xnet->xnet_running != TRUE)
        pthread_cond_wait(&xnet->start_cond, &xnet->xnet_lock);
    
    XNET_UNLOCK(xnet);
    
    xdbg_log(XDBG_INFO, "[%08x] xnet_start: xnet thread is running ...",
             pthread_self());

    return TRUE;
}

BOOLEAN xnet_stop(xnet_s *xnet)
{
    int rv;

    xdbg_log(XDBG_INFO, "xnet_stop: enter.");

    if (xnet == NULL)
    {
        xdbg_log(XDBG_ERR, "xnet_stop: invalid input pointer !!");
        return FALSE;
    }

    XNET_LOCK(xnet);

    if (xnet->xnet_initialized != TRUE || xnet->xnet_started != TRUE)
    {
        xdbg_log(XDBG_ERR, "xnet_stop: xnet is not initialized or stated yet !!");
        XNET_UNLOCK(xnet);
        return FALSE;
    }

    /*
     * remove allocated resources
     */
    xnet->xnet_started = FALSE;
    
    while (xnet->xnet_running == TRUE)
    {
        xdbg_log(XDBG_INFO, "xnet_stop: wait rx thread terminate ...");
        pthread_cond_wait(&xnet->stop_cond, &xnet->xnet_lock);
    }
    
    xdbg_log(XDBG_INFO, "xnet_stop: wait rx thread terminate - done.");

    XNET_UNLOCK(xnet);

    /**
     * in blocking mode, the caller is alreay calll join in xnet_start,
     *  don't call pthread_join again.
     */
    
    /* someone might call xnet_wait, so check if thread is already joined */
    if (xnet->xnet_wait != TRUE &&
        (rv = pthread_join(xnet->xnet_tid, NULL)) != 0)/* FIXME */
    {
        xdbg_log(XDBG_ERR, "[%08x] xnet_stop: join error tid %08x (rv=%d, %d, errno = %d) !!!",
                    pthread_self(), xnet->xnet_tid, rv, EINVAL, errno);
        perror("\nxnet_teriminate: blocking join");
    }

    xdbg_log(XDBG_INFO, "xnet_stop: completed.");

    return TRUE;
}

BOOLEAN xnet_close(xnet_s *xnet)
{
    xtimer_s *p_timer, *tmp_timer;
    xsocket_s *p_sock, *tmp_sock;

    xdbg_log(XDBG_INFO, "xnet_close: enter.");

    if (xnet == NULL)
    {
        xdbg_log(XDBG_ERR, "xnet_close: invalid input pointer !!");
        return FALSE;
    }

    XNET_LOCK(xnet);

    if (xnet->xnet_initialized != TRUE || xnet->xnet_started != FALSE)
    {
        xdbg_log(XDBG_ERR, "xnet_close: xnet is not initialized or not stopyet !!");
        XNET_UNLOCK(xnet);
        return FALSE;
    }

    /*
     * remove allocated resources
     */

    /* remove timer */
    LL_FOREACH_SAFE(xnet->xtimer_running,p_timer,tmp_timer)
    {
        if (p_timer)
        {
            LL_DELETE(xnet->xtimer_running,p_timer);
            xmem_free(p_timer, sizeof(xtimer_s));
        }
    }
    
    /* remove socket */
    LL_FOREACH_SAFE(xnet->xsock_list,p_sock,tmp_sock)
    {
        if (p_sock)
        {
            LL_DELETE(xnet->xsock_list,p_sock);
            xmem_free(p_sock, sizeof(xsocket_s));
        }
    }

    xnet->xnet_initialized = FALSE;

    XNET_UNLOCK(xnet);

    /* destroy mutex */
    pthread_mutex_destroy(&xnet->xnet_lock);

    /* free memory */
    xmem_free(xnet, sizeof(xnet_s));

    xdbg_log(XDBG_INFO, "xnet_close: completed.");

    return TRUE;
}

BOOLEAN xnet_set_def_timer(xnet_s *xnet, void (*def_timer)(xnet_s *, void *), 
    void *param, uint32_t def_timeout)
{
    if (xnet == NULL)
    {
        xdbg_log(XDBG_ERR, "xnet_set_def_timer: invalid input pointer !!");
        return FALSE;
    }

    XNET_LOCK(xnet);

    xnet->def_timer = def_timer;
    xnet->def_timer_param = param;
    xnet->def_timeout = def_timeout;

    XNET_UNLOCK(xnet);

    return TRUE;    
}

BOOLEAN xnet_wait(xnet_s *xnet)
{
    if (xnet == NULL)
        return FALSE;
    
    if (xnet->xnet_started != TRUE || xnet->xnet_running != TRUE)
        return FALSE;
    
    xdbg_log(XDBG_INFO, "xnet_wait: wait xnet thread terminated ...");
    
    xnet->xnet_wait = TRUE;
    
    if (pthread_join(xnet->xnet_tid, NULL) != 0)
        return FALSE;
    
    XNET_LOCK(xnet);
    xnet->xnet_tid = 0;
    XNET_UNLOCK(xnet);
    
    xdbg_log(XDBG_INFO, "xnet_wait: wait xnet thread - done.");
    
    return TRUE;    
}

xtimer_s *xnet_add_timer(xnet_s *xnet, uint32_t interval,
                         BOOLEAN (*cb)(xtimer_s *, void *), void *param,
                         BOOLEAN run_flag)
{
    struct xnet_timer *p_timer;

    xdbg_log(XDBG_DEBUG, "xnet_add_timer: enter.");

    if (cb == NULL || interval == 0)
    {
        xdbg_log(XDBG_ERR, "xnet_add_timer: invalid callback or interval !!");
        return NULL;
    }

    if (xnet->xnet_initialized != TRUE)
    {
        xdbg_log(XDBG_ERR, "xnet_add_timer: xnet is not initialized yet !!");
        return NULL;
    }

    if ((p_timer = (struct xnet_timer *) xmem_malloc(sizeof(*p_timer))) == NULL)
    {
        perror("xmem_alloc");
        return NULL;
    }

    memset(p_timer, 0, sizeof(*p_timer));

    XNET_LOCK(xnet);

    p_timer->xnet_handler = xnet;
    p_timer->xtimer_handler = p_timer;
    p_timer->creator = pthread_self();
    /*p_timer->type = type; */
    p_timer->interval = interval;
    p_timer->tmr_cb = cb;
    p_timer->param = (char *)param;
    /*p_timer->count = count; */
    p_timer->started = run_flag;

    LL_APPEND(xnet->xtimer_running, p_timer);

    xdbg_log(XDBG_DEBUG, "xnet_add_timer: done.");

    XNET_UNLOCK(xnet);

    return p_timer;
}

BOOLEAN xnet_start_timer(xtimer_s *timer_handler)
{
    xnet_s *xnet;
    struct xnet_timer *p_timer = timer_handler;
    BOOLEAN retval = FALSE;

    if (p_timer == NULL)
    {
        xdbg_log(XDBG_ERR, "xnet_start_timer: invalid input pointer !!");
        return FALSE;
    }

    xnet = p_timer->xnet_handler;
    if (xnet == NULL)
    {
        xdbg_log(XDBG_ERR, "xnet_start_timer: invalid input pointer !!");
        return FALSE;
    }

    XNET_LOCK(xnet);

    if (xnet->xnet_initialized != TRUE)
    {
        xdbg_log(XDBG_ERR, "xnet_start_timer: xnet is not initialized yet !!");
        retval = FALSE;
    }

    if (timer_handler->started == TRUE)
    {
        xdbg_log(XDBG_INFO, "xnet_start_timer: timer is already stared.");
        retval = TRUE;
    }

    LL_SEARCH_SCALAR(xnet->xtimer_running, p_timer, xtimer_handler, timer_handler);
    if (p_timer)
    {
        p_timer->started = TRUE;

        /* set start time */
        gettimeofday(&timer_handler->base_time, NULL);

        retval = TRUE;
    }
    else
    {
        xdbg_log(XDBG_ERR, "xnet_start_timer: timer is not added !!");
    }

    XNET_UNLOCK(xnet);

    return retval;
}

BOOLEAN xnet_stop_timer(xtimer_s *timer_handler)
{
    xnet_s *xnet = NULL;
    struct xnet_timer *p_timer = timer_handler;
    BOOLEAN retval = TRUE;

    if (p_timer == NULL)
    {
        xdbg_log(XDBG_ERR, "xnet_stop_timer: invalid input pointer !!");
        return FALSE;
    }

    xnet = p_timer->xnet_handler;

    XNET_LOCK(xnet);

    if (xnet->xnet_initialized != TRUE)
    {
        xdbg_log(XDBG_ERR, "xnet_stop_timer: xnet is not initialized yet !!");
        retval = FALSE;
    }

    if (timer_handler->started != TRUE)
    {
        xdbg_log(XDBG_INFO, "xnet_stop_timer: timer is already stopped");
        retval = FALSE;
    }

    /*memset(&timer_handler->base_time, 0, sizeof(struct timeval)); */
    LL_SEARCH_SCALAR(xnet->xtimer_running, p_timer, xtimer_handler, timer_handler);
    if (p_timer)
    {
        p_timer->started = FALSE;
        retval = FALSE;
    }
    else
    {
        xdbg_log(XDBG_ERR, "xnet_start_timer: timer is not added !!");
    }

    XNET_UNLOCK(xnet);

    return retval;
}

BOOLEAN xnet_check_timer(xtimer_s *timer_handler)
{
    if (timer_handler == NULL)
    {
        xdbg_log(XDBG_ERR, "xnet_check_timer: invalid input pointer !!");
        return FALSE;
    }

    return timer_handler->started;
}

BOOLEAN xnet_remove_timer(xtimer_s *timer_handler)
{
    xnet_s *xnet = NULL;
    struct xnet_timer *p_timer = timer_handler;
    BOOLEAN retval ;

    xdbg_log(XDBG_DEBUG, "xnet_remove_timer: enter");

    if (p_timer == NULL || p_timer->xnet_handler == NULL)
    {
        xdbg_log(XDBG_ERR, "xnet_remove_timer: invalid input pointer !!");
        return FALSE;
    }

    xnet = p_timer->xnet_handler;
    
    XNET_LOCK(xnet);

    if (xnet->xnet_initialized != TRUE)
    {
        xdbg_log(XDBG_ERR, "xnet_remove_timer: xnet is not initialized yet !!");
        XNET_UNLOCK(xnet);
        return FALSE;
    }

    LL_SEARCH_SCALAR(xnet->xtimer_running, p_timer, xtimer_handler, timer_handler);
    if (p_timer)
    {
        LL_DELETE(xnet->xtimer_running, p_timer);
        xmem_free(p_timer, sizeof(struct xnet_timer));
        retval = TRUE;
    }
    else
    {
        xdbg_log(XDBG_ERR, "xnet_remove_timer: timer is not added !!");
        retval = FALSE;
    }

    xdbg_log(XDBG_DEBUG, "xnet_remove_timer: done.");

    XNET_UNLOCK(xnet);

    return retval;
}

/* network io */
xsocket_s *xnet_add_socket(xnet_s *xnet, 
    int sockfd, BOOLEAN (*cb)(void *xnet, int, void *), void *param)
{
    struct xnet_socket *p_sock = NULL;

    if (cb == NULL)
    {
        xdbg_log(XDBG_ERR, "xnet_add_socket: invalid callback or interval !!");
        return NULL;
    }

    if ((p_sock = (struct xnet_socket *) xmem_malloc(sizeof(*p_sock))) == NULL)
    {
        perror("xmem_alloc");
        return NULL;
    }

    XNET_LOCK(xnet);

    p_sock->xnet_handler = xnet;
    p_sock->creator = pthread_self();
    p_sock->sockfd = sockfd;
    p_sock->sock_cb = cb;
    p_sock->param = (char *)param;

    LL_APPEND(xnet->xsock_list, p_sock);

    XNET_UNLOCK(xnet);

    return p_sock;
}

BOOLEAN xnet_remove_socket(xsocket_s *p_sock)
{
    xnet_s *xnet;

    if (p_sock == NULL || p_sock->xnet_handler == NULL)
        return FALSE;

    xnet = p_sock->xnet_handler;
    
    XNET_LOCK(xnet);

    LL_DELETE(xnet->xsock_list, p_sock);
    xmem_free(p_sock, sizeof(struct xnet_socket));

    XNET_UNLOCK(xnet);

    return TRUE;
}


