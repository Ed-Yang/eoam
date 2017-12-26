/**
 * @file xutl_net.h
 * @Author Edward Yang edwardyangyang@hotmail.com
 *
 * A networked socket library provides network I/O and timer funtions with a
 * POSIX thread.
 *
 * This library support re-entrance.  A Application can create multiple xnet
 * entities (each with one POSIX thread) as needed.
 *
 * @defgroup XNET socket I/O and timer library
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h> /* sleep */
#include "xutl_defs.h"
#include "xutl_dbg.h"

#ifndef __XUTL_NET_H
#define __XUTL_NET_H

#ifdef __cplusplus
extern "C" {
#endif

/** @{ */

#ifndef XNET_DEF_WAIT_MSEC
#define XNET_DEF_WAIT_MSEC  100 /** the wake up msec of xnet thread if no timer is active */
#endif

/* timer */
typedef struct xnet_timer xtimer_s;

/* socket */
typedef struct xnet_socket xsocket_s;

/* xnet */
typedef struct xnet_session xnet_s;

int xnet_time_diff(struct timeval *t1, struct timeval *t2);

/**
 * @brief initialize the xnet library, it is needed to call onece and only once
 *        before use xnet library.
 *
 * @param init function will be called before go into thread loop
 *
 * @retval TRUE   Success
 * @retval FALSE  Failed to init xnet, try to enable debug message and check.
 *
 * Example Usage:
 * @includelineno
 * @code
 *    xnet_open(usr_init);
 * @endcode
 */
xnet_s *xnet_open(void (*usr_init)(void *xnet, void *), void *param);

/**
 * @brief start the xnet thread to the resgistered io and timer functions
 *
 * @param xnet  handler return by invoking xnet_open
 * @param def_timeout the timeout value of default timer in msec, 0 will apply
 *       XNET_DEF_WAIT_MSEC 
 *
 */
BOOLEAN xnet_start(xnet_s *xnet, void (*usr_timer)(xnet_s *, void *), 
    void *param, uint32_t def_timeout);

/**
 * @brief stop the xnet thread 
 *
 * @param xnet  handler return by invoking xnet_open
 *
 * @retval TRUE Success
 * @retval FALSE invalid xnet handler
 *
 */
BOOLEAN xnet_stop(xnet_s *xnet);

/**
 * @brief free xnet allocated resources
 *
 * @param xnet  handler return by invoking xnet_open
 *
 * @retval TRUE Success
 * @retval FALSE invalid xnet handler
 *
 */
BOOLEAN xnet_close(xnet_s *xnet);

/**
 * @brief chagge the default xnet timer and parameters
 * 
 * @param def_timer 
 * @param param 
 * @param def_timeout 
 * @return BOOLEAN 
 */
BOOLEAN xnet_set_def_timer(xnet_s *xnet, void (*def_timer)(xnet_s *, void *), 
    void *param, uint32_t def_timeout);

/**
 * @brief wait xnet thread exit
 *
 * @param xnet  handler return by invoking xnet_open
 *
 * @retval TRUE Success
 * @retval FALSE invalid xnet handler
 *
 */
BOOLEAN xnet_wait(xnet_s *xnet);

/* timer */

/**
 * @brief add a xnet timer callback
 *
 * @param xnet  handler return by invoking xnet_open
 * @param interval timeout in miniseconds
 * @param cb timer callback function
 * @param param parameter to call the timer callback
 * @param count the times of invoking the counting timer
 * @start_flag start the timer after adding
 *
 * @return xnet timer handler or NULL on failure
 *
 * @comment while the cb fucntion return FALSE, it will stop the timer
 */
xtimer_s *xnet_add_timer(xnet_s *xnet, uint32_t interval,
                         BOOLEAN (*tmr_cb)(xtimer_s *, void *),
                         void *param, BOOLEAN run_flag);
/**
 * @brief remove xtimer
 *
 * @param xnet  handler return by invoking xnet_open
 * @param timer_handler handler return by invoking xnet_add_timer
 *
 *
 */
BOOLEAN xnet_remove_timer(xtimer_s *timer_handler);

/**
 * @brief start running a added timer
 *
 * @param xnet  handler return by invoking xnet_open
 * @param timer_handler handler return by invoking xnet_add_timer
 *
 *
 */
BOOLEAN xnet_start_timer(xtimer_s *timer_handler);

/**
 * @brief stop a running timer
 *
 * @param xnet  handler return by invoking xnet_open
 * @param timer_handler handler return by invoking xnet_add_timer
 *
 *
 */
BOOLEAN xnet_stop_timer(xtimer_s *timer_handler);

/**
 * @brief inquery timer status
 *
 * @param xnet  handler return by invoking xnet_open
 * @param timer_handler handler return by invoking xnet_add_timer
 *
 *
 */
BOOLEAN xnet_check_timer(xtimer_s *timer_handler);

/* network io */

/**
 * @brief add socket I/O callback
 *
 * @param xnet  handler return by invoking xnet_open
 * @param sock_cb handler return by invoking xnet_add_timer
 * @param param user defined data will be carried as input parameter of callback
 *
 * @return a callback handler on sucess, else NULL
 *
 * sock_cb(void xnet, int sockfd, void *param)
 * @param xnet
 * The first argument of sock_cb is instened to define as void for module
 * decoupling.  For example, a application might utilize the XIPC but does not
 * use XNET, then it does not have to include XNET.
 * @param sockfd the socket
 * @param while event occurred, it is provided as input parameter to callback
 */
xsocket_s *xnet_add_socket(xnet_s *xnet, int sockfd,
                           BOOLEAN (*sock_cb)(void *xnet, int, void *), void *param);

/**
 * @brief remove socket I/O callback
 *
 * @param xnet  handler return by invoking xnet_open
 * @param socket_handler handler return by invoking xnet_add_socket
 *
 * @return TRUE for success, else failure
 *
 */
BOOLEAN xnet_remove_socket(xsocket_s *socket_handler);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* __XUTL_NET_H */
