/**
 * @file xutl_ipc.h
 * @Author Edward Yang edwardyangyang@hotmail.com
 *
 * Provide a reliable commnucation mechanism between client and server application.
 * Application can easily implement the message exchange through a regisgred
 * callback for a specific message identified by op + mtype.
 *
 * @defgroup XIPC interprocess communication and message passing library
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> /* unlink */
#include <string.h>
#include <stdint.h>

#include "xutl_defs.h"

#ifndef __XUTL_IPC_H
#define __XUTL_IPC_H

#ifdef __cplusplus
extern "C" {
#endif

/** @{ */

#define XIPC_WAIT_MSEC      500 /** wait time while socket send or recieve is blocking */
#define XIPC_DEF_BACKLOG    10

#define XIPC_NO_ERROR       0 /* xipc_status_s */
#define XIPC_RSP_NO_ACK     -1
#define XIPC_RSP_ACK        0

typedef enum
{
    XIPC_STREAM = 1,
    XIPC_DGRAM,
} xipc_type_e;

typedef struct struct_xipc xipc_s;
typedef uint8_t xipc_msg_type_s;
typedef int32_t xipc_status_s;


#pragma pack( 1 )

typedef struct
{
    uint32_t value; /* user defined filed (ex. ifindex) */
    /* 4 */
    uint8_t op;
    xipc_msg_type_s mtype;
    /* NOTE, following a two bytes variable */
} xipc_hdr_s;

#pragma pack()

typedef xipc_status_s (xipc_exec_cb_s)(uint32_t value);
typedef xipc_status_s (xipc_data_cb_s)(void *param);
typedef xipc_status_s (xipc_group_cb_s)(xipc_s *, xipc_hdr_s *xhdr, void *data,
                                        size_t *size, void *param);

xipc_s *xipc_unix_server(xipc_type_e type, char *path, int backlog);
xipc_s *xipc_unix_client(xipc_type_e type, char *path);

#ifdef XIPC_NET /* FIXME:TODO */
xipc_s *xipc_sock_server(xipc_type_e type, char *local_ip, uint16_t local_port, int backlog);
xipc_s *xipc_sock_client(xipc_type_e type, char *remote_ip, uint16_t remote_port);
#endif

BOOLEAN xipc_close(xipc_s *xipc);

int xipc_get_fd(xipc_s *xipc); /* use for select, accept, xnet_add_socket, etc.. */

/* transasction api */

/* client */
BOOLEAN xipc_client_event(xipc_s *xipc, xipc_hdr_s *xhdr,
                          void *data, size_t dsize, xipc_status_s *status);

/**
 * @brief EXEC: OP <--> OP
 * 
 * @param xipc 
 * @param xhdr 
 * @param status 
 * @return BOOLEAN 
 */
BOOLEAN xipc_client_exec(xipc_s *xipc, xipc_hdr_s *xhdr, xipc_status_s *status);

/**
 * @brief PUT: OP + DATA <--> OP
 * 
 * @param xipc 
 * @param xhdr 
 * @param data 
 * @param dsize 
 * @param status 
 * @return BOOLEAN 
 */
BOOLEAN xipc_client_put(xipc_s *xipc, xipc_hdr_s *xhdr,
                        void *data, size_t dsize, xipc_status_s *status);

/**
 * @brief GET: OP <--> OP + DATA
 * 
 * @param xipc 
 * @param xhdr 
 * @param data 
 * @param dsize 
 * @param status 
 * @return BOOLEAN 
 */
BOOLEAN xipc_client_get(xipc_s *xipc, xipc_hdr_s *xhdr,
                        void *data, size_t dsize, xipc_status_s *status);

/**
 * @brief DATA: OP + DATA <--> OP + DATA
 * 
 * @param xipc 
 * @param xhdr 
 * @param data 
 * @param dsize 
 * @param status 
 * @return BOOLEAN 
 * 
 *  get item, getnext, 
 */
BOOLEAN xipc_client_data(xipc_s *xipc, xipc_hdr_s *xhdr,
                        void *data, size_t dsize, xipc_status_s *status);

BOOLEAN xipc_client_trans(xipc_s *xipc, xipc_hdr_s *xhdr,
                          void *data, size_t dsize, int rsp_size,
                          xipc_status_s *status);

/* server */
BOOLEAN xipc_set_exec_handler(xipc_s *xipc, xipc_hdr_s *xhdr,
                              xipc_exec_cb_s *exec_cb);

BOOLEAN xipc_set_data_handler(xipc_s *xipc, xipc_hdr_s *xhdr,
                              xipc_data_cb_s *data_cb, size_t dsize);

BOOLEAN xipc_set_group_handler(xipc_s *xipc, xipc_hdr_s *xhdr,
                               xipc_group_cb_s *group_cb, size_t dsize, void *param);

BOOLEAN xipc_process_trans(void *xnet, int sockfd, void *xipc);

BOOLEAN xipc_set_timeout(xipc_s *xipc, uint32_t msec);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* __EOAM_IPC_H */
