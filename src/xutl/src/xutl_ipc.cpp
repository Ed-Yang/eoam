#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> /* unlink */
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/un.h>

#include "xutl_dbg.h"
#include "xutl_mem.h"
#include "xutl_ipc.h"
#include "xutl_str.h"

#include "utlist.h"

#define XIPC_MAX_RETRIES    3

typedef enum
{
    XIPC_EXEC_HANDLER,
    XIPC_DATA_HANDLER,
    XIPC_GROUP_HANDLER
} xipc_handler_e ;

#pragma pack( 1 )

/**
 *
 * @param rsp_size the expected receive data size of sender
 * @param length the total lenght of message (including header)
 * @param the result filled after processing request
 */
typedef struct
{
    /* public header */
    xipc_hdr_s hdr;
    uint16_t rsp_total_size; /** 0, hdr_size, or hdr_size + dsize */
    /* internal data */
    uint16_t length;
    /* pad */
    uint8_t pad[2];
    xipc_status_s status_code;
} xipc_msg_hdr_s;

#pragma pack()

typedef struct xipc_trans
{
    xipc_hdr_s hdr;
    size_t dsize; /* if dsize is 0, ignore size check (ex. EVENT) */
    xipc_status_s (*xipc_group_cb)(xipc_s *, xipc_hdr_s *xhdr, void *, size_t *, void *);
    xipc_status_s (*xipc_data_cb)(void *);
    xipc_status_s (*xipc_exec_cb)(uint32_t);
    void *params;
    struct xipc_trans *next;
} xipc_trans_s;

/**
 * @brief
 * data structure for a XIPC session
 *
 */
struct struct_xipc
{
    int sockfd;
    int wait_msec;
    int retry_cnt;
    BOOLEAN is_server;
    pthread_mutex_t xipc_lock;
    pthread_t lock_tid;
    //BOOLEAN keep_conn;
    char xipc_path[XUTL_NAME_SIZE + 1];
    xipc_type_e sock_type;
    char data[sizeof(xipc_msg_hdr_s) + XUTL_FRAME_SIZE];
    xipc_trans_s *trans_list;
};

/*------------------------------------------------------------------------------
 * local API
 *------------------------------------------------------------------------------
 */
static void XIPC_LOCK(xipc_s *xipc)
{
    if (xipc->lock_tid != 0 && xipc->lock_tid == pthread_self())
    {
        xdbg_log(XDBG_ERR, "XIPC_LOCK: double locked  (0x%08x, 0x%08x) !!!",
            xipc->lock_tid, pthread_self());
    }

    pthread_mutex_lock(&xipc->xipc_lock);
    xipc->lock_tid = pthread_self();
}

static void XIPC_UNLOCK(xipc_s *xipc)
{
#if 0 /* lock, lock, unlock --> set to 0 */
    if (xipc->lock_tid != pthread_self())
    {
        xdbg_log(XDBG_ERR, "XIPC_UNLOCK: diff thread (0x%08x, 0x%08x) !!!",
            xipc->lock_tid, pthread_self());
    }
#endif

    xipc->lock_tid = 0;
    pthread_mutex_unlock(&xipc->xipc_lock);
}

/**
 * @brief
 *
 * @param t1
 * @param t2
 * @return int
 */
int _xipc_trans_cmp(xipc_trans_s *t1, xipc_trans_s *t2)
{
    uint32_t v1, v2;

    v1 = ((t1->hdr.op & 0xffff) << 16) | (t1->hdr.mtype & 0xffff);
    v2 = ((t2->hdr.op & 0xffff) << 16) | (t2->hdr.mtype & 0xffff);

    return (int) (v1 - v2);
}

int _xipc_send(int sockfd, const char *data, size_t size, int wait_time)
{
    int total = 0;
    ssize_t n;
    int retry_cnt = XIPC_MAX_RETRIES;
    struct timeval tv;
    uint8_t *packet = (uint8_t *)data;
    size_t len;

    tv.tv_sec = wait_time / 1000;
    tv.tv_usec = (wait_time % 1000) * 1000;

    xdbg_log(XDBG_DEBUG, "xipc_send: [%d bytes] %02x:%02x:%02x:%02x:%02x:%02x",
             size,
             packet[0],packet[1],packet[2],packet[3],packet[4],packet[5]);

    while (total < (int)size)
    {
        xdbg_log(XDBG_DEBUG, "xipc_send: try to send %d bytes ...", size - total);
        len = size - total ;
        if ((n = send(sockfd, (char *)&data[total], len, 0)) <= 0)
        {
            if (retry_cnt > 0 && errno == EWOULDBLOCK)
            {
                fd_set writefds;
                FD_ZERO(&writefds);
                FD_SET(sockfd, &writefds);

                /* no matter whatever return value, it has to wait */
                xdbg_log(XDBG_DEBUG, "xipc_send: wait to send (size = %d, now = %d)",
                         size, total);
                select(FD_SETSIZE, NULL, &writefds, NULL, &tv);
                /* test */
                retry_cnt--; /* decrease counter */
            }
            else
            {
                perror("\n_xipc_send:send");
                xdbg_log(XDBG_WARNING, "xipc_send: send failed (%d bytes)", size - total);
                return -1;
            }
        }

        total += n;
    }

    return total;
}

int _xipc_recv(int sockfd, uint8_t *data, size_t size, BOOLEAN partial, int wait_msec)
{
    int total = 0;
    ssize_t n;
    int retry_cnt = XIPC_MAX_RETRIES;
    struct timeval tv;

    tv.tv_sec = wait_msec / 1000;
    tv.tv_usec = (wait_msec % 1000) * 1000;

    while (total < (int)size)
    {
        xdbg_log(XDBG_DEBUG, "xipc_recv: try to recv [%3d]",size - total);
        if ((n = recv(sockfd, (char *)&data[total], size - total, 0)) <= 0)
        {
            if (retry_cnt > 0 && errno == EWOULDBLOCK)
            {
                fd_set readfds;
                FD_ZERO(&readfds);
                FD_SET(sockfd, &readfds);

                /* no matter whatever return value, it has to wait */
                xdbg_log(XDBG_DEBUG, "xipc_recv: wait to recv (size = %d, now = %d, tv %d, tv_usec %d)",
                         size, total, tv.tv_sec, tv.tv_usec);
                select(FD_SETSIZE, &readfds, NULL, NULL, &tv);
                retry_cnt--;
                n = 0;
            }
            else
            {
                /* perror("recv"); */
                xdbg_log(XDBG_DEBUG, "xipc_recv: recv failed (size = %d)", size);
                return -1;
            }
        }

        total += n;

        if (total > 0 && partial == TRUE)
            break;
    }

    xdbg_log(XDBG_DEBUG, "xipc_recv: [%3d] %02x:%02x:%02x:%02x:%02x:%02x",
             size,
             data[0],data[1],data[2],data[3],data[4],data[5],data[6]);

    return total;
}

/**
 * receive transaction message according to xipc sock_type
 *
 * @comment
 *  datagram: receive whole message
 *  stream: receive header + data
 */
static BOOLEAN _recv_trans_msg(xipc_s *xipc, int new_fd, uint8_t *p_msg, size_t msize)
{
    xipc_msg_hdr_s *p_msg_hdr;
    xipc_hdr_s *p_hdr;
    uint8_t *p_data;
    int n, rlen, dsize;

    p_hdr = (xipc_hdr_s *)p_msg;
    p_msg_hdr = (xipc_msg_hdr_s *)p_msg;

    p_data = (uint8_t *)p_msg + sizeof(xipc_msg_hdr_s);

    if (msize < sizeof(xipc_msg_hdr_s))
        return FALSE;

    if (xipc->sock_type == XIPC_DGRAM)
    {
        /* datagram */
        rlen = XUTL_FRAME_SIZE;
        /*partial = TRUE; */

        if ((n = _xipc_recv(new_fd, (uint8_t *)p_hdr, rlen, TRUE, xipc->wait_msec)) <= 0)
        {
            return FALSE;
        }
    }
    else
    {
        /* stream */
        rlen = sizeof(xipc_msg_hdr_s);
        /*partial = FALSE; */

        /* receive header */
        if ((n = _xipc_recv(new_fd, (uint8_t *)p_hdr, rlen, FALSE, xipc->wait_msec)) <= 0)
        {
            return FALSE;
        }

        /* check size of input buffer */
        if (msize < p_msg_hdr->length)
            return FALSE;

        dsize = p_msg_hdr->length - sizeof(xipc_msg_hdr_s);

        /* stream: receive data porton */
        if (dsize > 0 && (n = _xipc_recv(new_fd, p_data, dsize, FALSE, xipc->wait_msec)) <= 0)
        {
            return FALSE;
        }
    }

    return TRUE;
}

static xipc_s *_allocate_socket(xipc_type_e sock_type, char *xipc_path)
{
    xipc_s *xipc;

    if ( (xipc = (xipc_s *)xmem_malloc(sizeof(xipc_s))) == NULL)
    {
        xdbg_log(XDBG_ERR, "allocate_socket: cannot allocate memory (size %d) !!",
                 sizeof(xipc_s));
        return NULL;
    }

    memset((char *)xipc, 0xcc, sizeof(xipc_s));

    if (sock_type != XIPC_STREAM && sock_type != XIPC_DGRAM)
    {
        xdbg_log(XDBG_ERR, "allocate_socket: invalid type !!",
                 sizeof(xipc_s));
        xmem_free(xipc, sizeof(xipc_s));
        return NULL;
    }

    if (xipc_path == NULL)
    {
        xdbg_log(XDBG_ERR, "allocate_socket: null path !!");
        xmem_free(xipc, sizeof(xipc_s));
        return NULL;
    }

    if (strlen(xipc_path) > XUTL_NAME_SIZE)
    {
        xdbg_log(XDBG_ERR, "allocate_socket: name too long !!");
        xmem_free(xipc, sizeof(xipc_s));
        return NULL;
    }

    pthread_mutex_init(&xipc->xipc_lock, NULL);
    strcpy(xipc->xipc_path, xipc_path);
    xipc->trans_list = NULL;
    xipc->sock_type = sock_type;
    xipc->wait_msec = XIPC_WAIT_MSEC;

    return xipc;
}

static int _xipc_set_blocking(int sockfd, BOOLEAN blocking)
{
    BOOLEAN retval;

    if (sockfd <= 0)
        return FALSE;

#ifdef _WIN32
    unsigned long mode = blocking ? 0 : 1;
    return (ioctlsocket(fd, FIONBIO, &mode) == 0) ? TRUE : FALSE;
#else
    int flags = fcntl(sockfd, F_GETFL, 0);

    if (flags < 0)
        return FALSE;

    flags = blocking ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
    retval = (fcntl(sockfd, F_SETFL, flags) == 0) ? TRUE : FALSE;

    return retval;
#endif
}

static BOOLEAN _xipc_socket(xipc_s *xipc)
{
    int conn_type = SOCK_STREAM;
    BOOLEAN retval = TRUE;

    if (xipc == NULL)
        return FALSE;

    if (xipc->sock_type == XIPC_DGRAM)
        conn_type = SOCK_DGRAM;

    xipc->sockfd = socket(AF_UNIX, conn_type, 0);
    if (xipc->sockfd <= 0)
    {
        xdbg_log(XDBG_ERR, "xipc_socket: socket error !!");
        perror("socket");
        /* xmem_free(xipc, sizeof(xipc_s)); */
        retval = FALSE;
    }
    else
    {
        _xipc_set_blocking(xipc->sockfd, FALSE);
    }

    return retval;
}

static BOOLEAN _xipc_clnt_connect(xipc_s *xipc)
{
    struct sockaddr_un addr;
    int rv;

    if (xipc == NULL)
        return FALSE;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, xipc->xipc_path); /* sun_path is 108 bytes */

    rv = connect(xipc->sockfd, (struct sockaddr *)&addr, sizeof(addr));
    if (rv < 0)
    {
        xdbg_log(XDBG_ERR, "xipc_clnt_connect: socket error (errno = %d) !!!", errno);
        perror("\nconnect");
        xdbg_log(XDBG_ERR, "check whether file is open with higher privilege before !!!");
        return FALSE;
    }

    return TRUE;
}

/**
 * _xipc_reopen
 * 
 * after transaction is done, if connection is stream type, close old and
 * create a new socket
 * 
 * @param xipc 
 * @return BOOLEAN 
 */
static BOOLEAN _xipc_reopen(xipc_s *xipc)
{
    BOOLEAN retval = TRUE;
    int old_sockfd;

    if (xipc == NULL)
        return FALSE;

    /* open and then clsoe to avoid re-use the same sock id */
    if (xipc->sock_type == XIPC_STREAM)
    {
        // save old sockfd
        old_sockfd = xipc->sockfd;
        
        retval = _xipc_socket(xipc);
        
        if (old_sockfd > 0)
        {
            close(old_sockfd);
        }
    }

    return retval;
}

/**
 * _xipc_client_trans
 *
 * @dsize data size
 * @rsp_data_size expected response data size.  XIPC_RSP_NO_ACK, XIPC_RSP_ACK or n bytes
 * @param status
 *
 * @comment:
 *
 * snd_size = sizeof(xipc_msg_hdr_s) + dsize
 * rsp_total_size = (rsp_data_size >= 0) ? sizeof(xipc_msg_hdr_s) + rsp_data_size: 0
 *
 */
static BOOLEAN _xipc_client_trans(xipc_s *xipc, xipc_hdr_s *xhdr, void *data, 
    size_t dsize, int rsp_data_size, xipc_status_s *status)
{
    xipc_hdr_s *p_hdr;
    xipc_msg_hdr_s *p_msg_hdr;
    size_t rsp_total_size;
    size_t snd_size;
    char *p_data;

    if (xipc == NULL)
        return FALSE;

    xdbg_log(XDBG_DEBUG, "client: trans op = %d, mtype = %d dsize = %d rsp_data_size = %d",
             xhdr->op, xhdr->mtype, dsize, rsp_data_size);

    /* check request data size */
    if ((sizeof(xipc_msg_hdr_s) + dsize) > sizeof(xipc->data))
    {
        xdbg_log(XDBG_WARNING, "client: trans op = %d, mtype = %d dsize = %d sending buffer limit !!",
                 xhdr->op, xhdr->mtype, dsize);
        return FALSE;
    }

    if (rsp_data_size > 0 && (sizeof(xipc_msg_hdr_s) + rsp_data_size) > sizeof(xipc->data))
    {
        xdbg_log(XDBG_WARNING, "client: trans op = %d, mtype = %d rsp_data_size = %d rx buffer limit !!",
                 xhdr->op, xhdr->mtype, rsp_data_size);
        return FALSE;
    }

    if (xipc->sock_type == XIPC_STREAM)
    {
        if (_xipc_clnt_connect(xipc) != TRUE)
        {
            xdbg_log(XDBG_ERR, "xipc_client_trans: xipc_clnt_connect error %d !!", errno);
            _xipc_reopen(xipc);
            return FALSE;
        }
    }

    /* init data buffer to all zero */
    memset(xipc->data, 0, sizeof(xipc->data));

    p_hdr = (xipc_hdr_s *) xipc->data;
    p_msg_hdr = (xipc_msg_hdr_s *) xipc->data;
    p_data = (char *)(p_msg_hdr + 1);

    /* copy header */
    memcpy(p_hdr, xhdr, sizeof(xipc_hdr_s)); /* op + mtype */

    if (data != NULL)
        p_msg_hdr->length = sizeof(xipc_msg_hdr_s) + dsize;
    else
        p_msg_hdr->length = sizeof(xipc_msg_hdr_s);

    if (data != NULL && dsize > 0)
        memcpy(p_data, data, dsize);

    /* send size (include header) */
    snd_size = dsize + sizeof(xipc_msg_hdr_s);

    /* rsp size, this is the total bytes the client expects the server to respond */
    if (rsp_data_size >= 0)
    {
        /* note, for get op, dsize is 0 */
        rsp_total_size = sizeof(xipc_msg_hdr_s) + rsp_data_size;
    }
    else
    {
        rsp_total_size = 0;
    }
    p_msg_hdr->rsp_total_size = rsp_total_size;

    /* 
     * with datagram type, the whole message is pacaked into one packet, the
     * receiver have to also receive in one recv function 
     * */
    xdbg_log(XDBG_DEBUG, "client: send request size = %d", snd_size);
    if (_xipc_send(xipc->sockfd, (char *)p_hdr, snd_size, xipc->wait_msec) <= 0)
    {
        xdbg_log(XDBG_ERR, "xipc_client_trans: xipc_send error %d !!", errno);
        _xipc_reopen(xipc);
        return FALSE;
    }

    /* recv */
    if (rsp_total_size > 0)
    {
        xdbg_log(XDBG_DEBUG, "client: wait rsp op = %d, mtype = %d dsize = %d rsp_total_size = %d",
                 xhdr->op, xhdr->mtype, dsize, rsp_total_size);

        if (_recv_trans_msg(xipc, xipc->sockfd, (uint8_t *)p_hdr, rsp_total_size) == FALSE)
        {
            xdbg_log(XDBG_WARNING, "xipc_client_trans: recv_trans_msg error %d !!", errno);
            _xipc_reopen(xipc);
            return FALSE;
        }

        /* copy return header value */
        if (p_msg_hdr->status_code == XIPC_NO_ERROR)
            xhdr->value = p_msg_hdr->hdr.value;

        /* if appplication pass in rsp_data_size > 0 and result is success, copy return data */
        if (rsp_data_size > 0 && p_msg_hdr->status_code == XIPC_NO_ERROR)
        {
            /* copy return data */
            if (data)
            {
                memcpy(data, (uint8_t *)(p_msg_hdr + 1), rsp_data_size);
#ifdef XIPC_DUMP
                xstr_dump((uint8_t *)data, rsp_data_size, 32); 
#endif
            }
        }

        *status = p_msg_hdr->status_code;     /* FIXME */
    }
    else
    {
        /* no response, set to success */
        *status = XIPC_NO_ERROR;
    }

    if (xipc->sock_type == XIPC_STREAM)
    {
        xdbg_log(XDBG_DEBUG, "client: reopen conn op = %d, mtype = %d dsize = %d rsp_data_size = %d",
                 xhdr->op, xhdr->mtype, dsize, rsp_data_size);

        /* re-open socket */
        if (_xipc_reopen(xipc) != TRUE)
        {
            xdbg_log(XDBG_ERR, "xipc_client_trans: xipc_reopen error %d !!", errno);
            return FALSE;
        }
    }

    return TRUE;
}

static BOOLEAN _xipc_process_trans(void *xnet, int sockfd, void *xipc_in)
{
    xipc_s *xipc = (xipc_s *) xipc_in;
    xipc_hdr_s *p_hdr;
    xipc_msg_hdr_s *p_msg_hdr;
    xipc_trans_s *trans;
    xipc_trans_s tmp_trans;
    uint8_t *p_data;
    int new_fd;
    socklen_t addrlen;
    struct sockaddr_un remote;
    size_t dsize;
    int n, rlen;
    BOOLEAN partial;

    if (xnet == NULL || xipc_in == NULL || sockfd == 0)
        return FALSE;

    if (xipc->sock_type != XIPC_STREAM && xipc->sock_type != XIPC_DGRAM)
        return FALSE;

    if (xipc->sock_type == XIPC_STREAM)
    {
        addrlen = sizeof(remote);
        if ((new_fd = accept(xipc->sockfd, (struct sockaddr *)&remote, &addrlen)) < 0)
        {
            perror("accept");
            return -1;
        }
        _xipc_set_blocking(new_fd, FALSE);
    }
    else
    {
        new_fd = xipc->sockfd;
    }

    /* 
     * datagram: receive whole message
     * stream: receive header + data 
     * */
    p_hdr = (xipc_hdr_s *)xipc->data;
    p_msg_hdr = (xipc_msg_hdr_s *)xipc->data;
    p_data = (uint8_t *)xipc->data + sizeof(xipc_msg_hdr_s);

    if (xipc->sock_type == XIPC_DGRAM)
    {
        rlen = XUTL_FRAME_SIZE;
        partial = TRUE;
    }
    else
    {
        rlen = sizeof(xipc_msg_hdr_s);
        partial = FALSE;
    }

    if ((n = _xipc_recv(new_fd, (uint8_t *)p_hdr, rlen, partial, xipc->wait_msec)) <= 0)
    {
        xdbg_log(XDBG_ERR, "xipc_process_trans: cannot recv message header (rlen = %d, partial = %d) !!!", rlen, partial);

        return FALSE;
    }

    xdbg_log(XDBG_DEBUG, "xipc_process_trans: rx header (op = %d, mtype = %d) dsize = %d, n = %d",
             p_hdr->op, p_hdr->mtype, rlen, n);

    memset(&tmp_trans, 0, sizeof(tmp_trans)); /* clear memory to supress uninit mem err */
    tmp_trans.hdr.op = (uint8_t)p_hdr->op;
    tmp_trans.hdr.mtype = p_hdr->mtype;

    LL_SEARCH(xipc->trans_list, trans, &tmp_trans, _xipc_trans_cmp);

    if (trans == NULL || 
        (trans->xipc_exec_cb == NULL && trans->xipc_data_cb == NULL && trans->xipc_group_cb == NULL))
    {
        xdbg_log(XDBG_ERR, "xipc_process_trans: msg is not registerd (op = %d, mtype = %d) !!!",
                 p_hdr->op, p_hdr->mtype);
        if (xipc->sock_type == XIPC_STREAM)
        {
            close(new_fd);
        }
        return FALSE;
    }
    
    dsize = p_msg_hdr->length - sizeof(xipc_msg_hdr_s);

    if (trans->dsize > 0 && dsize != trans->dsize)
    {
        xdbg_log(XDBG_ERR, "xipc_process_trans: size mismatch (dsize = %d, trans->dsize = %d) !!!",
                 dsize, trans->dsize);
        if (xipc->sock_type == XIPC_STREAM)
        {
            close(new_fd);
        }
        return FALSE;
    }

    /* stream: receive data porton */
    if (xipc->sock_type == XIPC_STREAM)
    {
        if (dsize > 0 && (n = _xipc_recv(new_fd, p_data, dsize, FALSE, xipc->wait_msec)) <= 0)
        {
            xdbg_log(XDBG_ERR, "xipc_process_trans: cannot recv data (dsize = %d, hdr->dsize = %d) !!!",
                     dsize, trans->dsize);

            close(new_fd);
            return FALSE;
        }

        xdbg_log(XDBG_TRACE, "xipc_process_trans: rx data (op = %d, mtype = %d) dsize = %d n = %d",
                 p_hdr->op, p_hdr->mtype, dsize, n);
    }

    trans->hdr.value = p_hdr->value;  /* copy input value */

    /* invoke exec cb */
    if (trans->xipc_exec_cb)
    {
        uint32_t value = p_msg_hdr->hdr.value;
        p_msg_hdr->status_code = (trans->xipc_exec_cb)(value);
        if (p_msg_hdr->status_code == XIPC_NO_ERROR)
            p_msg_hdr->hdr.value = value;
    }

    /* invoke data cb */
    if (trans->xipc_data_cb)
    {
        p_msg_hdr->status_code = (trans->xipc_data_cb)(p_data);
    }

    /* invoke group cb */
    if (trans->xipc_group_cb)
    {
        p_msg_hdr->status_code = (trans->xipc_group_cb)(xipc, &trans->hdr, p_data, &dsize, trans->params);
        if (p_msg_hdr->status_code == XIPC_NO_ERROR)
            p_msg_hdr->hdr.value = trans->hdr.value; /* FIXME:group copy return value */
    }

    /* check return data size */
    if (xipc->sock_type != XIPC_DGRAM && (trans->dsize && dsize != trans->dsize))
    {
        xdbg_log(XDBG_ERR, "xipc_process_trans: data size is not matched with declaring (reg:%d, now:%d)"
                 ,trans->dsize, dsize);
        if (xipc->sock_type == XIPC_STREAM)
        {
            /* FIXME: persistent connection */
            close(new_fd);
        }
        return FALSE;
    }

    /* send response. no matter success or failure, send the requested size of data to client */
    if (xipc->sock_type == XIPC_STREAM && p_msg_hdr->rsp_total_size > 0)
    {
        xdbg_log(XDBG_TRACE, "server: send reponse (rsp_size = %d)", p_msg_hdr->rsp_total_size);

#ifdef XIPC_DUMP
        xstr_dump((uint8_t *)p_hdr, p_msg_hdr->rsp_total_size, 32);
#endif

        p_msg_hdr->length = p_msg_hdr->rsp_total_size;
        if (_xipc_send(new_fd, (char *)p_hdr, p_msg_hdr->rsp_total_size, xipc->wait_msec) <= 0)
        {
            perror("send");
            xdbg_log(XDBG_WARNING, "xipc_process_trans: cannot send reponse (hdr + dsize %d) errno = %d"
                     ,dsize, errno);
            if (xipc->sock_type == XIPC_STREAM)
            {
                if (close(new_fd) != 0)
                    perror("close");
            }
            return FALSE;
        }
    }

    if (xipc->sock_type == XIPC_STREAM)
    {
        /*sleep(1); */
        close(new_fd);
    }

    return TRUE;

} /* _xipc_process_trans */

/*------------------------------------------------------------------------------
 * common external API
 *------------------------------------------------------------------------------
 */
int xipc_get_fd(xipc_s *xipc)
{
    int sockfd;

    if (xipc == NULL)
        return -1;

    XIPC_LOCK((xipc_s *)xipc);

    sockfd = xipc->sockfd;

    XIPC_UNLOCK((xipc_s *)xipc);

    return sockfd;
}

BOOLEAN xipc_close(xipc_s *xipc)
{
    xipc_trans_s *p_trans, *tmp_trans;

    if (xipc == NULL)
        return FALSE;

    XIPC_LOCK((xipc_s *)xipc);

    /* free trans */
    LL_FOREACH_SAFE(xipc->trans_list, p_trans, tmp_trans)
    {
        LL_DELETE(xipc->trans_list, p_trans);
        xmem_free(p_trans, sizeof(xipc_trans_s));
    }

    /* free xipc */
    if (xipc->sockfd)
        close(xipc->sockfd);

    /* unlock and then free */
    XIPC_UNLOCK((xipc_s *)xipc);
    
    xmem_free(xipc, sizeof(xipc_s));

    return TRUE;
}

/*------------------------------------------------------------------------------
 * client external API
 *------------------------------------------------------------------------------
 */
xipc_s *xipc_unix_client(xipc_type_e type, char *xipc_path)
{
    xipc_s *xipc = NULL;

    if (xipc_path)
        xdbg_log(XDBG_DEBUG, "xipc_unix_client: sock file path - %s", xipc_path);

    if ((xipc = _allocate_socket(type, xipc_path)) == NULL)
        return NULL;

    if (_xipc_socket(xipc) != TRUE)
    {
        xmem_free(xipc, sizeof(xipc_s));
        return NULL;
    }

    /* 
     * if connection is connectionless, connect to server immediately, or connect
     * to server on each transaction.
     */
    if (type == XIPC_DGRAM)
    {
        if (_xipc_clnt_connect(xipc) != TRUE)
        {
            xdbg_log(XDBG_ERR, "xipc_client: xipc_clnt_connect error %d !!", errno);
            xipc_close(xipc);
            xipc = NULL;
        }
    }

    return xipc;
}

/**
 * @brief
 *
 * @param xipc
 * @param xhdr
 * @param data
 * @param dsize
 * @param status
 * @return BOOLEAN
 */
BOOLEAN xipc_client_event(xipc_s *xipc, xipc_hdr_s *xhdr,
                          void *data, size_t dsize, xipc_status_s *status)
{
    BOOLEAN retval;

    if (xipc == NULL)
        return FALSE;

    XIPC_LOCK(xipc);

    retval = _xipc_client_trans(xipc, xhdr, data, dsize, XIPC_RSP_NO_ACK, status);

    XIPC_UNLOCK(xipc);

    return retval;
}

/**
 * @brief EXEC: OP <--> OP
 *
 * @param xipc
 * @param xhdr
 * @param status
 * @return BOOLEAN
 */
BOOLEAN xipc_client_exec(xipc_s *xipc, xipc_hdr_s *xhdr, xipc_status_s *status)
{
    BOOLEAN retval;
    
    if (xipc == NULL)
        return FALSE;

    XIPC_LOCK(xipc);

    if (xipc->sock_type == XIPC_STREAM)
        retval = _xipc_client_trans(xipc, xhdr, NULL, 0, XIPC_RSP_ACK, status);
    else
        retval = _xipc_client_trans(xipc, xhdr, NULL, 0, XIPC_RSP_NO_ACK, status);

    XIPC_UNLOCK(xipc);

    return retval;
}

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
                        void *data, size_t dsize, xipc_status_s *status)
{
    BOOLEAN retval;

    if (xipc == NULL)
        return FALSE;

    XIPC_LOCK(xipc);

    if (xipc->sock_type == XIPC_STREAM)
        retval = _xipc_client_trans(xipc, xhdr, data, dsize, XIPC_RSP_ACK, status);
    else
        retval = _xipc_client_trans(xipc, xhdr, data, dsize, XIPC_RSP_NO_ACK, status);

    XIPC_UNLOCK(xipc);

    return retval;
}

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
                        void *data, size_t dsize, xipc_status_s *status)
{
    BOOLEAN retval;
 
    if (xipc == NULL)
        return FALSE;

    if (xipc->sock_type != XIPC_STREAM)
        return FALSE;

    XIPC_LOCK(xipc);

    retval = _xipc_client_trans(xipc, xhdr, data, 0, (int)dsize, status);

    XIPC_UNLOCK(xipc);

    return retval;
}

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
                         void *data, size_t dsize, xipc_status_s *status)
{
    BOOLEAN retval;

    if (xipc == NULL)
        return FALSE;

    if (xipc->sock_type != XIPC_STREAM)
        return FALSE;

    XIPC_LOCK(xipc);

    retval = _xipc_client_trans(xipc, xhdr, data, dsize, (int)dsize, status);

    XIPC_UNLOCK(xipc);

    return retval;
}

BOOLEAN xipc_client_trans(xipc_s *xipc, xipc_hdr_s *xhdr, void *data, 
    size_t dsize, int rsp_data_size, xipc_status_s *status)
{
    BOOLEAN retval;

    XIPC_LOCK(xipc);

    retval = _xipc_client_trans(xipc, xhdr, data, dsize, rsp_data_size, status);

    XIPC_UNLOCK(xipc);

    return retval;
}

/*------------------------------------------------------------------------------
 * server external API
 *------------------------------------------------------------------------------
 */
xipc_s *xipc_unix_server(xipc_type_e type, char *xipc_path, int backlog)
{
    xipc_s *xipc;
    struct sockaddr_un addr;
    int rv, len;

    if (xipc_path)
        xdbg_log(XDBG_DEBUG, "xipc_unix_server: sock file path - %s", xipc_path);

    if ((xipc = _allocate_socket(type, xipc_path)) == NULL)
        return NULL;

    if (_xipc_socket(xipc) != TRUE)
    {
        xmem_free(xipc, sizeof(xipc_s));
        return NULL;
    }

    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, xipc_path); /* sun_path is 108 bytes */
    len = sizeof(addr);

    /* unlink the file so the bind will succeed, then bind to that file. */
    unlink(xipc_path);
    rv = bind(xipc->sockfd, (struct sockaddr *) &addr, len);
    if (rv < 0)
    {
        xdbg_log(XDBG_ERR, "xipc_unix_server: bind error !!");
        perror("bind");
        close(xipc->sockfd);
        xmem_free(xipc, sizeof(xipc_s));
        return NULL;
    }

    if (type == XIPC_STREAM)
    {
        if (backlog > 0)
            rv = listen(xipc->sockfd, backlog);
        else
            rv = listen(xipc->sockfd, XIPC_DEF_BACKLOG);
        
        if (rv < 0)
        {
            xdbg_log(XDBG_ERR, "xipc_unix_server: listen error !!");
            perror("listen");
            close(xipc->sockfd);
            xmem_free(xipc, sizeof(xipc_s));
        }
    }

    return xipc;
}


BOOLEAN xipc_set_exec_handler(xipc_s *xipc, xipc_hdr_s *xhdr,
                              xipc_exec_cb_s *exec_cb)
{
    xipc_trans_s *trans;
    xipc_trans_s tmp_trans;
    BOOLEAN retval = TRUE; 

    if (xipc == NULL)
        return FALSE;

    XIPC_LOCK((xipc_s *)xipc);

    xdbg_log(XDBG_TRACE, "server: register exec op = %d, mtype = %d", 
        xhdr->op, xhdr->mtype);

    tmp_trans.hdr.op = xhdr->op;
    tmp_trans.hdr.mtype = xhdr->mtype;

    LL_SEARCH(xipc->trans_list,trans,&tmp_trans,_xipc_trans_cmp);

    if (trans == NULL)
    {
        if ((trans = (xipc_trans_s *)xmem_malloc(sizeof(xipc_trans_s))) == NULL)
            retval = FALSE;
    }
    else
    {
        xdbg_log(XDBG_ERR, "server: register exec handler: already registered !!");
        retval = FALSE;
    }

    if (retval)
    {
        memset((char *)trans, 0, sizeof(xipc_trans_s));
        trans->hdr.op = xhdr->op;
        trans->hdr.mtype = xhdr->mtype;
        trans->dsize = 0;
        trans->xipc_exec_cb = exec_cb;
        trans->params = NULL;

        LL_APPEND(xipc->trans_list, trans);
    }

    XIPC_UNLOCK((xipc_s *)xipc);

    return retval;
}

BOOLEAN xipc_set_data_handler(xipc_s *xipc, xipc_hdr_s *xhdr,
                              xipc_data_cb_s *data_cb,
                              size_t dsize)
{
    xipc_trans_s *trans;
    xipc_trans_s tmp_trans;
    BOOLEAN retval = TRUE; 

    if (xipc == NULL)
        return FALSE;

    XIPC_LOCK((xipc_s *)xipc);

    xdbg_log(XDBG_TRACE, "server: register data op = %d, mtype = %d dsize = %d", xhdr->op, xhdr->mtype, dsize);

    memset(&tmp_trans, 0, sizeof(tmp_trans));
    tmp_trans.hdr.op = xhdr->op;
    tmp_trans.hdr.mtype = xhdr->mtype;

    LL_SEARCH(xipc->trans_list,trans,&tmp_trans,_xipc_trans_cmp);

    if (trans == NULL)
    {
        if ((trans = (xipc_trans_s *)xmem_malloc(sizeof(xipc_trans_s))) == NULL)
            retval = FALSE;
    }
    else
    {
        xdbg_log(XDBG_ERR, "server: register data handler: already registered !!");
        retval = FALSE;
    }

    if (retval)
    {
        memset((char *)trans, 0, sizeof(xipc_trans_s));
        trans->hdr.op = xhdr->op;
        trans->hdr.mtype = xhdr->mtype;
        trans->dsize = dsize;
        trans->xipc_data_cb = data_cb;
        trans->params = NULL;

        LL_APPEND(xipc->trans_list, trans);
    }

    XIPC_UNLOCK((xipc_s *)xipc);

    return retval;
}

BOOLEAN xipc_set_group_handler(xipc_s *xipc, xipc_hdr_s *xhdr,
                               xipc_group_cb_s *group_cb,
                               size_t dsize, void *params)
{
    xipc_trans_s *trans;
    xipc_trans_s tmp_trans;
    BOOLEAN retval = TRUE; 

    if (xipc == NULL)
        return FALSE;

    XIPC_LOCK((xipc_s *)xipc);

    xdbg_log(XDBG_TRACE, "server: register group op = %d, mtype = %d dsize = %d", xhdr->op, xhdr->mtype, dsize);

    tmp_trans.hdr.op = xhdr->op;
    tmp_trans.hdr.mtype = xhdr->mtype;

    LL_SEARCH(xipc->trans_list,trans,&tmp_trans,_xipc_trans_cmp);

    if (trans == NULL)
    {
        if ((trans = (xipc_trans_s *)xmem_malloc(sizeof(xipc_trans_s))) == NULL)
            retval = FALSE;
    }
    else
    {
        xdbg_log(XDBG_ERR, "server: register group handler: already registered !!");
        retval = FALSE;
    }

    if (retval)
    {
        memset((char *)trans, 0, sizeof(xipc_trans_s));
        trans->hdr.op = xhdr->op;
        trans->hdr.mtype = xhdr->mtype;
        trans->dsize = dsize;
        trans->xipc_group_cb = group_cb;
        trans->params = params;

        LL_APPEND(xipc->trans_list, trans);
    }

    XIPC_UNLOCK((xipc_s *)xipc);

    return retval;
}

BOOLEAN xipc_process_trans(void *xnet, int sockfd, void *xipc_in)
{
    BOOLEAN retval ;

    XIPC_LOCK((xipc_s *)xipc_in);

    retval = _xipc_process_trans(xnet, sockfd, xipc_in);

    XIPC_UNLOCK((xipc_s *)xipc_in);

    return retval;
}

BOOLEAN xipc_set_timeout(xipc_s *xipc, uint32_t msec)
{
    if (xipc == NULL)
        return FALSE;

    XIPC_LOCK((xipc_s *)xipc);

    xipc->wait_msec = msec;

    XIPC_UNLOCK((xipc_s *)xipc);

    return TRUE;
}


