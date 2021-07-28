/*
 * Copyright (C) 2013-2020 Argonne National Laboratory, Department of Energy,
 *                    UChicago Argonne, LLC and The HDF Group.
 * All rights reserved.
 *
 * The full copyright notice, including terms governing use, modification,
 * and redistribution, is contained in the COPYING file that can be
 * found at the root of the source code distribution tree.
 */

#include "na_plugin.h"

#include "na_ip.h"

#include "mercury_hash_table.h"
#include "mercury_thread_rwlock.h"
// #include "mercury_time.h"

#include <ucp/api/ucp.h>

#include <stdalign.h>
#include <string.h>

#include <netdb.h>
#include <sys/socket.h>

/****************/
/* Local Macros */
/****************/

/* Default protocol */
#define NA_UCX_PROTOCOL_DEFAULT "all"

/* Addr status bits */
// #define NA_SM_ADDR_RESERVED   (1 << 0)
#define NA_UCX_ADDR_RESOLVING (1 << 1)
#define NA_UCX_ADDR_RESOLVED  (1 << 2)

/* Default max msg size */
#define NA_UCX_MSG_SIZE_MAX (4096)

/* Max tag */
#define NA_UCX_MAX_TAG UINT32_MAX

/* Reserved tags */
#define NA_UCX_TAG_MASK        ((uint64_t) 0x00000000FFFFFFFF)
#define NA_UCX_TAG_UNEXPECTED  ((uint64_t) 0x0000000100000000)
#define NA_UCX_TAG_SENDER_MASK ((uint64_t) 0xFFFFFFFE00000000)

/* Maximum number of pre-allocated IOV entries */
#define NA_UCX_IOV_STATIC_MAX (8)

/* Op ID status bits */
#define NA_UCX_OP_COMPLETED (1 << 0)
#define NA_UCX_OP_CANCELED  (1 << 1)
#define NA_UCX_OP_QUEUED    (1 << 2)
#define NA_UCX_OP_ERRORED   (1 << 3)

/* Private data access */
#define NA_UCX_CLASS(na_class)                                                 \
    ((struct na_ucx_class *) ((na_class)->plugin_class))
#define NA_UCX_CONTEXT(na_context)                                             \
    ((struct na_ucx_context *) ((na_context)->plugin_context))

/* Reset op ID */
#define NA_UCX_OP_RESET(__op, __context, __cb_type, __cb, __arg, __addr)       \
    do {                                                                       \
        __op->context = __context;                                             \
        __op->completion_data.callback_info.type = __cb_type;                  \
        __op->completion_data.callback = __cb;                                 \
        __op->completion_data.callback_info.arg = __arg;                       \
        __op->addr = __addr;                                                   \
        na_ucx_addr_ref_incr(__addr);                                          \
        hg_atomic_set32(&__op->status, 0);                                     \
    } while (0)

#define NA_UCX_OP_RESET_NO_ADDR(__op, __context, __cb_type, __cb, __arg)       \
    do {                                                                       \
        __op->context = __context;                                             \
        __op->completion_data.callback_info.type = __cb_type;                  \
        __op->completion_data.callback = __cb;                                 \
        __op->completion_data.callback_info.arg = __arg;                       \
        hg_atomic_set32(&__op->status, 0);                                     \
    } while (0)

#define NA_UCX_OP_RELEASE(__op)                                                \
    do {                                                                       \
        if (__op->addr)                                                        \
            na_ucx_addr_ref_decr(__op->addr);                                  \
        hg_atomic_set32(&__op->status, NA_UCX_OP_COMPLETED);                   \
    } while (0)

/************************************/
/* Local Type and Struct Definition */
/************************************/

/* Address */
struct na_ucx_addr {
    struct sockaddr_storage ss_addr; /* Sock addr */
    ucs_sock_addr_t addr_key;        /* Address key */
    ucp_ep_h ucp_ep;                 /* Currently only one EP per address */
    uint32_t conn_id;                /* Connection ID (local) */
    uint32_t remote_conn_id;         /* Connection ID (remote) */
    hg_atomic_int32_t refcount;      /* Reference counter */
    hg_atomic_int32_t status;        /* Status bits */
};

/* Map (used to cache addresses) */
struct na_ucx_map {
    hg_thread_rwlock_t lock;
    hg_hash_table_t *map;
};

/* Memory descriptor info */
struct na_ucx_mem_desc_info {
    na_uint64_t fi_mr_key; /* FI MR key                   */
    size_t len;            /* Size of region              */
    unsigned long iovcnt;  /* Segment count               */
    na_uint8_t flags;      /* Flag of operation access    */
};

/* Memory descriptor */
struct na_ucx_mem_desc {
    struct na_ucx_mem_desc_info info; /* Segment info */
    union {
        struct iovec s[NA_UCX_IOV_STATIC_MAX]; /* Single segment */
        struct iovec *d;                       /* Multiple segments */
    } iov;                                     /* Remain last */
};

/* Memory handle */
struct na_ucx_mem_handle {
    struct na_ucx_mem_desc desc; /* Memory descriptor        */
    struct fid_mr *fi_mr;        /* FI MR handle             */
};

/* Msg info */
struct na_ucx_msg_info {
    union {
        const void *const_ptr;
        void *ptr;
    } buf;
    size_t buf_size;
    na_size_t actual_buf_size;
    na_tag_t tag;
};

/* Operation ID */
struct na_ucx_op_id {
    struct na_cb_completion_data completion_data; /* Completion data    */
    union {
        struct na_ucx_msg_info msg;
        // struct na_ucx_rma_info rma;
    } info;                             /* Op info                  */
    HG_QUEUE_ENTRY(na_ucx_op_id) entry; /* Entry in queue           */
    na_context_t *context;              /* NA context associated    */
    struct na_ucx_addr *addr;           /* Address associated       */
    hg_atomic_int32_t status;           /* Operation status         */
};

/* UCX context */
// struct na_ucx_context {
//     ucp_worker_h ucp_worker;
//     na_uint8_t id;
// };

/* UCX class */
struct na_ucx_class {
    struct na_ucx_map addr_map;    /* Address map */
    struct na_ucx_map conn_map;    /* Connection ID map */
    ucp_context_h ucp_context;     /* UCP context */
    ucp_worker_h ucp_worker;       /* Shared UCP worker */
    ucp_listener_h ucp_listener;   /* Listener handle if listening */
    struct na_ucx_addr *self_addr; /* Self address */
    size_t ucp_request_size;       /* Size of UCP requests */
    char *protocol_name;           /* Protocol used */
    na_size_t unexpected_size_max; /* Max unexpected size */
    na_size_t expected_size_max;   /* Max expected size */
    hg_atomic_int32_t ncontexts;   /* Number of contexts */
    na_bool_t no_wait;             /* Wait disabled */
};

/********************/
/* Local Prototypes */
/********************/

/**
 * Init config.
 */
static na_return_t
na_ucp_config_init(
    const char *tls, const char *net_devices, ucp_config_t **config_p);

/**
 * Release config.
 */
static void
na_ucp_config_release(ucp_config_t *config);

/**
 * Create context.
 */
static na_return_t
na_ucp_context_create(const ucp_config_t *config, na_bool_t no_wait,
    ucs_thread_mode_t thread_mode, ucp_context_h *context_p,
    size_t *request_size_p);

/**
 * Destroy context.
 */
static void
na_ucp_context_destroy(ucp_context_h context);

/**
 * Create worker.
 */
static na_return_t
na_ucp_worker_create(ucp_context_h context, ucs_thread_mode_t thread_mode,
    ucp_worker_h *worker_p);

/**
 * Destroy worker.
 */
static void
na_ucp_worker_destroy(ucp_worker_h worker);

/**
 * Create listener.
 */
static na_return_t
na_ucp_listener_create(ucp_worker_h context, const struct sockaddr *addr,
    socklen_t addrlen, void *listener_arg, ucp_listener_h *listener_p,
    struct sockaddr_storage **listener_addr_p);

/**
 * Destroy listener.
 */
static void
na_ucp_listener_destroy(ucp_listener_h listener);

/**
 * Listener callback.
 */
static void
na_ucp_listener_conn_cb(ucp_conn_request_h conn_request, void *arg);

/**
 * Accept connection.
 */
static na_return_t
na_ucp_accept(ucp_worker_h worker, ucp_conn_request_h conn_request,
    ucp_err_handler_cb_t err_handler_cb, void *err_handler_arg, ucp_ep_h *ep_p);

/**
 * Establish connection.
 */
static na_return_t
na_ucp_connect(ucp_worker_h worker, const struct sockaddr *addr,
    socklen_t addrlen, ucp_err_handler_cb_t err_handler_cb,
    void *err_handler_arg, ucp_ep_h *ep_p);

/**
 * Create endpoint.
 */
static na_return_t
na_ucp_ep_create(ucp_worker_h worker, ucp_ep_params_t *ep_params,
    ucp_err_handler_cb_t err_handler_cb, void *err_handler_arg, ucp_ep_h *ep_p);

/**
 * Error handler.
 */
static void
na_ucp_ep_error_cb(void *arg, ucp_ep_h ep, ucs_status_t status);

/**
 * Get next connection ID.
 */
static uint32_t
na_ucp_conn_id_gen(void);

/**
 * Exchange connection IDs.
 */
static na_return_t
na_ucp_conn_id_exchange(ucp_ep_h ep, const uint32_t *local_conn_id,
    uint32_t *remote_conn_id, void *arg);

static void
na_ucp_conn_id_send_cb(void *request, ucs_status_t status, void *user_data);

static void
na_ucp_conn_id_recv_cb(
    void *request, ucs_status_t status, size_t length, void *user_data);

/**
 * Create a msg tag.
 */
static NA_INLINE ucp_tag_t
na_ucp_tag_gen(uint32_t tag, uint8_t unexpected, uint32_t conn_id);

/**
 * Convert a msg tag to a connection ID.
 */
static NA_INLINE uint32_t
na_ucp_tag_to_conn_id(ucp_tag_t tag);

/**
 * Send a msg.
 */
static na_return_t
na_ucp_msg_send(ucp_ep_h ep, const void *buf, size_t buf_size, ucp_tag_t tag,
    void *request);

/**
 * Recv a msg.
 */
static na_return_t
na_ucp_msg_recv(ucp_worker_h worker, void *buf, size_t buf_size, ucp_tag_t tag,
    ucp_tag_t tag_mask, void *request, ucp_tag_recv_nbx_callback_t recv_cb);

/**
 * Send msg callback.
 */
static void
na_ucp_msg_send_cb(void *request, ucs_status_t status, void *user_data);

/**
 * Recv unexpected msg callback.
 */
static void
na_ucp_msg_recv_unexpected_cb(void *request, ucs_status_t status,
    const ucp_tag_recv_info_t *info, void *user_data);

/**
 * Recv expected msg callback.
 */
static void
na_ucp_msg_recv_expected_cb(void *request, ucs_status_t status,
    const ucp_tag_recv_info_t *info, void *user_data);

/**
 * Allocate new UCX class.
 */
static struct na_ucx_class *
na_ucx_class_alloc(void);

/**
 * Free UCX class.
 */
static void
na_ucx_class_free(struct na_ucx_class *na_ucx_class);

/**
 * Parse hostname info.
 */
static na_return_t
na_ucx_parse_hostname_info(const char *hostname_info, const char *subnet_info,
    char **net_device_p, struct sockaddr_storage **sockaddr_p);

/**
 * Hash address key.
 */
static NA_INLINE unsigned int
na_ucx_addr_key_hash(hg_hash_table_key_t key);

/**
 * Compare address keys.
 */
static NA_INLINE int
na_ucx_addr_key_equal(hg_hash_table_key_t key1, hg_hash_table_key_t key2);

/**
 * Lookup addr key from map.
 */
static NA_INLINE struct na_ucx_addr *
na_ucx_addr_map_lookup(struct na_ucx_map *na_ucx_map,
    const struct sockaddr *addr, socklen_t addrlen);

/**
 * Insert new addr key into map. Execute callback while write lock is acquired.
 */
static na_return_t
na_ucx_addr_map_insert(struct na_ucx_map *na_ucx_map,
    const struct sockaddr *addr, socklen_t addrlen,
    struct na_ucx_addr **na_ucx_addr_p);

/**
 * Remove addr key from map.
 */
static na_return_t
na_ucx_addr_map_remove(struct na_ucx_map *na_ucx_map, na_uint64_t key);

/**
 * Create address.
 */
static na_return_t
na_ucx_addr_create(const struct sockaddr *addr, socklen_t addrlen,
    struct na_ucx_addr **na_ucx_addr_p);

/**
 * Destroy address.
 */
static void
na_ucx_addr_destroy(struct na_ucx_addr *na_ucx_addr);

/**
 * Increment ref count.
 */
static NA_INLINE void
na_ucx_addr_ref_incr(struct na_ucx_addr *na_ucx_addr);

/**
 * Decrement ref count and free address if 0.
 */
static NA_INLINE void
na_ucx_addr_ref_decr(struct na_ucx_addr *na_ucx_addr);

/**
 * Resolve address.
 */
static na_return_t
na_ucx_addr_resolve(
    struct na_ucx_class *na_ucx_class, struct na_ucx_addr *na_ucx_addr);

/**
 * Complete UCX operation.
 */
static na_return_t
na_ucx_complete(struct na_ucx_op_id *na_ucx_op_id, na_return_t cb_ret);

/**
 * Release resources after NA callback execution.
 */
static NA_INLINE void
na_ucx_release(void *arg);

/********************/
/* Plugin callbacks */
/********************/

/* check_protocol */
static na_bool_t
na_ucx_check_protocol(const char *protocol_name);

/* initialize */
static na_return_t
na_ucx_initialize(
    na_class_t *na_class, const struct na_info *na_info, na_bool_t listen);

/* finalize */
static na_return_t
na_ucx_finalize(na_class_t *na_class);

// /* context_create */
// static na_return_t
// na_ucx_context_create(na_class_t *na_class, void **context, na_uint8_t id);

// /* context_destroy */
// static na_return_t
// na_ucx_context_destroy(na_class_t *na_class, void *context);

/* op_create */
static na_op_id_t *
na_ucx_op_create(na_class_t *na_class);

/* op_destroy */
static na_return_t
na_ucx_op_destroy(na_class_t *na_class, na_op_id_t *op_id);

/* addr_lookup */
static na_return_t
na_ucx_addr_lookup(na_class_t *na_class, const char *name, na_addr_t *addr_p);

/* addr_free */
static NA_INLINE na_return_t
na_ucx_addr_free(na_class_t *na_class, na_addr_t addr);

/* addr_self */
static NA_INLINE na_return_t
na_ucx_addr_self(na_class_t *na_class, na_addr_t *addr);

/* addr_dup */
static NA_INLINE na_return_t
na_ucx_addr_dup(na_class_t *na_class, na_addr_t addr, na_addr_t *new_addr);

/* addr_dup */
static na_bool_t
na_ucx_addr_cmp(na_class_t *na_class, na_addr_t addr1, na_addr_t addr2);

/* addr_is_self */
static NA_INLINE na_bool_t
na_ucx_addr_is_self(na_class_t *na_class, na_addr_t addr);

/* addr_to_string */
static na_return_t
na_ucx_addr_to_string(
    na_class_t *na_class, char *buf, na_size_t *buf_size, na_addr_t addr);

/* addr_get_serialize_size */
static NA_INLINE na_size_t
na_ucx_addr_get_serialize_size(na_class_t *na_class, na_addr_t addr);

/* addr_serialize */
static na_return_t
na_ucx_addr_serialize(
    na_class_t *na_class, void *buf, na_size_t buf_size, na_addr_t addr);

/* addr_deserialize */
static na_return_t
na_ucx_addr_deserialize(
    na_class_t *na_class, na_addr_t *addr, const void *buf, na_size_t buf_size);

/* msg_get_max_unexpected_size */
static NA_INLINE na_size_t
na_ucx_msg_get_max_unexpected_size(const na_class_t *na_class);

/* msg_get_max_expected_size */
static NA_INLINE na_size_t
na_ucx_msg_get_max_expected_size(const na_class_t *na_class);

/* msg_get_max_tag */
static NA_INLINE na_tag_t
na_ucx_msg_get_max_tag(const na_class_t *na_class);

/* msg_send_unexpected */
static na_return_t
na_ucx_msg_send_unexpected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
    void *plugin_data, na_addr_t dest_addr, na_uint8_t dest_id, na_tag_t tag,
    na_op_id_t *op_id);

/* msg_recv_unexpected */
static na_return_t
na_ucx_msg_recv_unexpected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, void *buf, na_size_t buf_size,
    void *plugin_data, na_op_id_t *op_id);

/* msg_send_expected */
static na_return_t
na_ucx_msg_send_expected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
    void *plugin_data, na_addr_t dest_addr, na_uint8_t dest_id, na_tag_t tag,
    na_op_id_t *op_id);

/* msg_recv_expected */
static na_return_t
na_ucx_msg_recv_expected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, void *buf, na_size_t buf_size,
    void *plugin_data, na_addr_t source_addr, na_uint8_t source_id,
    na_tag_t tag, na_op_id_t *op_id);

/* mem_handle */
static na_return_t
na_ucx_mem_handle_create(na_class_t *na_class, void *buf, na_size_t buf_size,
    unsigned long flags, na_mem_handle_t *mem_handle);

// static na_return_t
// na_ucx_mem_handle_create_segments(na_class_t NA_UNUSED *na_class,
//     struct na_segment *segments, na_size_t segment_count, unsigned long
//     flags, na_mem_handle_t *mem_handle);

static na_return_t
na_ucx_mem_handle_free(na_class_t *na_class, na_mem_handle_t mem_handle);

static NA_INLINE na_size_t
na_ucx_mem_handle_get_max_segments(const na_class_t *na_class);

static na_return_t
na_ucx_mem_register(na_class_t *na_class, na_mem_handle_t mem_handle);

static na_return_t
na_ucx_mem_deregister(na_class_t *na_class, na_mem_handle_t mem_handle);

/* mem_handle serialization */
static NA_INLINE na_size_t
na_ucx_mem_handle_get_serialize_size(
    na_class_t *na_class, na_mem_handle_t mem_handle);

static na_return_t
na_ucx_mem_handle_serialize(na_class_t *na_class, void *buf, na_size_t buf_size,
    na_mem_handle_t mem_handle);

static na_return_t
na_ucx_mem_handle_deserialize(na_class_t *na_class, na_mem_handle_t *mem_handle,
    const void *buf, na_size_t buf_size);

/* put */
static na_return_t
na_ucx_put(na_class_t *na_class, na_context_t *context, na_cb_t callback,
    void *arg, na_mem_handle_t local_mem_handle, na_offset_t local_offset,
    na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
    na_size_t length, na_addr_t remote_addr, na_uint8_t remote_id,
    na_op_id_t *op_id);

/* get */
static na_return_t
na_ucx_get(na_class_t *na_class, na_context_t *context, na_cb_t callback,
    void *arg, na_mem_handle_t local_mem_handle, na_offset_t local_offset,
    na_mem_handle_t remote_mem_handle, na_offset_t remote_offset,
    na_size_t length, na_addr_t remote_addr, na_uint8_t remote_id,
    na_op_id_t *op_id);

/* poll_get_fd */
static int
na_ucx_poll_get_fd(na_class_t *na_class, na_context_t *context);

/* poll_try_wait */
static NA_INLINE na_bool_t
na_ucx_poll_try_wait(na_class_t *na_class, na_context_t *context);

/* progress */
static na_return_t
na_ucx_progress(
    na_class_t *na_class, na_context_t *context, unsigned int timeout);

/* cancel */
static na_return_t
na_ucx_cancel(na_class_t *na_class, na_context_t *context, na_op_id_t *op_id);

/*******************/
/* Local Variables */
/*******************/

const struct na_class_ops NA_PLUGIN_OPS(ucx2) = {
    "ucx2",                               /* name */
    na_ucx_check_protocol,                /* check_protocol */
    na_ucx_initialize,                    /* initialize */
    na_ucx_finalize,                      /* finalize */
    NULL,                                 /* cleanup */
    NULL,                                 /* context_create */
    NULL,                                 /* context_destroy */
    na_ucx_op_create,                     /* op_create */
    na_ucx_op_destroy,                    /* op_destroy */
    na_ucx_addr_lookup,                   /* addr_lookup */
    na_ucx_addr_free,                     /* addr_free */
    NULL,                                 /* addr_set_remove */
    na_ucx_addr_self,                     /* addr_self */
    na_ucx_addr_dup,                      /* addr_dup */
    na_ucx_addr_cmp,                      /* addr_cmp */
    na_ucx_addr_is_self,                  /* addr_is_self */
    na_ucx_addr_to_string,                /* addr_to_string */
    na_ucx_addr_get_serialize_size,       /* addr_get_serialize_size */
    na_ucx_addr_serialize,                /* addr_serialize */
    na_ucx_addr_deserialize,              /* addr_deserialize */
    na_ucx_msg_get_max_unexpected_size,   /* msg_get_max_unexpected_size */
    na_ucx_msg_get_max_expected_size,     /* msg_get_max_expected_size */
    NULL,                                 /* msg_get_unexpected_header_size */
    NULL,                                 /* msg_get_expected_header_size */
    na_ucx_msg_get_max_tag,               /* msg_get_max_tag */
    NULL,                                 /* msg_buf_alloc */
    NULL,                                 /* msg_buf_free */
    NULL,                                 /* msg_init_unexpected */
    na_ucx_msg_send_unexpected,           /* msg_send_unexpected */
    na_ucx_msg_recv_unexpected,           /* msg_recv_unexpected */
    NULL,                                 /* msg_init_expected */
    na_ucx_msg_send_expected,             /* msg_send_expected */
    na_ucx_msg_recv_expected,             /* msg_recv_expected */
    na_ucx_mem_handle_create,             /* mem_handle_create */
    NULL,                                 /* mem_handle_create_segment */
    na_ucx_mem_handle_free,               /* mem_handle_free */
    na_ucx_mem_handle_get_max_segments,   /* mem_handle_get_max_segments */
    na_ucx_mem_register,                  /* mem_register */
    na_ucx_mem_deregister,                /* mem_deregister */
    na_ucx_mem_handle_get_serialize_size, /* mem_handle_get_serialize_size */
    na_ucx_mem_handle_serialize,          /* mem_handle_serialize */
    na_ucx_mem_handle_deserialize,        /* mem_handle_deserialize */
    na_ucx_put,                           /* put */
    na_ucx_get,                           /* get */
    na_ucx_poll_get_fd,                   /* poll_get_fd */
    na_ucx_poll_try_wait,                 /* poll_try_wait */
    na_ucx_progress,                      /* progress */
    na_ucx_cancel                         /* cancel */
};

/* Thread mode names */
#ifndef NA_UCX_HAS_THREAD_MODE_NAMES
#    define NA_UCX_THREAD_MODES                                                \
        X(UCS_THREAD_MODE_SINGLE, "single")                                    \
        X(UCS_THREAD_MODE_SERIALIZED, "serialized")                            \
        X(UCS_THREAD_MODE_MULTI, "multi")
#    define X(a, b) b,
static const char *ucs_thread_mode_names[UCS_THREAD_MODE_LAST] = {
    NA_UCX_THREAD_MODES};
#    undef X
#endif

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucp_config_init(
    const char *tls, const char *net_devices, ucp_config_t **config_p)
{
    ucp_config_t *config = NULL;
    ucs_status_t status;
    na_return_t ret;

    /* Read UCP configuration */
    status = ucp_config_read(NULL, NULL, &config);
    NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, error, ret, NA_PROTOCOL_ERROR,
        "ucp_config_read() failed (%s)", ucs_status_string(status));

    /* Set user-requested transport */
    status = ucp_config_modify(config, "TLS", tls);
    NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, error, ret, NA_PROTOCOL_ERROR,
        "ucp_config_modify() failed (%s)", ucs_status_string(status));

    /* Use mutex instead of spinlock */
    status = ucp_config_modify(config, "USE_MT_MUTEX", "y");
    NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, error, ret, NA_PROTOCOL_ERROR,
        "ucp_config_modify() failed (%s)", ucs_status_string(status));

    /* TODO Currently assume that systems are homogeneous */
    status = ucp_config_modify(config, "UNIFIED_MODE", "y");
    NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, error, ret, NA_PROTOCOL_ERROR,
        "ucp_config_modify() failed (%s)", ucs_status_string(status));

    /* Add address debug info if running in debug */
    status = ucp_config_modify(config, "ADDRESS_DEBUG_INFO", "y");
    NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, error, ret, NA_PROTOCOL_ERROR,
        "ucp_config_modify() failed (%s)", ucs_status_string(status));

    /* Set network devices to use */
    if (net_devices) {
        status = ucp_config_modify(config, "NET_DEVICES", net_devices);
        NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, error, ret,
            NA_PROTOCOL_ERROR, "ucp_config_modify() failed (%s)",
            ucs_status_string(status));
    } else
        NA_LOG_SUBSYS_WARNING(
            cls, "Could not find NET_DEVICE to use, using default");

    /* Print UCX config */
    NA_LOG_SUBSYS_DEBUG_FUNC(cls,
        ucp_config_print(config, hg_log_get_stream_debug(),
            "NA UCX class configuration used",
            UCS_CONFIG_PRINT_CONFIG | UCS_CONFIG_PRINT_HEADER),
        "Now using the following UCX global configuration");

    *config_p = config;

    return NA_SUCCESS;

error:
    if (config)
        ucp_config_release(config);

    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_ucp_config_release(ucp_config_t *config)
{
    ucp_config_release(config);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucp_context_create(const ucp_config_t *config, na_bool_t no_wait,
    ucs_thread_mode_t thread_mode, ucp_context_h *context_p,
    size_t *request_size_p)
{
    ucp_context_h context = NULL;
    ucp_params_t context_params = {
        .field_mask =
            UCP_PARAM_FIELD_FEATURES | UCP_PARAM_FIELD_TAG_SENDER_MASK,
        .features = UCP_FEATURE_TAG | UCP_FEATURE_RMA | UCP_FEATURE_STREAM,
        .tag_sender_mask = NA_UCX_TAG_SENDER_MASK};
    ucp_context_attr_t context_actuals = {
        .field_mask = UCP_ATTR_FIELD_REQUEST_SIZE | UCP_ATTR_FIELD_THREAD_MODE};
    ucs_status_t status;
    na_return_t ret;

    /* Skip wakeup feature if not waiting */
    if (no_wait != NA_TRUE)
        context_params.features |= UCP_FEATURE_WAKEUP;

    if (thread_mode == UCS_THREAD_MODE_MULTI) {
        /* If the UCP context can potentially be used by more than one
         * worker / thread, then this context needs thread safety. */
        context_params.field_mask |= UCP_PARAM_FIELD_MT_WORKERS_SHARED;
        context_params.mt_workers_shared = 1;
    }

    /* Create UCP context */
    status = ucp_init(&context_params, config, &context);
    NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, error, ret, NA_PROTOCOL_ERROR,
        "ucp_init() failed (%s)", ucs_status_string(status));

    /* Print context info */
    NA_LOG_SUBSYS_DEBUG_FUNC(cls,
        ucp_context_print_info(context, hg_log_get_stream_debug()),
        "Context info");

    /* Query context to ensure we got what we asked for */
    status = ucp_context_query(context, &context_actuals);
    NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, error, ret, NA_PROTOCOL_ERROR,
        "ucp_context_query() failed (%s)", ucs_status_string(status));

    /* Check that expected fields are present */
    NA_CHECK_SUBSYS_ERROR(cls,
        (context_actuals.field_mask & UCP_ATTR_FIELD_REQUEST_SIZE) == 0, error,
        ret, NA_PROTOCOL_ERROR, "context attributes contain no request size");
    NA_CHECK_SUBSYS_ERROR(cls,
        (context_actuals.field_mask & UCP_ATTR_FIELD_THREAD_MODE) == 0, error,
        ret, NA_PROTOCOL_ERROR, "context attributes contain no thread mode");

    /* Do not continue if thread mode is less than expected */
    NA_CHECK_SUBSYS_ERROR(cls,
        thread_mode != UCS_THREAD_MODE_SINGLE &&
            context_actuals.thread_mode < thread_mode,
        error, ret, NA_PROTOCOL_ERROR, "Context thread mode is: %s",
        ucs_thread_mode_names[context_actuals.thread_mode]);

    NA_LOG_SUBSYS_DEBUG(
        cls, "UCP request size is %zu", context_actuals.request_size);

    *context_p = context;
    *request_size_p = context_actuals.request_size;

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_ucp_context_destroy(ucp_context_h context)
{
    ucp_cleanup(context);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucp_worker_create(ucp_context_h context, ucs_thread_mode_t thread_mode,
    ucp_worker_h *worker_p)
{
    ucp_worker_h worker = NULL;
    ucp_worker_params_t worker_params = {
        .field_mask = UCP_WORKER_PARAM_FIELD_THREAD_MODE,
        .thread_mode = thread_mode};
    ucp_worker_attr_t worker_actuals = {
        .field_mask = UCP_WORKER_ATTR_FIELD_THREAD_MODE};
    // uint64_t expflag;
    ucs_status_t status;
    na_return_t ret;
    // int rc;

    status = ucp_worker_create(context, &worker_params, &worker);
    NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, error, ret, NA_PROTOCOL_ERROR,
        "ucp_worker_create() failed (%s)", ucs_status_string(status));

    /* Print worker info */
    NA_LOG_SUBSYS_DEBUG_FUNC(ctx,
        ucp_worker_print_info(worker, hg_log_get_stream_debug()),
        "Worker info");

    /* Check thread mode */
    status = ucp_worker_query(worker, &worker_actuals);
    NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, error, ret, NA_PROTOCOL_ERROR,
        "ucp_worker_query() failed (%s)", ucs_status_string(status));

    NA_CHECK_SUBSYS_ERROR(cls,
        (worker_actuals.field_mask & UCP_WORKER_ATTR_FIELD_THREAD_MODE) == 0,
        error, ret, NA_PROTONOSUPPORT,
        "worker attributes contain no thread mode");
    NA_CHECK_SUBSYS_ERROR(cls,
        thread_mode != UCS_THREAD_MODE_SINGLE &&
            worker_actuals.thread_mode < thread_mode,
        error, ret, NA_PROTONOSUPPORT,
        "UCP worker thread mode (%s) is not supported",
        ucs_thread_mode_names[worker_actuals.thread_mode]);

    // (void) hg_thread_mutex_lock(&nucl->addr_lock);
    // ret = hg_hash_table_insert(nucl->addr_tbl, self, self);
    // (void) hg_thread_mutex_unlock(&nucl->addr_lock);

    // if (!ret)
    //     goto cleanup_self;

    /* Find the highest bit in the application tag space.  We will set it to
     * indicate an expected message and clear it to indicate an unexpected
     * message.
     */
    // expflag = ~nctx->app.tagmask ^ (~nctx->app.tagmask >> 1);
    // nctx->msg.tagmask = nctx->app.tagmask | expflag;
    // nctx->msg.tagmax = SHIFTOUT_MASK(~nctx->msg.tagmask);
    // nctx->msg.tagshift = mask_to_shift(~nctx->msg.tagmask);
    // nctx->exp.tag = nctx->app.tag | expflag;
    // nctx->unexp.tag = nctx->app.tag;

    // ucp_worker_release_address(nctx->worker, uaddr);

    *worker_p = worker;

    return NA_SUCCESS;

error:
    if (worker)
        ucp_worker_destroy(worker);
    // cleanup_tbl:
    //     (void) hg_thread_mutex_lock(&nucl->addr_lock);
    //     hg_hash_table_remove(nucl->addr_tbl, self);
    //     (void) hg_thread_mutex_unlock(&nucl->addr_lock);
    // cleanup_self:
    //     free(self);
    // cleanup_addr:
    //     ucp_worker_release_address(nctx->worker, uaddr);
    // cleanup_worker:
    //     ucp_worker_destroy(nctx->worker);
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_ucp_worker_destroy(ucp_worker_h worker)
{
    ucp_worker_destroy(worker);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucp_listener_create(ucp_worker_h worker, const struct sockaddr *addr,
    socklen_t addrlen, void *listener_arg, ucp_listener_h *listener_p,
    struct sockaddr_storage **listener_addr_p)
{
    ucp_listener_h listener = NULL;
    ucp_listener_params_t listener_params = {
        .field_mask = UCP_LISTENER_PARAM_FIELD_SOCK_ADDR |
                      UCP_LISTENER_PARAM_FIELD_CONN_HANDLER,
        .sockaddr = (ucs_sock_addr_t){.addr = addr, .addrlen = addrlen},
        .conn_handler = (ucp_listener_conn_handler_t){
            .cb = na_ucp_listener_conn_cb, .arg = listener_arg}};
    ucp_listener_attr_t listener_actuals = {
        .field_mask = UCP_LISTENER_ATTR_FIELD_SOCKADDR};
    struct sockaddr_storage *ss_addr = NULL;
    ucs_status_t status;
    na_return_t ret;

    /* Create listener on worker */
    status = ucp_listener_create(worker, &listener_params, &listener);
    NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, error, ret, NA_PROTOCOL_ERROR,
        "ucp_listener_create() failed (%s)", ucs_status_string(status));

    /* Check sockaddr */
    status = ucp_listener_query(listener, &listener_actuals);
    NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, error, ret, NA_PROTOCOL_ERROR,
        "ucp_listener_query() failed (%s)", ucs_status_string(status));

    NA_CHECK_SUBSYS_ERROR(cls,
        (listener_actuals.field_mask & UCP_LISTENER_ATTR_FIELD_SOCKADDR) == 0,
        error, ret, NA_PROTONOSUPPORT,
        "listener attributes contain no sockaddr");

    /* Allocate new addr to store result */
    ss_addr = calloc(1, sizeof(*ss_addr));
    NA_CHECK_SUBSYS_ERROR(cls, ss_addr == NULL, error, ret, NA_NOMEM,
        "Could not allocate ss address");
    memcpy(ss_addr, &listener_actuals.sockaddr, sizeof(*ss_addr));

    *listener_p = listener;
    *listener_addr_p = ss_addr;

    return NA_SUCCESS;

error:
    if (listener)
        ucp_listener_destroy(listener);
    free(ss_addr);
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_ucp_listener_destroy(ucp_listener_h listener)
{
    ucp_listener_destroy(listener);
}

/*---------------------------------------------------------------------------*/
static void
na_ucp_listener_conn_cb(ucp_conn_request_h conn_request, void *arg)
{
    struct na_ucx_class *na_ucx_class = (struct na_ucx_class *) arg;
    ucp_conn_request_attr_t conn_request_attrs = {
        .field_mask = UCP_CONN_REQUEST_ATTR_FIELD_CLIENT_ADDR};
    struct na_ucx_addr *na_ucx_addr = NULL;
    ucs_status_t status;
    na_return_t na_ret;

    status = ucp_conn_request_query(conn_request, &conn_request_attrs);
    NA_CHECK_SUBSYS_ERROR_NORET(poll, status != UCS_OK, error,
        "ucp_conn_request_query() failed (%s)", ucs_status_string(status));

    /* Lookup address from table */
    na_ucx_addr = na_ucx_addr_map_lookup(&na_ucx_class->addr_map,
        (const struct sockaddr *) &conn_request_attrs.client_address,
        sizeof(conn_request_attrs.client_address));
    NA_CHECK_SUBSYS_ERROR_NORET(addr, na_ucx_addr != NULL, error,
        "An entry is already present for this address");

    /* Insert new entry and create new address */
    na_ret = na_ucx_addr_map_insert(&na_ucx_class->addr_map,
        (const struct sockaddr *) &conn_request_attrs.client_address,
        sizeof(conn_request_attrs.client_address), &na_ucx_addr);
    NA_CHECK_SUBSYS_ERROR_NORET(addr,
        na_ret != NA_SUCCESS && na_ret != NA_EXIST, error,
        "Could not insert new address");

    /* Accept connection */
    na_ret = na_ucp_accept(na_ucx_class->ucp_worker, conn_request,
        na_ucp_ep_error_cb, (void *) na_ucx_class, &na_ucx_addr->ucp_ep);
    NA_CHECK_SUBSYS_NA_ERROR(
        addr, error, na_ret, "Could not accept connection request");

    /* Generate connection ID */
    na_ucx_addr->conn_id = na_ucp_conn_id_gen();

    /* Exchange IDs so that we can later use that ID to identify msg senders */
    na_ret = na_ucp_conn_id_exchange(na_ucx_addr->ucp_ep, &na_ucx_addr->conn_id,
        &na_ucx_addr->remote_conn_id, na_ucx_addr);
    NA_CHECK_SUBSYS_NA_ERROR(
        addr, error, na_ret, "Could not exchange connection IDs");

    return;

error:
    return;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucp_accept(ucp_worker_h worker, ucp_conn_request_h conn_request,
    ucp_err_handler_cb_t err_handler_cb, void *err_handler_arg, ucp_ep_h *ep_p)
{
    ucp_ep_params_t ep_params = {.field_mask = UCP_EP_PARAM_FIELD_CONN_REQUEST,
        .conn_request = conn_request};

    return na_ucp_ep_create(
        worker, &ep_params, err_handler_cb, err_handler_arg, ep_p);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucp_connect(ucp_worker_h worker, const struct sockaddr *addr,
    socklen_t addrlen, ucp_err_handler_cb_t err_handler_cb,
    void *err_handler_arg, ucp_ep_h *ep_p)
{
    ucp_ep_params_t ep_params = {
        .field_mask = UCP_EP_PARAM_FIELD_FLAGS | UCP_EP_PARAM_FIELD_SOCK_ADDR,
        .flags = UCP_EP_PARAMS_FLAGS_CLIENT_SERVER,
        .sockaddr = (ucs_sock_addr_t){.addr = addr, .addrlen = addrlen}};

    char sockaddr_str[60];
    NA_LOG_SUBSYS_DEBUG(addr, "Connecting to %s, addrlen=%d",
        ucs_sockaddr_str(addr, sockaddr_str, 60), addrlen);

    return na_ucp_ep_create(
        worker, &ep_params, err_handler_cb, err_handler_arg, ep_p);
}

/*---------------------------------------------------------------------------*/
static uint32_t
na_ucp_conn_id_gen(void)
{
    /* TODO improve that, not good enough */
    static uint32_t conn_id = 1;
    return conn_id++;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucp_conn_id_exchange(ucp_ep_h ep, const uint32_t *local_conn_id,
    uint32_t *remote_conn_id, void *arg)
{
    const ucp_request_param_t recv_params = {
        .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK |
                        UCP_OP_ATTR_FIELD_USER_DATA |
                        UCP_OP_ATTR_FIELD_DATATYPE | UCP_OP_ATTR_FIELD_FLAGS,
        .cb = {.recv_stream = na_ucp_conn_id_recv_cb},
        .user_data = arg,
        .datatype = ucp_dt_make_contig(sizeof(uint32_t)),
        .flags = UCP_STREAM_RECV_FLAG_WAITALL};
    const ucp_request_param_t send_params = {
        .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK |
                        UCP_OP_ATTR_FIELD_USER_DATA |
                        UCP_OP_ATTR_FIELD_DATATYPE,
        .cb = {.send = na_ucp_conn_id_send_cb},
        .user_data = arg,
        .datatype = ucp_dt_make_contig(sizeof(uint32_t))};
    ucs_status_ptr_t send_ptr, recv_ptr;
    na_return_t ret;
    size_t recv_len;

    /* Recv remote conn ID */
    recv_ptr =
        ucp_stream_recv_nbx(ep, remote_conn_id, 1, &recv_len, &recv_params);
    if (recv_ptr == NULL) {
        /* Completed immediately */
        NA_LOG_SUBSYS_DEBUG(
            addr, "ucp_stream_recv_nbx() completed immediately");
    } else
        NA_CHECK_SUBSYS_ERROR(addr, UCS_PTR_IS_ERR(recv_ptr), error, ret,
            NA_PROTOCOL_ERROR, "ucp_stream_recv_nbx() failed (%s)",
            ucs_status_string(UCS_PTR_STATUS(recv_ptr)));

    /* Send local conn ID */
    send_ptr = ucp_stream_send_nbx(ep, local_conn_id, 1, &send_params);
    if (send_ptr == NULL) {
        /* Completed immediately */
        NA_LOG_SUBSYS_DEBUG(
            addr, "ucp_stream_send_nbx() completed immediately");
    } else
        NA_CHECK_SUBSYS_ERROR(addr, UCS_PTR_IS_ERR(send_ptr), error, ret,
            NA_PROTOCOL_ERROR, "ucp_stream_send_nbx() failed (%s)",
            ucs_status_string(UCS_PTR_STATUS(send_ptr)));

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_ucp_conn_id_send_cb(void NA_UNUSED *request, ucs_status_t NA_UNUSED status,
    void NA_UNUSED *user_data)
{
}

/*---------------------------------------------------------------------------*/
static void
na_ucp_conn_id_recv_cb(
    void *request, ucs_status_t status, size_t length, void *user_data)
{
    struct na_ucx_addr *na_ucx_addr = (struct na_ucx_addr *) user_data;

    hg_atomic_set32(&na_ucx_addr->status, NA_UCX_ADDR_RESOLVED);
}

/*---------------------------------------------------------------------------*/
static NA_INLINE ucp_tag_t
na_ucp_tag_gen(uint32_t tag, uint8_t unexpected, uint32_t conn_id)
{
    return (ucp_tag_t) ((conn_id << 33) | ((unexpected & 0x1) << 32) | tag);
}

/*---------------------------------------------------------------------------*/
static NA_INLINE uint32_t
na_ucp_tag_to_conn_id(ucp_tag_t tag)
{
    return (uint32_t) ((tag & NA_UCX_TAG_SENDER_MASK) >> 33);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucp_ep_create(ucp_worker_h worker, ucp_ep_params_t *ep_params,
    ucp_err_handler_cb_t err_handler_cb, void *err_handler_arg, ucp_ep_h *ep_p)
{
    ucp_ep_h ep = NULL;
    ucs_status_t status;
    na_return_t ret;

    ep_params->field_mask |=
        UCP_EP_PARAM_FIELD_ERR_HANDLER | UCP_EP_PARAM_FIELD_ERR_HANDLING_MODE;
    ep_params->err_mode = UCP_ERR_HANDLING_MODE_PEER;
    ep_params->err_handler.cb = err_handler_cb;
    ep_params->err_handler.arg = err_handler_arg;

    status = ucp_ep_create(worker, ep_params, &ep);
    NA_CHECK_SUBSYS_ERROR(addr, status != UCS_OK, error, ret, NA_PROTOCOL_ERROR,
        "ucp_ep_create() failed (%s)", ucs_status_string(status));

    *ep_p = ep;

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_ucp_ep_error_cb(void *arg, ucp_ep_h NA_UNUSED ep, ucs_status_t status)
{
    if (UCS_STATUS_IS_ERR(status))
        return;

    NA_LOG_WARNING("Detected error: %s", ucs_status_string(status));

    /* the upper layer should close the connection */
    // if (is_established()) {
    //     _context.handle_connection_error(this);
    // } else {
    //     _context.remove_connection_inprogress(this);
    //     invoke_callback(_establish_cb, status);
    // }
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucp_msg_send(
    ucp_ep_h ep, const void *buf, size_t buf_size, ucp_tag_t tag, void *request)
{
    const ucp_request_param_t send_params = {
        .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK | UCP_OP_ATTR_FIELD_REQUEST,
        .cb = {.send = na_ucp_msg_send_cb},
        .request = request};
    ucs_status_ptr_t status_ptr;
    na_return_t ret;

    status_ptr = ucp_tag_send_nbx(ep, buf, buf_size, tag, &send_params);
    if (status_ptr == NULL) {
        /* Check for immediate completion */
        NA_LOG_SUBSYS_DEBUG(msg, "Operation completed immediately");
    } else
        NA_CHECK_SUBSYS_ERROR(msg, UCS_PTR_IS_ERR(status_ptr), error, ret,
            NA_PROTOCOL_ERROR, "ucp_tag_recv_nbx() failed (%s)",
            ucs_status_string(UCS_PTR_STATUS(status_ptr)));

    if (status_ptr != NULL)
        NA_LOG_SUBSYS_DEBUG(msg, "Operation was scheduled");

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucp_msg_recv(ucp_worker_h worker, void *buf, size_t buf_size, ucp_tag_t tag,
    ucp_tag_t tag_mask, void *request, ucp_tag_recv_nbx_callback_t recv_cb)
{
    const ucp_request_param_t recv_params = {
        .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK | UCP_OP_ATTR_FIELD_REQUEST,
        .cb = {.recv = recv_cb},
        .request = request};
    ucs_status_ptr_t status_ptr;
    na_return_t ret;

    status_ptr =
        ucp_tag_recv_nbx(worker, buf, buf_size, tag, tag_mask, &recv_params);
    if (status_ptr == NULL) {
        /* Check for immediate completion */
        NA_LOG_SUBSYS_DEBUG(msg, "Operation completed immediately");
    } else
        NA_CHECK_SUBSYS_ERROR(msg, UCS_PTR_IS_ERR(status_ptr), error, ret,
            NA_PROTOCOL_ERROR, "ucp_tag_recv_nbx() failed (%s)",
            ucs_status_string(UCS_PTR_STATUS(status_ptr)));

    if (status_ptr != NULL)
        NA_LOG_SUBSYS_DEBUG(msg, "Operation was scheduled");

    return NA_SUCCESS;

error:

    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_ucp_msg_send_cb(
    void *request, ucs_status_t status, void NA_UNUSED *user_data)
{
    struct na_ucx_op_id *na_ucx_op_id = (struct na_ucx_op_id *) request;
    na_return_t cb_ret = NA_SUCCESS;

    NA_LOG_SUBSYS_DEBUG(
        msg, "ucp_tag_send_nbx() completed (%s)", ucs_status_string(status));

    if (status == UCS_ERR_CANCELED)
        NA_GOTO_DONE(done, cb_ret, NA_CANCELED);
    else
        NA_CHECK_SUBSYS_ERROR(msg, status != UCS_OK, done, cb_ret,
            NA_PROTOCOL_ERROR, "na_ucp_msg_send_cb() failed (%s)",
            ucs_status_string(status));

done:
    na_ucx_complete(na_ucx_op_id, status);
}

/*---------------------------------------------------------------------------*/
static void
na_ucp_msg_recv_unexpected_cb(void *request, ucs_status_t status,
    const ucp_tag_recv_info_t *info, void NA_UNUSED *user_data)
{
    struct na_ucx_op_id *na_ucx_op_id = (struct na_ucx_op_id *) request;
    na_cb_type_t cb_type = na_ucx_op_id->completion_data.callback_info.type;
    na_return_t cb_ret = NA_SUCCESS;

    NA_LOG_SUBSYS_DEBUG(
        msg, "ucp_tag_recv_nbx() completed (%s)", ucs_status_string(status));

    if (status == UCS_ERR_CANCELED)
        NA_GOTO_DONE(done, cb_ret, NA_CANCELED);
    else
        NA_CHECK_SUBSYS_ERROR(msg, status != UCS_OK, done, cb_ret,
            NA_PROTOCOL_ERROR, "ucp_tag_recv_nbx() failed (%s)",
            ucs_status_string(status));

    NA_CHECK_SUBSYS_ERROR(msg, cb_type != NA_CB_RECV_UNEXPECTED, done, cb_ret,
        NA_INVALID_ARG, "Invalid cb_type %d, expected NA_CB_RECV_UNEXPECTED",
        cb_type);
    NA_CHECK_SUBSYS_ERROR(msg,
        (info->sender_tag & ~NA_UCX_TAG_UNEXPECTED) > NA_UCX_MAX_TAG, done,
        cb_ret, NA_OVERFLOW, "Invalid tag value %" PRIu64, info->sender_tag);

    NA_LOG_SUBSYS_DEBUG(msg, "Received msg length=%zu, sender_tag=%zu",
        info->length, info->sender_tag & NA_UCX_TAG_MASK);

done:
    na_ucx_complete(na_ucx_op_id, cb_ret);
}

/*---------------------------------------------------------------------------*/
static void
na_ucp_msg_recv_expected_cb(void *request, ucs_status_t status,
    const ucp_tag_recv_info_t *info, void NA_UNUSED *user_data)
{
    struct na_ucx_op_id *na_ucx_op_id = (struct na_ucx_op_id *) request;
    na_cb_type_t cb_type = na_ucx_op_id->completion_data.callback_info.type;
    na_return_t cb_ret = NA_SUCCESS;

    NA_LOG_SUBSYS_DEBUG(
        msg, "ucp_tag_recv_nbx() completed (%s)", ucs_status_string(status));

    if (status == UCS_ERR_CANCELED)
        NA_GOTO_DONE(done, cb_ret, NA_CANCELED);
    else
        NA_CHECK_SUBSYS_ERROR(msg, status != UCS_OK, done, cb_ret,
            NA_PROTOCOL_ERROR, "ucp_tag_recv_nbx() failed (%s)",
            ucs_status_string(status));

    NA_CHECK_SUBSYS_ERROR(msg, cb_type != NA_CB_RECV_EXPECTED, done, cb_ret,
        NA_INVALID_ARG, "Invalid cb_type %d, expected NA_CB_RECV_EXPECTED",
        cb_type);
    NA_CHECK_SUBSYS_ERROR(msg, info->sender_tag > NA_UCX_MAX_TAG, done, cb_ret,
        NA_OVERFLOW, "Invalid tag value");

    NA_LOG_SUBSYS_DEBUG(msg, "Received msg length=%zu, sender_tag=%zu",
        info->length, info->sender_tag);

done:
    na_ucx_complete(na_ucx_op_id, cb_ret);
}

/*---------------------------------------------------------------------------*/
static struct na_ucx_class *
na_ucx_class_alloc(void)
{
    struct na_ucx_class *na_ucx_class = NULL;
    int rc;

    na_ucx_class = calloc(1, sizeof(*na_ucx_class));
    NA_CHECK_SUBSYS_ERROR_NORET(cls, na_ucx_class == NULL, error,
        "Could not allocate NA private data class");

    /* Init table lock */
    rc = hg_thread_rwlock_init(&na_ucx_class->addr_map.lock);
    NA_CHECK_SUBSYS_ERROR_NORET(
        cls, rc != HG_UTIL_SUCCESS, error, "hg_thread_rwlock_init() failed");

    /* Create address table */
    na_ucx_class->addr_map.map =
        hg_hash_table_new(na_ucx_addr_key_hash, na_ucx_addr_key_equal);
    NA_CHECK_SUBSYS_ERROR_NORET(cls, na_ucx_class->addr_map.map == NULL, error,
        "Could not allocate address table");

    return na_ucx_class;

error:
    if (na_ucx_class)
        na_ucx_class_free(na_ucx_class);

    return NULL;
}

/*---------------------------------------------------------------------------*/
static void
na_ucx_class_free(struct na_ucx_class *na_ucx_class)
{
    if (na_ucx_class->self_addr)
        na_ucx_addr_destroy(na_ucx_class->self_addr);
    if (na_ucx_class->ucp_listener)
        na_ucp_listener_destroy(na_ucx_class->ucp_listener);
    if (na_ucx_class->ucp_worker)
        na_ucp_worker_destroy(na_ucx_class->ucp_worker);
    if (na_ucx_class->ucp_context)
        na_ucp_context_destroy(na_ucx_class->ucp_context);

    if (na_ucx_class->addr_map.map)
        hg_hash_table_free(na_ucx_class->addr_map.map);
    (void) hg_thread_rwlock_destroy(&na_ucx_class->addr_map.lock);

    free(na_ucx_class);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_parse_hostname_info(const char *hostname_info, const char *subnet_info,
    char **net_device_p, struct sockaddr_storage **sockaddr_p)
{
    char *hostname = NULL;
    unsigned int port = 0;
    na_return_t ret = NA_SUCCESS;

    /* Set hostname (use default interface name if no hostname was passed) */
    if (hostname_info) {
        hostname = strdup(hostname_info);
        NA_CHECK_SUBSYS_ERROR(cls, hostname == NULL, done, ret, NA_NOMEM,
            "strdup() of hostname failed");

        /* TODO add support for IPv6 address parsing */

        /* Extract hostname / port */
        if (strstr(hostname, ":")) {
            char *port_str = NULL;
            strtok_r(hostname, ":", &port_str);
            port = (unsigned int) strtoul(port_str, NULL, 10);
        }
    }

    /* TODO add support for IPv6 wildcards */

    if (hostname && strcmp(hostname, "0.0.0.0") != 0) {
        /* Try to get matching IP/device */
        ret = na_ip_check_interface(hostname, port, net_device_p, sockaddr_p);
        NA_CHECK_SUBSYS_NA_ERROR(cls, done, ret, "Could not check interfaces");
    } else {
        char pref_anyip[NI_MAXHOST];
        uint32_t subnet = 0, netmask = 0;

        /* Try to use IP subnet */
        if (subnet_info) {
            ret = na_ip_parse_subnet(subnet_info, &subnet, &netmask);
            NA_CHECK_SUBSYS_NA_ERROR(
                cls, done, ret, "na_ip_parse_subnet() failed");
        }
        ret = na_ip_pref_addr(subnet, netmask, pref_anyip);
        NA_CHECK_SUBSYS_NA_ERROR(cls, done, ret, "na_ip_pref_addr() failed");

        /* Generate IP address (ignore net_device) */
        ret = na_ip_check_interface(pref_anyip, port, NULL, sockaddr_p);
        NA_CHECK_SUBSYS_NA_ERROR(cls, done, ret, "Could not check interfaces");
    }

done:
    free(hostname);
    return ret;
}

/*---------------------------------------------------------------------------*/
static unsigned int
na_ucx_addr_key_hash(hg_hash_table_key_t key)
{
    ucs_sock_addr_t *addr_key = (ucs_sock_addr_t *) key;

    if (addr_key->addr->sa_family == AF_INET)
        return (unsigned int) ((const struct sockaddr_in *) addr_key->addr)
            ->sin_addr.s_addr;
    else
        return (unsigned int) ((const struct sockaddr_in6 *) addr_key->addr)
            ->sin6_addr.__in6_u.__u6_addr32[0];
}

/*---------------------------------------------------------------------------*/
static int
na_ucx_addr_key_equal(hg_hash_table_key_t key1, hg_hash_table_key_t key2)
{
    ucs_sock_addr_t *addr_key1 = (ucs_sock_addr_t *) key1,
                    *addr_key2 = (ucs_sock_addr_t *) key2;

    return (addr_key1->addrlen == addr_key2->addrlen) &&
           (memcmp(&addr_key1->addr, &addr_key2->addr, addr_key1->addrlen));
}

/*---------------------------------------------------------------------------*/
static NA_INLINE struct na_ucx_addr *
na_ucx_addr_map_lookup(struct na_ucx_map *na_ucx_map,
    const struct sockaddr *addr, socklen_t addrlen)
{
    ucs_sock_addr_t sockaddr = {.addr = addr, .addrlen = addrlen};
    hg_hash_table_value_t value = NULL;

    /* Lookup key */
    hg_thread_rwlock_rdlock(&na_ucx_map->lock);
    value =
        hg_hash_table_lookup(na_ucx_map->map, (hg_hash_table_key_t) &sockaddr);
    hg_thread_rwlock_release_rdlock(&na_ucx_map->lock);

    return (value == HG_HASH_TABLE_NULL) ? NULL : (struct na_ucx_addr *) value;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_addr_map_insert(struct na_ucx_map *na_ucx_map,
    const struct sockaddr *addr, socklen_t addrlen,
    struct na_ucx_addr **na_ucx_addr_p)
{
    struct na_ucx_addr *na_ucx_addr = NULL;
    ucs_sock_addr_t addr_key = {.addr = addr, .addrlen = addrlen};
    na_return_t ret;
    int rc;

    hg_thread_rwlock_wrlock(&na_ucx_map->lock);

    /* Look up again to prevent race between lock release/acquire */
    na_ucx_addr = (struct na_ucx_addr *) hg_hash_table_lookup(
        na_ucx_map->map, (hg_hash_table_key_t) &addr_key);
    if (na_ucx_addr) {
        ret = NA_EXIST; /* Entry already exists */
        goto done;
    }

    /* Allocate address */
    ret = na_ucx_addr_create(addr, addrlen, &na_ucx_addr);
    NA_CHECK_SUBSYS_NA_ERROR(addr, done, ret, "Could not allocate NA UCX addr");

    /* Insert new value */
    rc = hg_hash_table_insert(na_ucx_map->map,
        (hg_hash_table_key_t) &na_ucx_addr->addr_key,
        (hg_hash_table_value_t) na_ucx_addr);
    NA_CHECK_SUBSYS_ERROR(
        addr, rc == 0, error, ret, NA_NOMEM, "hg_hash_table_insert() failed");

done:
    hg_thread_rwlock_release_wrlock(&na_ucx_map->lock);

    *na_ucx_addr_p = na_ucx_addr;

    return NA_SUCCESS;

error:
    hg_thread_rwlock_release_wrlock(&na_ucx_map->lock);
    if (na_ucx_addr)
        na_ucx_addr_destroy(na_ucx_addr);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_addr_map_remove(struct na_ucx_map *na_ucx_map, na_uint64_t key)
{
    hg_hash_table_key_t key_ptr = (hg_hash_table_key_t) &key;
    na_return_t ret = NA_SUCCESS;
    int rc;

    hg_thread_rwlock_wrlock(&na_ucx_map->lock);
    if (hg_hash_table_lookup(na_ucx_map->map, key_ptr) == HG_HASH_TABLE_NULL)
        goto unlock;

    rc = hg_hash_table_remove(na_ucx_map->map, key_ptr);
    NA_CHECK_SUBSYS_ERROR_DONE(addr, rc == 0, "Could not remove key");

unlock:
    hg_thread_rwlock_release_wrlock(&na_ucx_map->lock);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_addr_create(const struct sockaddr *addr, socklen_t addrlen,
    struct na_ucx_addr **na_ucx_addr_p)
{
    struct na_ucx_addr *na_ucx_addr;
    na_return_t ret;

    na_ucx_addr = calloc(1, sizeof(*na_ucx_addr));
    NA_CHECK_SUBSYS_ERROR(addr, na_ucx_addr == NULL, error, ret, NA_NOMEM,
        "Could not allocate NA UCX addr");

    if (addr)
        memcpy(&na_ucx_addr->ss_addr, addr, addrlen);

    /* Point key back to ss_addr */
    na_ucx_addr->addr_key.addr =
        (const struct sockaddr *) &na_ucx_addr->ss_addr;
    na_ucx_addr->addr_key.addrlen = addrlen;

    na_ucx_addr->ucp_ep = NULL;
    hg_atomic_init32(&na_ucx_addr->refcount, 1);
    hg_atomic_init32(&na_ucx_addr->status, 0);

    if (addr) {
        char host_string[NI_MAXHOST];
        char serv_string[NI_MAXSERV];
        int rc;

        rc = getnameinfo(addr, addrlen, host_string, sizeof(host_string),
            serv_string, sizeof(serv_string), NI_NUMERICHOST | NI_NUMERICSERV);
        NA_CHECK_SUBSYS_ERROR(addr, rc != 0, error, ret, NA_PROTOCOL_ERROR,
            "getnameinfo() failed (%s)", gai_strerror(rc));

        NA_LOG_SUBSYS_DEBUG(
            addr, "Created new address for %s:%s", host_string, serv_string);
    }

    *na_ucx_addr_p = na_ucx_addr;

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_ucx_addr_destroy(struct na_ucx_addr *na_ucx_addr)
{
    if (na_ucx_addr->ucp_ep)
        ucp_ep_destroy(na_ucx_addr->ucp_ep);
    free(na_ucx_addr);
}

/*---------------------------------------------------------------------------*/
static NA_INLINE void
na_ucx_addr_ref_incr(struct na_ucx_addr *na_ucx_addr)
{
    hg_atomic_incr32(&na_ucx_addr->refcount);
}

/*---------------------------------------------------------------------------*/
static NA_INLINE void
na_ucx_addr_ref_decr(struct na_ucx_addr *na_ucx_addr)
{
    if (hg_atomic_decr32(&na_ucx_addr->refcount) == 0) {
        free(na_ucx_addr);
    }
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_addr_resolve(
    struct na_ucx_class *na_ucx_class, struct na_ucx_addr *na_ucx_addr)
{
    na_return_t ret;

    /* Let only one thread at a time resolving the address */
    if (!hg_atomic_cas32(&na_ucx_addr->status, 0, NA_UCX_ADDR_RESOLVING))
        return NA_SUCCESS;

    /* Create new endpoint */
    ret = na_ucp_connect(na_ucx_class->ucp_worker, na_ucx_addr->addr_key.addr,
        na_ucx_addr->addr_key.addrlen, na_ucp_ep_error_cb,
        (void *) na_ucx_class, &na_ucx_addr->ucp_ep);
    NA_CHECK_SUBSYS_NA_ERROR(
        addr, error, ret, "Could not connect UCP endpoint");

    /* Generate connection ID */
    na_ucx_addr->conn_id = na_ucp_conn_id_gen();

    /* Exchange IDs so that we can later use that ID to identify msg senders */
    ret = na_ucp_conn_id_exchange(na_ucx_addr->ucp_ep, &na_ucx_addr->conn_id,
        &na_ucx_addr->remote_conn_id, na_ucx_addr);
    NA_CHECK_SUBSYS_NA_ERROR(
        addr, error, ret, "Could not exchange connection IDs");

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE void
na_ucx_op_retry(struct na_ucx_class *na_ucx_class, struct na_sm_op_id *na_sm_op_id)
{
    struct na_ucx_op_queue *retry_op_queue =
        &na_ucx_class->retry_op_queue;

    NA_LOG_SUBSYS_DEBUG(op, "Pushing %p for retry", (void *) na_sm_op_id);

    /* Push op ID to retry queue */
    hg_thread_spin_lock(&retry_op_queue->lock);
    HG_QUEUE_PUSH_TAIL(&retry_op_queue->queue, na_sm_op_id, entry);
    hg_atomic_or32(&na_sm_op_id->status, NA_SM_OP_QUEUED);
    hg_thread_spin_unlock(&retry_op_queue->lock);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_complete(struct na_ucx_op_id *na_ucx_op_id, na_return_t cb_ret)
{
    struct na_cb_info *callback_info = NULL;
    na_return_t ret;
    hg_util_int32_t status;

    /* Mark op id as completed before checking for cancelation */
    status = hg_atomic_or32(&na_ucx_op_id->status, NA_UCX_OP_COMPLETED);

    /* Init callback info */
    callback_info = &na_ucx_op_id->completion_data.callback_info;

    /* Set callback ret */
    callback_info->ret = cb_ret;

    /* Check for current status before completing */
    if (status & NA_UCX_OP_CANCELED) {
        /* If it was canceled while being processed, set callback ret
         * accordingly */
        NA_LOG_SUBSYS_DEBUG(
            op, "Operation ID %p is canceled", (void *) na_ucx_op_id);
    } else if (status & NA_UCX_OP_ERRORED) {
        /* If it was errored, set callback ret accordingly */
        NA_LOG_SUBSYS_DEBUG(
            op, "Operation ID %p is errored", (void *) na_ucx_op_id);
    }

    switch (callback_info->type) {
        case NA_CB_RECV_UNEXPECTED:
            if (callback_info->ret != NA_SUCCESS) {
                /* In case of cancellation where no recv'd data */
                callback_info->info.recv_unexpected.actual_buf_size = 0;
                callback_info->info.recv_unexpected.source = NA_ADDR_NULL;
                callback_info->info.recv_unexpected.tag = 0;
            } else {
                /* Increment addr ref count */
                na_ucx_addr_ref_incr(na_ucx_op_id->addr);

                /* Fill callback info */
                // callback_info->info.recv_unexpected.actual_buf_size =
                //     na_ucx_op_id->info.msg.actual_buf_size;
                // callback_info->info.recv_unexpected.source =
                //     (na_addr_t) na_ucx_op_id->addr;
                // callback_info->info.recv_unexpected.tag =
                //     na_ucx_op_id->info.msg.tag;
            }
            break;
        case NA_CB_RECV_EXPECTED:
            /* Check buf_size and msg_size */
            // NA_CHECK_SUBSYS_ERROR(msg,
            //     na_ucx_op_id->info.msg.actual_buf_size >
            //         na_ucx_op_id->info.msg.buf_size,
            //     out, ret, NA_MSGSIZE,
            //     "Expected recv msg size too large for buffer");
            break;
        case NA_CB_SEND_UNEXPECTED:
        case NA_CB_SEND_EXPECTED:
            break;
        case NA_CB_PUT:
        case NA_CB_GET:
            // /* Can free extra IOVs here */
            // if (na_ucx_op_id->info.rma.local_iovcnt > na_ucx_IOV_STATIC_MAX)
            // {
            //     free(na_ucx_op_id->info.rma.local_iov.d);
            //     na_ucx_op_id->info.rma.local_iov.d = NULL;
            // }
            // if (na_ucx_op_id->info.rma.remote_iovcnt > na_ucx_IOV_STATIC_MAX)
            // {
            //     free(na_ucx_op_id->info.rma.remote_iov.d);
            //     na_ucx_op_id->info.rma.remote_iov.d = NULL;
            // }
            break;
        default:
            NA_GOTO_SUBSYS_ERROR(op, error, ret, NA_INVALID_ARG,
                "Operation type %d not supported", callback_info->type);
            break;
    }

    /* Add OP to NA completion queue */
    na_cb_completion_add(na_ucx_op_id->context, &na_ucx_op_id->completion_data);

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE void
na_ucx_release(void *arg)
{
    struct na_ucx_op_id *na_ucx_op_id = (struct na_ucx_op_id *) arg;

    NA_CHECK_SUBSYS_WARNING(op,
        na_ucx_op_id &&
            (!(hg_atomic_get32(&na_ucx_op_id->status) & NA_UCX_OP_COMPLETED)),
        "Releasing resources from an uncompleted operation");

    if (na_ucx_op_id->addr) {
        na_ucx_addr_ref_decr(na_ucx_op_id->addr);
        na_ucx_op_id->addr = NULL;
    }
}

/********************/
/* Plugin callbacks */
/********************/

static na_bool_t
na_ucx_check_protocol(const char *protocol_name)
{
    ucp_config_t *config = NULL;
    ucp_params_t params = {.field_mask = UCP_PARAM_FIELD_FEATURES,
        .features = UCP_FEATURE_TAG | UCP_FEATURE_RMA | UCP_FEATURE_STREAM};
    ucp_context_h context = NULL;
    ucs_status_t status;
    na_bool_t accept = NA_FALSE;

    status = ucp_config_read(NULL, NULL, &config);
    NA_CHECK_SUBSYS_ERROR_NORET(cls, status != UCS_OK, done,
        "ucp_config_read() failed (%s)", ucs_status_string(status));

    /* Print UCX config */
    // NA_LOG_SUBSYS_DEBUG_FUNC(cls,
    //     ucp_config_print(config, hg_log_get_stream_debug(),
    //         "NA UCX class configuration",
    //         UCS_CONFIG_PRINT_CONFIG | UCS_CONFIG_PRINT_HEADER |
    //             UCS_CONFIG_PRINT_DOC | UCS_CONFIG_PRINT_HIDDEN),
    //     "UCX global configuration");

    /* Try to use requested protocol */
    status = ucp_config_modify(config, "TLS", protocol_name);
    NA_CHECK_SUBSYS_ERROR_NORET(cls, status != UCS_OK, done,
        "ucp_config_modify() failed (%s)", ucs_status_string(status));

    status = ucp_init(&params, config, &context);
    if (status == UCS_OK) {
        accept = NA_TRUE;
        ucp_cleanup(context);
    }

done:
    if (config)
        ucp_config_release(config);

    return accept;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_initialize(
    na_class_t *na_class, const struct na_info *na_info, na_bool_t listen)
{
    struct na_ucx_class *na_ucx_class = NULL;
#ifdef NA_UCX_HAS_LIB_QUERY
    ucp_lib_attr_t ucp_lib_attrs;
#endif
    char *net_device = NULL;
    struct sockaddr_storage *listen_ss_addr = NULL,
                            *ucp_listener_ss_addr = NULL;
    ucp_config_t *config;
    na_bool_t no_wait = NA_FALSE;
    na_size_t unexpected_size_max = 0, expected_size_max = 0;
    ucs_thread_mode_t context_thread_mode = UCS_THREAD_MODE_SINGLE,
                      worker_thread_mode = UCS_THREAD_MODE_MULTI;
    na_return_t ret;
    ucs_status_t status;

    if (na_info->na_init_info != NULL) {
        /* Progress mode */
        if (na_info->na_init_info->progress_mode & NA_NO_BLOCK)
            no_wait = NA_TRUE;
        /* Max contexts */
        // if (na_info->na_init_info->max_contexts)
        //     context_max = na_info->na_init_info->max_contexts;
        /* Sizes */
        if (na_info->na_init_info->max_unexpected_size)
            unexpected_size_max = na_info->na_init_info->max_unexpected_size;
        if (na_info->na_init_info->max_expected_size)
            expected_size_max = na_info->na_init_info->max_expected_size;
        /* Thread mode */
        if ((na_info->na_init_info->max_contexts > 1) &&
            !(na_info->na_init_info->thread_mode & NA_THREAD_MODE_SINGLE))
            context_thread_mode = UCS_THREAD_MODE_MULTI;

        if (na_info->na_init_info->thread_mode & NA_THREAD_MODE_SINGLE_CTX)
            worker_thread_mode = UCS_THREAD_MODE_SINGLE;
    }

#ifdef NA_UCX_HAS_LIB_QUERY
    ucp_lib_attrs.field_mask = UCP_LIB_ATTR_FIELD_MAX_THREAD_LEVEL;
    status = ucp_lib_query(&ucp_lib_attrs);
    NA_CHECK_SUBSYS_ERROR(cls, status != UCS_OK, error, ret, NA_PROTOCOL_ERROR,
        "ucp_context_query: %s", ucs_status_string(status));
    NA_CHECK_SUBSYS_ERROR(cls,
        (ucp_lib_attrs.field_mask & UCP_LIB_ATTR_FIELD_MAX_THREAD_LEVEL) == 0,
        error, ret, NA_PROTONOSUPPORT,
        "lib attributes contain no max thread level");

    /* Best effort to ensure thread safety
     * (no error to allow for UCS_THREAD_MODE_SERIALIZED) */
    if (worker_thread_mode != UCS_THREAD_MODE_SINGLE &&
        ucp_lib_attrs.max_thread_level == UCS_THREAD_MODE_SERIALIZED) {
        worker_thread_mode = UCS_THREAD_MODE_SERIALIZED;
        NA_LOG_WARNING("Max worker thread level is: %s",
            ucs_thread_mode_names[worker_thread_mode]);
    }
#endif

    /* Parse hostname info and get device / listener IP */
    ret = na_ucx_parse_hostname_info(na_info->host_name,
        (na_info->na_init_info && na_info->na_init_info->ip_subnet)
            ? na_info->na_init_info->ip_subnet
            : NULL,
        &net_device, (listen) ? &listen_ss_addr : NULL);
    NA_CHECK_SUBSYS_NA_ERROR(
        cls, error, ret, "na_ucx_parse_hostname_info() failed");

    /* Create new UCX class */
    na_ucx_class = na_ucx_class_alloc();
    NA_CHECK_SUBSYS_ERROR(cls, na_ucx_class == NULL, error, ret, NA_NOMEM,
        "Could not allocate NA UCX class");

    /* Keep a copy of the protocol name */
    na_ucx_class->protocol_name = (na_info->protocol_name)
                                      ? strdup(na_info->protocol_name)
                                      : strdup(NA_UCX_PROTOCOL_DEFAULT);
    NA_CHECK_SUBSYS_ERROR(cls, na_ucx_class->protocol_name == NULL, error, ret,
        NA_NOMEM, "Could not dup NA protocol name");

    /* Set wait mode */
    na_ucx_class->no_wait = no_wait;

    /* TODO may need to query UCX */
    na_ucx_class->unexpected_size_max =
        unexpected_size_max ? unexpected_size_max : NA_UCX_MSG_SIZE_MAX;
    na_ucx_class->expected_size_max =
        expected_size_max ? expected_size_max : NA_UCX_MSG_SIZE_MAX;

    /* Init config options */
    ret = na_ucp_config_init(na_info->protocol_name, net_device, &config);
    NA_CHECK_SUBSYS_NA_ERROR(
        cls, error, ret, "Could not initialize UCX config");

    /* Create UCP context and release config */
    ret = na_ucp_context_create(config, no_wait, context_thread_mode,
        &na_ucx_class->ucp_context, &na_ucx_class->ucp_request_size);
    na_ucp_config_release(config);
    NA_CHECK_SUBSYS_NA_ERROR(cls, error, ret, "Could not create UCX context");

    /* Create single worker */
    ret = na_ucp_worker_create(na_ucx_class->ucp_context, worker_thread_mode,
        &na_ucx_class->ucp_worker);
    NA_CHECK_SUBSYS_NA_ERROR(cls, error, ret, "Could not create UCX worker");

    /* Create listener if we're listening */
    if (listen) {
        ret = na_ucp_listener_create(na_ucx_class->ucp_worker,
            (const struct sockaddr *) listen_ss_addr, sizeof(*listen_ss_addr),
            (void *) na_ucx_class, &na_ucx_class->ucp_listener,
            &ucp_listener_ss_addr);
        NA_CHECK_SUBSYS_NA_ERROR(
            cls, error, ret, "Could not create UCX listener");

        /* No longer needed */
        free(listen_ss_addr);
        listen_ss_addr = NULL;
    }

    /* Create self address */
    ret = na_ucx_addr_create((const struct sockaddr *) ucp_listener_ss_addr,
        sizeof(*ucp_listener_ss_addr), &na_ucx_class->self_addr);
    free(ucp_listener_ss_addr);
    NA_CHECK_SUBSYS_NA_ERROR(cls, error, ret, "Could not create self address");

    na_class->plugin_class = (void *) na_ucx_class;

    return NA_SUCCESS;

error:
    free(listen_ss_addr);
    if (na_ucx_class)
        na_ucx_class_free(na_ucx_class);

    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_finalize(na_class_t *na_class)
{
    struct na_ucx_class *na_ucx_class = NA_UCX_CLASS(na_class);
    na_return_t ret = NA_SUCCESS;

    if (na_ucx_class == NULL)
        return ret;

    NA_CHECK_SUBSYS_ERROR(cls, hg_atomic_get32(&na_ucx_class->ncontexts) != 0,
        done, ret, NA_BUSY, "Contexts were not destroyed (%d remaining)",
        hg_atomic_get32(&na_ucx_class->ncontexts));

    na_ucx_class_free(na_ucx_class);
    na_class->plugin_class = NULL;

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_op_id_t *
na_ucx_op_create(na_class_t *na_class)
{
    struct na_ucx_op_id *na_ucx_op_id = NULL;

    /* When using UCP requests, OP IDs must have enough space to fit the
     * UCP request data as a header */
    na_ucx_op_id = hg_mem_header_alloc(NA_UCX_CLASS(na_class)->ucp_request_size,
        alignof(struct na_ucx_op_id), sizeof(*na_ucx_op_id));
    NA_CHECK_SUBSYS_ERROR_NORET(op, na_ucx_op_id == NULL, out,
        "Could not allocate NA OFI operation ID");

    memset(na_ucx_op_id, 0, sizeof(struct na_ucx_op_id));

    /* Completed by default */
    hg_atomic_init32(&na_ucx_op_id->status, NA_UCX_OP_COMPLETED);

    /* Set op ID release callbacks */
    na_ucx_op_id->completion_data.plugin_callback = na_ucx_release;
    na_ucx_op_id->completion_data.plugin_callback_args = na_ucx_op_id;

out:
    return (na_op_id_t *) na_ucx_op_id;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_op_destroy(na_class_t NA_UNUSED *na_class, na_op_id_t *op_id)
{
    struct na_ucx_op_id *na_ucx_op_id = (struct na_ucx_op_id *) op_id;
    na_return_t ret = NA_SUCCESS;

    NA_CHECK_SUBSYS_ERROR(op,
        !(hg_atomic_get32(&na_ucx_op_id->status) & NA_UCX_OP_COMPLETED), done,
        ret, NA_BUSY, "Attempting to free OP ID that was not completed");

    hg_mem_header_free(NA_UCX_CLASS(na_class)->ucp_request_size,
        alignof(struct na_ucx_op_id), na_ucx_op_id);

done:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_addr_lookup(na_class_t *na_class, const char *name, na_addr_t *addr_p)
{
    char host_string[NI_MAXHOST];
    char serv_string[NI_MAXSERV];
    struct addrinfo hints, *hostname_res = NULL;
    struct na_ucx_class *na_ucx_class = NA_UCX_CLASS(na_class);
    struct na_ucx_addr *na_ucx_addr = NULL;
    na_return_t ret;
    int rc;

    /* Only support 'all' or same protocol */
    NA_CHECK_SUBSYS_ERROR(fatal,
        strncmp(name, "all", strlen("all")) &&
            strncmp(name, na_ucx_class->protocol_name,
                strlen(na_ucx_class->protocol_name)),
        error, ret, NA_PROTOCOL_ERROR,
        "Protocol not supported by this class (%s)",
        na_ucx_class->protocol_name);

    /* Retrieve address */
    rc = sscanf(name, "%*[^:]://%[^:]:%s", host_string, serv_string);
    NA_CHECK_SUBSYS_ERROR(addr, rc != 2, error, ret, NA_PROTONOSUPPORT,
        "Malformed address string");

    NA_LOG_SUBSYS_DEBUG(addr, "Host %s, Serv %s", host_string, serv_string);

    /* Resolve address */
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    hints.ai_protocol = 0;
    rc = getaddrinfo(host_string, serv_string, &hints, &hostname_res);
    NA_CHECK_ERROR(rc != 0, error, ret, NA_PROTOCOL_ERROR,
        "getaddrinfo() failed (%s)", gai_strerror(rc));

    /* Lookup address from table */
    na_ucx_addr = na_ucx_addr_map_lookup(&na_ucx_class->addr_map,
        hostname_res->ai_addr, hostname_res->ai_addrlen);

    if (!na_ucx_addr) {
        na_return_t na_ret;

        NA_LOG_SUBSYS_DEBUG(addr,
            "Address for %s was not found, attempting to insert it",
            host_string);

        /* Insert new entry and create new address if needed */
        na_ret = na_ucx_addr_map_insert(&na_ucx_class->addr_map,
            hostname_res->ai_addr, hostname_res->ai_addrlen, &na_ucx_addr);
        freeaddrinfo(hostname_res);
        NA_CHECK_SUBSYS_ERROR(addr, na_ret != NA_SUCCESS && na_ret != NA_EXIST,
            error, ret, na_ret, "Could not insert new address");
    } else {
        freeaddrinfo(hostname_res);
        NA_LOG_SUBSYS_DEBUG(addr, "Address for %s was found", host_string);
    }

    na_ucx_addr_ref_incr(na_ucx_addr);

    *addr_p = (na_addr_t) na_ucx_addr;

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_return_t
na_ucx_addr_free(na_class_t NA_UNUSED *na_class, na_addr_t addr)
{
    na_ucx_addr_ref_decr((struct na_ucx_addr *) addr);

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_return_t
na_ucx_addr_self(na_class_t *na_class, na_addr_t *addr_p)
{
    na_ucx_addr_ref_incr(NA_UCX_CLASS(na_class)->self_addr);
    *addr_p = (na_addr_t) NA_UCX_CLASS(na_class)->self_addr;

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_return_t
na_ucx_addr_dup(
    na_class_t NA_UNUSED *na_class, na_addr_t addr, na_addr_t *new_addr)
{
    na_ucx_addr_ref_incr((struct na_ucx_addr *) addr);
    *new_addr = addr;

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_bool_t
na_ucx_addr_cmp(
    na_class_t NA_UNUSED *na_class, na_addr_t addr1, na_addr_t addr2)
{
    return addr1 == addr2;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_bool_t
na_ucx_addr_is_self(na_class_t *na_class, na_addr_t addr)
{
    return NA_UCX_CLASS(na_class)->self_addr == (struct na_ucx_addr *) addr;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_addr_to_string(
    na_class_t *na_class, char *buf, na_size_t *buf_size_p, na_addr_t addr)
{
    struct na_ucx_class *na_ucx_class = NA_UCX_CLASS(na_class);
    struct na_ucx_addr *na_ucx_addr = (struct na_ucx_addr *) addr;
    char host_string[NI_MAXHOST];
    char serv_string[NI_MAXSERV];
    na_size_t buf_size;
    na_return_t ret;
    int rc;

    NA_CHECK_SUBSYS_ERROR(addr, na_ucx_addr->addr_key.addrlen == 0, error, ret,
        NA_OPNOTSUPPORTED, "Cannot convert address to string");

    rc = getnameinfo((const struct sockaddr *) &na_ucx_addr->ss_addr,
        sizeof(na_ucx_addr->ss_addr), host_string, sizeof(host_string),
        serv_string, sizeof(serv_string), NI_NUMERICHOST | NI_NUMERICSERV);
    NA_CHECK_SUBSYS_ERROR(addr, rc != 0, error, ret, NA_PROTOCOL_ERROR,
        "getnameinfo() failed (%s)", gai_strerror(rc));

    buf_size = strlen(host_string) + strlen(serv_string) +
               strlen(na_ucx_class->protocol_name) + 5;
    if (buf) {
        rc = snprintf(buf, buf_size, "%s://%s:%s", na_ucx_class->protocol_name,
            host_string, serv_string);
        NA_CHECK_SUBSYS_ERROR(addr, rc < 0 || rc > (int) buf_size, error, ret,
            NA_OVERFLOW, "snprintf() failed or name truncated, rc: %d", rc);

        NA_LOG_SUBSYS_DEBUG(addr, "Converted UCX address (%p) to string (%s)",
            (void *) na_ucx_addr, buf);
    }
    *buf_size_p = buf_size;

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_size_t
na_ucx_addr_get_serialize_size(na_class_t NA_UNUSED *nacl, na_addr_t _addr)
{
    // na_ucx_addr_t *addr = _addr;

    // return sizeof(uint16_t) + addr->addrlen;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_addr_serialize(
    na_class_t NA_UNUSED *nacl, void *buf, na_size_t buf_size, na_addr_t _addr)
{
    // na_ucx_addr_t *addr = _addr;
    // uint16_t addrlen;

    // if (buf_size < sizeof(addrlen) + addr->addrlen) {
    //     NA_LOG_ERROR("Buffer size too small for serializing address");
    //     return NA_OVERFLOW;
    // }

    // if (UINT16_MAX < addr->addrlen) {
    //     NA_LOG_ERROR("Length field too narrow for serialized address
    //     length"); return NA_OVERFLOW;
    // }

    // addrlen = (uint16_t) addr->addrlen;
    // memcpy(buf, &addrlen, sizeof(addrlen));
    // memcpy((char *) buf + sizeof(addrlen), &addr->addr[0], addrlen);

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_addr_deserialize(
    na_class_t *nacl, na_addr_t *addrp, const void *buf, na_size_t buf_size)
{
    // uint16_t addrlen;
    // na_ucx_addr_t *addr;

    // if (buf_size < sizeof(addrlen)) {
    //     NA_LOG_ERROR("Buffer too short for address length");
    //     return NA_INVALID_ARG;
    // }

    // memcpy(&addrlen, buf, sizeof(addrlen));

    // if (buf_size < sizeof(addrlen) + addrlen) {
    //     NA_LOG_ERROR("Buffer truncates address");
    //     return NA_INVALID_ARG;
    // }

    // if (addrlen < 1) {
    //     NA_LOG_ERROR("Address length is zero");
    //     return NA_INVALID_ARG;
    // }

    // if ((addr = malloc(sizeof(*addr) + addrlen)) == NULL)
    //     return NA_NOMEM;

    // *addr = (na_ucx_addr_t){
    //     .wire_cache = {.wire_id = wire_id_nil,
    //         .sender_id = sender_id_nil,
    //         .ctx = NULL,
    //         .ep = NULL,
    //         .owner = addr,
    //         .mutcnt = 0,
    //         .deferrals =
    //         HG_QUEUE_HEAD_INITIALIZER(addr->wire_cache.deferrals)},
    //     .refcount = 1,
    //     .addrlen = addrlen};
    // memcpy(&addr->addr[0], (const char *) buf + sizeof(addrlen), addrlen);

    // *addrp = na_ucx_addr_dedup(nacl, addr);

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_size_t
na_ucx_msg_get_max_unexpected_size(const na_class_t *na_class)
{
    return NA_UCX_CLASS(na_class)->unexpected_size_max;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_size_t
na_ucx_msg_get_max_expected_size(const na_class_t *na_class)
{
    return NA_UCX_CLASS(na_class)->expected_size_max;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_tag_t
na_ucx_msg_get_max_tag(const na_class_t *na_class)
{
    return NA_UCX_MAX_TAG;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_msg_send_unexpected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
    void NA_UNUSED *plugin_data, na_addr_t dest_addr,
    na_uint8_t NA_UNUSED dest_id, na_tag_t tag, na_op_id_t *op_id)
{
    struct na_ucx_addr *na_ucx_addr = (struct na_ucx_addr *) dest_addr;
    struct na_ucx_op_id *na_ucx_op_id = (struct na_ucx_op_id *) op_id;
    na_return_t ret;

    /* Check op_id */
    NA_CHECK_SUBSYS_ERROR(op, na_ucx_op_id == NULL, error, ret, NA_INVALID_ARG,
        "Invalid operation ID");
    NA_CHECK_SUBSYS_ERROR(op,
        !(hg_atomic_get32(&na_ucx_op_id->status) & NA_UCX_OP_COMPLETED), error,
        ret, NA_BUSY, "Attempting to use OP ID that was not completed");

    NA_UCX_OP_RESET(na_ucx_op_id, context, NA_CB_SEND_UNEXPECTED, callback, arg,
        na_ucx_addr);

    /* TODO we assume that buf remains valid (safe because we pre-allocate
     * buffers) */
    na_ucx_op_id->info.msg = (struct na_ucx_msg_info){.buf.const_ptr = buf,
        .buf_size = buf_size,
        .actual_buf_size = buf_size,
        .tag = tag};

    if (!(hg_atomic_get32(na_ucx_addr->status) & NA_UCX_ADDR_RESOLVED)) {
        ret = na_ucx_addr_resolve(NA_UCX_CLASS(na_class), na_ucx_addr);
        NA_CHECK_NA_ERROR(error, ret, "Could not resolve address");

        na_ucx_op_retry(NA_UCX_CLASS(na_class), na_ucx_op_id);
    } else {
        ret = na_ucp_msg_send(na_ucx_addr->ucp_ep, buf, buf_size,
            na_ucp_tag_gen(tag, NA_TRUE, na_ucx_addr->remote_conn_id),
            na_ucx_op_id);
        NA_CHECK_NA_ERROR(error, ret, "Could not post unexpected msg");
    }

    return NA_SUCCESS;

error:
    NA_UCX_OP_RELEASE(na_ucx_op_id);
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_msg_recv_unexpected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, void *buf, na_size_t buf_size,
    void *plugin_data, na_op_id_t *op_id)
{
    struct na_ucx_op_id *na_ucx_op_id = (struct na_ucx_op_id *) op_id;
    na_return_t ret;

    /* Check op_id */
    NA_CHECK_SUBSYS_ERROR(op, na_ucx_op_id == NULL, error, ret, NA_INVALID_ARG,
        "Invalid operation ID");
    NA_CHECK_SUBSYS_ERROR(op,
        !(hg_atomic_get32(&na_ucx_op_id->status) & NA_UCX_OP_COMPLETED), error,
        ret, NA_BUSY, "Attempting to use OP ID that was not completed");

    NA_UCX_OP_RESET_NO_ADDR(
        na_ucx_op_id, context, NA_CB_RECV_UNEXPECTED, callback, arg);

    /* We assume buf remains valid (safe because we pre-allocate buffers) */
    na_ucx_op_id->info.msg = (struct na_ucx_msg_info){
        .buf.ptr = buf, .buf_size = buf_size, .actual_buf_size = 0, .tag = 0};

    ret = na_ucp_msg_recv(NA_UCX_CLASS(na_class)->ucp_worker, buf, buf_size,
        NA_UCX_TAG_UNEXPECTED, NA_UCX_TAG_UNEXPECTED, na_ucx_op_id,
        na_ucp_msg_recv_unexpected_cb);

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_msg_send_expected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
    void NA_UNUSED *plugin_data, na_addr_t dest_addr,
    na_uint8_t NA_UNUSED dest_id, na_tag_t tag, na_op_id_t *op_id)
{
    struct na_ucx_addr *na_ucx_addr = (struct na_ucx_addr *) dest_addr;
    struct na_ucx_op_id *na_ucx_op_id = (struct na_ucx_op_id *) op_id;
    na_return_t ret;

    /* Check op_id */
    NA_CHECK_SUBSYS_ERROR(op, na_ucx_op_id == NULL, error, ret, NA_INVALID_ARG,
        "Invalid operation ID");
    NA_CHECK_SUBSYS_ERROR(op,
        !(hg_atomic_get32(&na_ucx_op_id->status) & NA_UCX_OP_COMPLETED), error,
        ret, NA_BUSY, "Attempting to use OP ID that was not completed");

    NA_UCX_OP_RESET(
        na_ucx_op_id, context, NA_CB_SEND_EXPECTED, callback, arg, na_ucx_addr);

    /* TODO we assume that buf remains valid (safe because we pre-allocate
     * buffers) */
    na_ucx_op_id->info.msg = (struct na_ucx_msg_info){.buf.const_ptr = buf,
        .buf_size = buf_size,
        .actual_buf_size = buf_size,
        .tag = tag};

    if (!na_ucx_addr->ucp_ep)
        na_ucx_addr_resolve(NA_UCX_CLASS(na_class), na_ucx_addr);

    ret = na_ucp_msg_send(na_ucx_addr->ucp_ep, buf, buf_size,
        na_ucp_tag_gen(tag, NA_FALSE, na_ucx_addr->remote_conn_id),
        na_ucx_op_id);
    NA_CHECK_NA_ERROR(error, ret, "Could not post expected msg send");

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_msg_recv_expected(na_class_t *na_class, na_context_t *context,
    na_cb_t callback, void *arg, void *buf, na_size_t buf_size,
    void NA_UNUSED *plugin_data, na_addr_t source_addr,
    na_uint8_t NA_UNUSED source_id, na_tag_t tag, na_op_id_t *op_id)
{
    struct na_ucx_addr *na_ucx_addr = (struct na_ucx_addr *) source_addr;
    struct na_ucx_op_id *na_ucx_op_id = (struct na_ucx_op_id *) op_id;
    na_return_t ret;

    /* Check op_id */
    NA_CHECK_SUBSYS_ERROR(op, na_ucx_op_id == NULL, error, ret, NA_INVALID_ARG,
        "Invalid operation ID");
    NA_CHECK_SUBSYS_ERROR(op,
        !(hg_atomic_get32(&na_ucx_op_id->status) & NA_UCX_OP_COMPLETED), error,
        ret, NA_BUSY, "Attempting to use OP ID that was not completed");

    NA_UCX_OP_RESET(
        na_ucx_op_id, context, NA_CB_RECV_EXPECTED, callback, arg, na_ucx_addr);

    /* We assume buf remains valid (safe because we pre-allocate buffers) */
    na_ucx_op_id->info.msg = (struct na_ucx_msg_info){
        .buf.ptr = buf, .buf_size = buf_size, .actual_buf_size = 0, .tag = tag};

    ret = na_ucp_msg_recv(NA_UCX_CLASS(na_class)->ucp_worker, buf, buf_size,
        tag, NA_UCX_TAG_MASK, na_ucx_op_id, na_ucp_msg_recv_expected_cb);

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_mem_handle_create(na_class_t *nacl, void *buf, na_size_t buf_size,
    unsigned long NA_UNUSED flags, na_mem_handle_t *mhp)
{
    // const ucp_mem_map_params_t params = {
    //     .field_mask =
    //         UCP_MEM_MAP_PARAM_FIELD_ADDRESS | UCP_MEM_MAP_PARAM_FIELD_LENGTH,
    //     .address = buf,
    //     .length = buf_size};
    // const na_ucx_class_t *nucl = na_ucx_class_const(nacl);
    // ucs_status_t status;
    // na_mem_handle_t mh;

    // if ((mh = zalloc(sizeof(*mh))) == NULL)
    //     return NA_NOMEM;

    // hg_atomic_set32(&mh->kind, na_ucx_mem_local);
    // mh->handle.local.buf = buf;
    // status = ucp_mem_map(nucl->uctx, &params, &mh->handle.local.mh);

    // if (status != UCS_OK) {
    //     free(mh);
    //     return NA_PROTOCOL_ERROR;
    // }

    // *mhp = mh;
    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_mem_handle_free(na_class_t *nacl, na_mem_handle_t mh)
{
    // const na_ucx_class_t *nucl = na_ucx_class_const(nacl);
    // ucs_status_t status;

    // switch (hg_atomic_get32(&mh->kind)) {
    //     case na_ucx_mem_local:
    //         status = ucp_mem_unmap(nucl->uctx, mh->handle.local.mh);
    //         free(mh);
    //         return (status == UCS_OK) ? NA_SUCCESS : NA_PROTOCOL_ERROR;
    //     case na_ucx_mem_unpacked_remote:
    //         ucp_rkey_destroy(mh->handle.unpacked_remote.rkey);
    //         free(mh);
    //         return NA_SUCCESS;
    //     case na_ucx_mem_packed_remote:
    //         free(mh->handle.packed_remote.buf);
    //         free(mh);
    //         return NA_SUCCESS;
    //     default:
    //         return NA_INVALID_ARG;
    // }
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_size_t
na_ucx_mem_handle_get_max_segments(const na_class_t NA_UNUSED *nacl)
{
    return 1;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_mem_register(na_class_t NA_UNUSED *nacl, na_mem_handle_t mh)
{
    // if (hg_atomic_get32(&mh->kind) != na_ucx_mem_local) {
    //     NA_LOG_ERROR("%p is not a local handle", (void *) mh);
    //     return NA_INVALID_ARG;
    // }
    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_mem_deregister(na_class_t NA_UNUSED *nacl, na_mem_handle_t NA_UNUSED mh)
{
    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_size_t
na_ucx_mem_handle_get_serialize_size(na_class_t *nacl, na_mem_handle_t mh)
{
    // const na_ucx_class_t *nucl = na_ucx_class_const(nacl);
    // ucs_status_t status;
    // void *ptr;
    // const size_t hdrlen = sizeof(na_mem_handle_header_t);
    // size_t paylen;

    // if (hg_atomic_get32(&mh->kind) != na_ucx_mem_local) {
    //     NA_LOG_ERROR(
    //         "non-local memory handle %p cannot be serialized", (void *) mh);
    //     return 0; // ok for error?
    // }

    // status = ucp_rkey_pack(nucl->uctx, mh->handle.local.mh, &ptr, &paylen);
    // if (status != UCS_OK)
    //     return 0; // ok for error?
    // ucp_rkey_buffer_release(ptr);

    // return hdrlen + paylen;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_mem_handle_serialize(
    na_class_t *nacl, void *_buf, na_size_t buf_size, na_mem_handle_t mh)
{
    // const na_ucx_class_t *nucl = na_ucx_class_const(nacl);
    // char *buf = _buf;
    // void *rkey;
    // const size_t hdrlen = sizeof(na_mem_handle_header_t);
    // na_mem_handle_header_t hdr = {// TBD convert to network endianness
    //     .base_addr = (uint64_t) (void *) mh->handle.local.buf,
    //     .paylen = 0};
    // size_t paylen;
    // ucs_status_t status;

    // if (hg_atomic_get32(&mh->kind) != na_ucx_mem_local) {
    //     NA_LOG_ERROR(
    //         "non-local memory handle %p cannot be serialized", (void *) mh);
    //     return NA_INVALID_ARG;
    // }

    // status = ucp_rkey_pack(nucl->uctx, mh->handle.local.mh, &rkey, &paylen);
    // if (status != UCS_OK) {
    //     NA_LOG_ERROR("ucp_rkey_pack failed %s", ucs_status_string(status));
    //     return NA_PROTOCOL_ERROR; // ok for error?
    // }

    // if (UINT32_MAX < paylen) {
    //     NA_LOG_ERROR("payload too big, %zu bytes", paylen);
    //     return NA_OVERFLOW;
    // }
    // if (buf_size < hdrlen + paylen) {
    //     NA_LOG_ERROR("buffer too small, %zu bytes", buf_size);
    //     return NA_OVERFLOW;
    // }

    // hdr.paylen = (uint32_t) paylen; // TBD convert to network endianness
    // memcpy(buf, &hdr, hdrlen);
    // memcpy(buf + hdrlen, rkey, paylen);
    // ucp_rkey_buffer_release(rkey);

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_mem_handle_deserialize(na_class_t NA_UNUSED *nacl, na_mem_handle_t *mhp,
    const void *buf, na_size_t buf_size)
{
    // na_mem_handle_header_t hdr;
    // na_mem_handle_t mh;
    // void *duplicate;
    // const size_t hdrlen = sizeof(na_mem_handle_header_t);
    // size_t paylen;

    // if ((mh = zalloc(sizeof(*mh))) == NULL)
    //     return NA_NOMEM;

    // if (buf_size < hdrlen) {
    //     NA_LOG_ERROR("buffer is shorter than a header, %zu bytes", buf_size);
    //     return NA_OVERFLOW;
    // }

    // memcpy(&hdr, buf, hdrlen);

    // paylen = hdr.paylen; // TBD convert from network endianness

    // if (buf_size < hdrlen + paylen) {
    //     NA_LOG_ERROR("buffer too short, %zu bytes", buf_size);
    //     return NA_OVERFLOW;
    // }

    // if ((duplicate = memdup(buf, hdrlen + paylen)) == NULL) {
    //     free(mh);
    //     return NA_NOMEM;
    // }

    // hg_atomic_set32(&mh->kind, na_ucx_mem_packed_remote);
    // mh->handle.packed_remote.buf = duplicate;
    // mh->handle.packed_remote.buflen = hdrlen + paylen;

    // *mhp = mh;
    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_put(na_class_t NA_UNUSED *nacl, na_context_t *ctx, na_cb_t callback,
    void *arg, na_mem_handle_t local_mh, na_offset_t local_offset,
    na_mem_handle_t remote_mh, na_offset_t remote_offset, na_size_t length,
    na_addr_t remote_addr, na_uint8_t remote_id, na_op_id_t *op_id)
{
    // return na_ucx_copy(ctx, callback, arg, local_mh, local_offset, remote_mh,
    //     remote_offset, length, remote_addr, remote_id, op_id, true);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_get(na_class_t NA_UNUSED *nacl, na_context_t *ctx, na_cb_t callback,
    void *arg, na_mem_handle_t local_mh, na_offset_t local_offset,
    na_mem_handle_t remote_mh, na_offset_t remote_offset, na_size_t length,
    na_addr_t remote_addr, na_uint8_t remote_id, na_op_id_t *op_id)
{
    // return na_ucx_copy(ctx, callback, arg, local_mh, local_offset, remote_mh,
    //     remote_offset, length, remote_addr, remote_id, op_id, false);
}

/*---------------------------------------------------------------------------*/
static int
na_ucx_poll_get_fd(na_class_t *na_class, na_context_t NA_UNUSED *context)
{
    struct na_ucx_class *na_ucx_class = NA_UCX_CLASS(na_class);
    ucs_status_t status;
    int fd;

    if (na_ucx_class->no_wait)
        return -1;

    status = ucp_worker_get_efd(na_ucx_class->ucp_worker, &fd);
    NA_CHECK_SUBSYS_ERROR(poll, status != UCS_OK, error, fd, -1,
        "ucp_worker_get_efd() failed (%s)", ucs_status_string(status));

    return fd;

error:
    return -1;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_bool_t
na_ucx_poll_try_wait(na_class_t *na_class, na_context_t NA_UNUSED *context)
{
    struct na_ucx_class *na_ucx_class = NA_UCX_CLASS(na_class);
    ucs_status_t status;

    if (na_ucx_class->no_wait)
        return NA_FALSE;

    status = ucp_worker_arm(na_ucx_class->ucp_worker);
    if (status == UCS_ERR_BUSY) {
        /* Events have already arrived */
        return NA_FALSE;
    } else if (status != UCS_OK) {
        NA_LOG_SUBSYS_ERROR(
            poll, "ucp_worker_arm() failed (%s)", ucs_status_string(status));
        return NA_FALSE;
    }

    return NA_TRUE;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_progress(na_class_t *na_class, na_context_t NA_UNUSED *context,
    unsigned int timeout_ms)
{
    hg_time_t deadline, now = hg_time_from_ms(0);

    if (timeout_ms != 0)
        hg_time_get_current_ms(&now);
    deadline = hg_time_add(now, hg_time_from_ms(timeout_ms));

    do {
        if (ucp_worker_progress(NA_UCX_CLASS(na_class)->ucp_worker) != 0)
            return NA_SUCCESS;

        if (timeout_ms != 0)
            hg_time_get_current_ms(&now);
    } while (hg_time_less(now, deadline));

    return NA_TIMEOUT;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_cancel(
    na_class_t NA_UNUSED *na_class, na_context_t *context, na_op_id_t *op)
{
    // na_ucx_context_t *ctx = context->plugin_context;

    // switch (op->completion_data.callback_info.type) {
    //     case NA_CB_PUT:
    //     case NA_CB_GET:
    //     case NA_CB_RECV_UNEXPECTED:
    //     case NA_CB_RECV_EXPECTED:
    //         if (hg_atomic_cas32(&op->status, op_s_underway, op_s_canceled)) {
    //             /* UCP will still run the callback */
    //             ucp_request_cancel(ctx->worker, op);
    //         } else {
    //             hg_util_int32_t NA_DEBUG_USED status =
    //                 hg_atomic_get32(&op->status);
    //             // hlog_assert(status == op_s_canceled || status ==
    //             // op_s_complete);
    //         }
    //         return NA_SUCCESS;
    //     case NA_CB_SEND_UNEXPECTED:
    //     case NA_CB_SEND_EXPECTED:
    //         if (hg_atomic_cas32(&op->status, op_s_underway, op_s_canceled)) {
    //             /* UCP will still run the callback */
    //             ucp_request_cancel(ctx->worker, op);
    //         } else if (hg_atomic_cas32(
    //                        &op->status, op_s_deferred, op_s_canceled)) {
    //             ; // do nothing
    //         } else {
    //             hg_util_int32_t NA_DEBUG_USED status =
    //                 hg_atomic_get32(&op->status);
    //             // hlog_assert(status == op_s_canceled || status ==
    //             // op_s_complete);
    //         }
    //         return NA_SUCCESS;
    //     default:
    //         return (hg_atomic_get32(&op->status) == op_s_complete)
    //                    ? NA_SUCCESS
    //                    : NA_INVALID_ARG; // error return follows OFI plugin
    // }
}
