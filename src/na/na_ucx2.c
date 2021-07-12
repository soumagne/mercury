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

// #include "mercury_hash_table.h"
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

/* Default max msg size */
#define NA_UCX_MSG_SIZE_MAX (4096)

/* Max tag */
#define NA_UCX_MAX_TAG UINT32_MAX

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

/************************************/
/* Local Type and Struct Definition */
/************************************/

/* Address */
struct na_ucx_addr {
    ucs_sock_addr_t sockaddr;   /* Sock addr */
    uint32_t conn_id;           /* Connection ID */
    ucp_ep_h ucp_ep;            /* Currently only one EP per address */
    hg_atomic_int32_t refcount; /* Reference counter */
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
    // union {
    //     struct na_ucx_msg_info msg;
    //     struct na_ucx_rma_info rma;
    // } info;                             /* Op info                  */
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
    ucp_context_h ucp_context;              /* UCP context */
    ucp_worker_h ucp_worker;                /* Shared UCP worker */
    ucp_listener_h ucp_listener;            /* Listener handle if listening */
    struct sockaddr_storage *listener_addr; /* Listener adress if listening */
    struct na_ucx_addr *self_addr;          /* Self address */
    size_t ucp_request_size;                /* Size of UCP requests */
    char *protocol_name;                    /* Protocol used */
    na_size_t unexpected_size_max;          /* Max unexpected size */
    na_size_t expected_size_max;            /* Max expected size */
    hg_atomic_int32_t ncontexts;            /* Number of contexts */
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
na_ucp_context_create(const ucp_config_t *config, ucs_thread_mode_t thread_mode,
    ucp_context_h *context_p, size_t *request_size_p);

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
na_ucp_listener_destroy(
    ucp_listener_h listener, struct sockaddr_storage *listener_addr);

/**
 * Listener callback.
 */
static void
na_ucp_listener_conn_cb(ucp_conn_request_h conn_request, void *arg);

/**
 * Recv a msg.
 */
static na_return_t
na_ucp_msg_recv(ucp_worker_h worker, void *buf, size_t buf_size, ucp_tag_t tag,
    ucp_tag_t tag_mask, void *request);

/**
 * Recv msg callback.
 */
static void
na_ucp_msg_recv_cb(void *request, ucs_status_t status,
    const ucp_tag_recv_info_t *info, void NA_UNUSED *user_data);

/**
 * Parse hostname info.
 */
static na_return_t
na_ucx_parse_hostname_info(const char *hostname_info, const char *subnet_info,
    char **net_device_p, struct sockaddr_storage **sockaddr_p);

/**
 * Create self address.
 */
static na_return_t
na_ucx_addr_self_create(const struct sockaddr *addr, socklen_t addrlen,
    struct na_ucx_addr **na_ucx_addr_p);

/**
 * Destroy self address.
 */
static void
na_ucx_addr_self_destroy(struct na_ucx_addr *na_ucx_addr);

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

/* addr_set_remove */
static NA_INLINE na_return_t
na_ucx_addr_set_remove(na_class_t *na_class, na_addr_t addr);

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
static NA_INLINE int
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
    na_ucx_addr_set_remove,               /* addr_set_remove */
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
na_ucp_context_create(const ucp_config_t *config, ucs_thread_mode_t thread_mode,
    ucp_context_h *context_p, size_t *request_size_p)
{
    ucp_context_h context = NULL;
    ucp_params_t context_params = {
        .field_mask = UCP_PARAM_FIELD_FEATURES | UCP_PARAM_FIELD_REQUEST_SIZE,
        .features = UCP_FEATURE_TAG | UCP_FEATURE_RMA,
        .request_size = sizeof(struct na_ucx_op_id)};
    ucp_context_attr_t context_actuals = {
        .field_mask = UCP_ATTR_FIELD_REQUEST_SIZE | UCP_ATTR_FIELD_THREAD_MODE};
    ucs_status_t status;
    na_return_t ret;

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
        .conn_handler = {na_ucp_listener_conn_cb, listener_arg}};
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
na_ucp_listener_destroy(
    ucp_listener_h listener, struct sockaddr_storage *listener_addr)
{
    ucp_listener_destroy(listener);
    free(listener_addr);
}

/*---------------------------------------------------------------------------*/
static void
na_ucp_listener_conn_cb(ucp_conn_request_h conn_request, void NA_UNUSED *arg)
{
    ucp_conn_request_attr_t conn_request_attrs = {
        .field_mask = UCP_CONN_REQUEST_ATTR_FIELD_CLIENT_ADDR};
    ucs_status_t status;
    char client_string[NI_MAXHOST];
    int rc;

    status = ucp_conn_request_query(conn_request, &conn_request_attrs);
    NA_CHECK_SUBSYS_ERROR_NORET(poll, status != UCS_OK, error,
        "ucp_conn_request_query() failed (%s)", ucs_status_string(status));

    // ucp_ep_create();

    rc = getnameinfo(
        (const struct sockaddr *) &conn_request_attrs.client_address,
        sizeof(conn_request_attrs.client_address), client_string,
        sizeof(client_string), NULL, 0, NI_NUMERICHOST | NI_NUMERICSERV);
    NA_CHECK_SUBSYS_ERROR_NORET(poll, rc != 0, error,
        "getnameinfo() failed (%s)", ucs_status_string(status));

    NA_LOG_SUBSYS_DEBUG(
        poll, "Received connection request from %s", client_string);

    return;

error:
    return;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucp_msg_recv(ucp_worker_h worker, void *buf, size_t buf_size, ucp_tag_t tag,
    ucp_tag_t tag_mask, void *request)
{
    const ucp_request_param_t recv_params = {
        .op_attr_mask =
            UCP_OP_ATTR_FIELD_CALLBACK | UCP_OP_ATTR_FIELD_USER_DATA,
        .cb = {.recv = na_ucp_msg_recv_cb},
        .request = request};
    ucs_status_ptr_t status_ptr;
    na_return_t ret;

    status_ptr =
        ucp_tag_recv_nbx(worker, buf, buf_size, tag, tag_mask, &recv_params);
    NA_CHECK_SUBSYS_ERROR(msg, UCS_PTR_IS_ERR(status_ptr), error, ret,
        NA_PROTOCOL_ERROR, "ucp_tag_recv_nbx() failed (%s)",
        ucs_status_string(UCS_PTR_STATUS(status_ptr)));

    /* TODO check for immediate completion */

    return NA_SUCCESS;

error:

    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_ucp_msg_recv_cb(void *request, ucs_status_t status,
    const ucp_tag_recv_info_t *info, void NA_UNUSED *user_data)
{
    //     static const struct na_cb_info_recv_unexpected
    //     recv_unexpected_errinfo = {
    //         .actual_buf_size = 0, .source = NA_ADDR_NULL, .tag = 0};
    //     na_op_id_t *op = request;
    //     na_ucx_context_t *nuctx = op->ctx.nu;
    //     struct na_cb_info *cbinfo = &op->completion_data.callback_info;
    //     struct na_cb_info_recv_unexpected *recv_unexpected =
    //         &cbinfo->info.recv_unexpected;
    //     const op_status_t expected_status =
    //         (status == UCS_ERR_CANCELED) ? op_s_canceled : op_s_underway;

    //     if (hg_atomic_get32(&op->status) != (hg_util_int32_t)
    //     expected_status) {
    //         NA_LOG_ERROR("op id %p: expected status %s, found %s", (void *)
    //         op,
    //             op_status_string(expected_status),
    //             op_status_string(op->status));
    //     }

    //     hg_atomic_set32(&op->status, op_s_complete);

    //     if (status == UCS_OK) {
    //         wire_id_t wire_id;
    //         const void *buf = op->info.rx.buf;
    //         void *data;
    //         na_addr_t source;

    //         // XXX use standard endianness
    //         memcpy(&wire_id.id, buf, sizeof(wire_id.id));

    //         if (cbinfo->type != NA_CB_RECV_UNEXPECTED) {
    //             source = NULL;
    //         } else if ((data = wire_get_data(&nuctx->wiring, wire_id)) ==
    //                    wire_data_nil) {
    //             *recv_unexpected = recv_unexpected_errinfo;
    //             cbinfo->ret = NA_PROTOCOL_ERROR;
    //             goto out;
    //         } else {
    //             source = data;
    //             addr_incref(source, "sender address");
    //         }

    //         assert((info->sender_tag & nuctx->app.tagmask) ==
    //         nuctx->app.tag);

    //         *recv_unexpected = (struct na_cb_info_recv_unexpected){
    //             .actual_buf_size = (na_size_t) info->length,
    //             .source = source,
    //             .tag = (na_tag_t) ((info->sender_tag & ~nuctx->msg.tagmask)
    //             >>
    //                                nuctx->msg.tagshift)};

    //         cbinfo->ret = NA_SUCCESS;
    //     } else if (status == UCS_ERR_CANCELED) {
    //         *recv_unexpected = recv_unexpected_errinfo;
    //         cbinfo->ret = NA_CANCELED;
    //     } else {
    //         *recv_unexpected = recv_unexpected_errinfo;
    //         cbinfo->ret = NA_PROTOCOL_ERROR;
    //     }

    // out:
    //     na_cb_completion_add(op->ctx.na, &op->completion_data);
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
        char *parse_str = NULL;

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
static na_return_t
na_ucx_addr_self_create(const struct sockaddr *addr, socklen_t addrlen,
    struct na_ucx_addr **na_ucx_addr_p)
{
    struct na_ucx_addr *na_ucx_addr;
    na_return_t ret = NA_SUCCESS;

    na_ucx_addr = malloc(sizeof(*na_ucx_addr));

    na_ucx_addr->sockaddr = (ucs_sock_addr_t){.addr = addr, .addrlen = addrlen};

    na_ucx_addr->conn_id = 0;
    na_ucx_addr->ucp_ep = NULL;
    hg_atomic_init32(&na_ucx_addr->refcount, 1);

    *na_ucx_addr_p = na_ucx_addr;

    return ret;
}

/*---------------------------------------------------------------------------*/
static void
na_ucx_addr_self_destroy(struct na_ucx_addr *na_ucx_addr)
{
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
static NA_INLINE void
na_ucx_release(void *arg)
{
    struct na_ucx_op_id *na_ucx_op_id = (struct na_ucx_op_id *) arg;

    NA_CHECK_SUBSYS_WARNING(op,
        na_ucx_op_id &&
            (!(hg_atomic_get32(&na_ucx_op_id->status) & NA_UCX_OP_COMPLETED)),
        "Releasing resources from an uncompleted operation");

    if (na_ucx_op_id->addr) {
        // na_ucx_addr_decref(na_ofi_op_id->addr);
        na_ucx_op_id->addr = NULL;
    }
}

/*---------------------------------------------------------------------------*/

// static void
// tagged_send(na_ucx_context_t *nuctx, const void *buf, na_size_t buf_size,
//     ucp_ep_h ep, sender_id_t sender_id, uint64_t tag, na_op_id_t *op)
// {
//     const ucp_request_param_t tx_params = {
//         .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK |
//         UCP_OP_ATTR_FIELD_REQUEST, .cb = {.send = send_callback}, .request =
//         op};
//     ucs_status_ptr_t request;

//     assert(buf_size >= sizeof(sender_id));

//     // XXX use standard endianness
//     memcpy((void *) (uintptr_t) buf, &sender_id, sizeof(sender_id));

//     wiring_ref_get(&nuctx->wiring, &op->ref);
//     request = ucp_tag_send_nbx(ep, buf, buf_size, tag, &tx_params);

//     if (UCS_PTR_IS_ERR(request)) {
//         NA_LOG_ERROR(
//             "ucp_tag_send_nbx: %s",
//             ucs_status_string(UCS_PTR_STATUS(request)));
//         hg_atomic_set32(&op->status, op_s_complete);
//         op->completion_data.callback_info.ret = NA_PROTOCOL_ERROR;
//         wiring_ref_put(&nuctx->wiring, &op->ref);
//         na_cb_completion_add(op->ctx.na, &op->completion_data);
//     } else if (request == UCS_OK) {
//         // send was immediate: queue completion
//         hg_atomic_set32(&op->status, op_s_complete);
//         op->completion_data.callback_info.ret = NA_SUCCESS;
//         wiring_ref_put(&nuctx->wiring, &op->ref);
//         na_cb_completion_add(op->ctx.na, &op->completion_data);
//     }
// }

// static bool
// wire_event_callback(wire_event_info_t info, void *arg)
// {
//     address_wire_aseq_t aseq;
//     address_wire_t *cache = arg;
//     na_op_id_t *op;
//     na_ucx_addr_t *owner = cache->owner;

//     assert(info.event == wire_ev_estd || info.event == wire_ev_closed ||
//            info.event == wire_ev_reclaimed);

//     wiring_assert_locked(&cache->ctx->wiring);

//     if (info.event == wire_ev_closed) {
//         assert(HG_QUEUE_IS_EMPTY(&cache->deferrals));

//         return true;
//     }

//     if (info.event == wire_ev_reclaimed) {
//         /* No in-flight wireup operations will reference this wire
//          * so it has been reclaimed.
//          */
//         aseq = address_wire_write_begin(cache);
//         atomic_store_explicit(
//             &cache->sender_id, sender_id_nil, memory_order_relaxed);
//         atomic_store_explicit(
//             &cache->wire_id.id, sender_id_nil, memory_order_relaxed);
//         atomic_store_explicit(&cache->ep, NULL, memory_order_relaxed);
//         address_wire_write_end(aseq);

//         /* Now the address can be reclaimed
//          * safely, too.  Decrease the reference count that we increased when
//          * either the local host initiated wireup or the local host
//          * accepted the remote's wireup request.
//          */
//         (void) na_ucx_addr_free(cache->ctx->nacl, owner);

//         return true;
//     }

//     /* Transmit deferred messages before saving the sender ID so that
//      * a new transmission cannot slip out before the deferred ones.
//      * New transmissions will find that the sender ID is nil and wait
//      * for us to release the wiring lock.
//      */
//     HG_QUEUE_FOREACH (op, &cache->deferrals, info.tx.link) {
//         const void *buf = op->info.tx.buf;
//         na_size_t buf_size = op->info.tx.buf_size;
//         uint64_t tag = op->info.tx.tag;
//         if (hg_atomic_cas32(&op->status, op_s_deferred, op_s_underway)) {
//             tagged_send(
//                 cache->ctx, buf, buf_size, info.ep, info.sender_id, tag, op);
//         } else if (hg_atomic_cas32(&op->status, op_s_canceled,
//         op_s_complete)) {
//             struct na_cb_info *cbinfo = &op->completion_data.callback_info;
//             cbinfo->ret = NA_CANCELED;
//             na_cb_completion_add(op->ctx.na, &op->completion_data);
//         }
//     }

//     HG_QUEUE_INIT(&cache->deferrals);

//     aseq = address_wire_write_begin(cache);
//     atomic_store_explicit(&cache->ep, info.ep, memory_order_relaxed);
//     atomic_store_explicit(
//         &cache->sender_id, info.sender_id, memory_order_relaxed);
//     address_wire_write_end(aseq);

//     return true;
// }

// static na_return_t
// na_ucx_msg_send(na_context_t *context, na_cb_t callback, void *arg,
//     const void *buf, na_size_t buf_size, na_addr_t dest_addr,
//     na_tag_t proto_tag, na_cb_type_t cb_type, na_op_id_t *op_id)
// {
//     na_ucx_context_t *cached_ctx, *const nuctx = context->plugin_context;
//     sender_id_t sender_id;
//     na_return_t ret;
//     address_wire_t *cache = &dest_addr->wire_cache;
//     ucp_ep_h ep;
//     uint64_t tag;
//     const na_tag_t NA_DEBUG_USED maxtag =
//         (na_tag_t) MIN(NA_TAG_MAX, nuctx->msg.tagmax);

//     assert(proto_tag <= maxtag);

//     for (;;) {
//         const address_wire_aseq_t aseq = address_wire_read_begin(cache);
//         sender_id =
//             atomic_load_explicit(&cache->sender_id, memory_order_relaxed);
//         cached_ctx = atomic_load_explicit(&cache->ctx, memory_order_relaxed);
//         /* XXX The endpoint mustn't be destroyed between the time we
//          * load its pointer and the time we transmit on it, but the wireup
//          * state machine isn't synchronized with transmission.
//          *
//          * Wireup probably should not
//          * release an endpoint until an explicit wireup_stop() is performed.
//          * I can introduce a state between "dead" and "reclaimed".
//          *
//          * Alternatively, defer releasing the endpoint until an "epoch" has
//          * passed.
//          */
//         ep = atomic_load_explicit(&cache->ep, memory_order_relaxed);
//         if (address_wire_read_end(aseq))
//             break;
//     }

//     tag = proto_tag << nuctx->msg.tagshift;
//     if (cb_type == NA_CB_SEND_EXPECTED)
//         tag |= nuctx->exp.tag;
//     else
//         tag |= nuctx->unexp.tag;

//     /* TBD Assert expected op_id->status */
//     op_id->ctx.na = context;
//     op_id->ctx.nu = nuctx;
//     op_id->completion_data.callback_info.type = cb_type;
//     op_id->completion_data.callback = callback;
//     op_id->completion_data.callback_info.arg = arg;
//     op_id->info.tx.buf = buf;
//     op_id->info.tx.buf_size = buf_size;
//     op_id->info.tx.tag = tag;

//     /* Fast path: if the sender ID is established, and the cached context
//      * matches the caller's context, then don't acquire the lock,
//      * just send and return.
//      */
//     if (cached_ctx == context->plugin_context && sender_id != sender_id_nil)
//     {
//         op_id->status = op_s_underway;
//         tagged_send(cached_ctx, buf, buf_size, ep, sender_id, tag, op_id);
//         return NA_SUCCESS;
//     }

//     wiring_lock(&nuctx->wiring);

//     /* Since we last checked, sender_id or ctx may have been set.  Check
//      * once more.
//      *
//      * TBD handle cache->ctx that is equal to neither NULL nor
//      * context->plugin_context.
//      */
//     if ((cached_ctx = cache->ctx) == NULL) {
//         /* This thread can write to `cache->ctx` without conflicting
//          * with any other thread: because the thread holds the lock,
//          * no new wire-event callback will be established on `cache`.
//          * Because `cache->ctx == NULL`, no wireup is underway, so no
//          * wire-event callback is already established.
//          */
//         const address_wire_aseq_t aseq = address_wire_write_begin(cache);

//         cache->ctx = cached_ctx = nuctx;

//         addr_incref(cache->owner, "wireup");

//         cache->wire_id = wireup_start(&cached_ctx->wiring,
//             (ucp_address_t *) &cached_ctx->self->addr[0],
//             cached_ctx->self->addrlen, (ucp_address_t *) &dest_addr->addr[0],
//             dest_addr->addrlen, wire_event_callback, cache, dest_addr);

//         address_wire_write_end(aseq);

//         if (!wire_is_valid(cache->wire_id)) {
//             NA_LOG_ERROR("could not start wireup, cache %p", (void *) cache);
//             addr_decref(cache->owner, "wireup failure");
//             ret = NA_NOMEM;
//             goto release;
//         }
//     } else if ((sender_id = cache->sender_id) != sender_id_nil) {
//         op_id->status = op_s_underway;
//         tagged_send(cached_ctx, buf, buf_size, ep, sender_id, tag, op_id);
//         ret = NA_SUCCESS;
//         goto release;
//     } else if (!wire_is_valid(cache->wire_id)) {

//         const address_wire_aseq_t aseq = address_wire_write_begin(cache);

//         addr_incref(cache->owner, "wireup");

//         cache->wire_id = wireup_start(&cached_ctx->wiring,
//             (ucp_address_t *) &cached_ctx->self->addr[0],
//             cached_ctx->self->addrlen, (ucp_address_t *) &dest_addr->addr[0],
//             dest_addr->addrlen, wire_event_callback, cache, dest_addr);

//         address_wire_write_end(aseq);

//         if (!wire_is_valid(cache->wire_id)) {
//             NA_LOG_ERROR("could not start wireup, cache %p", (void *) cache);
//             addr_decref(cache->owner, "wireup failure");
//             ret = NA_NOMEM;
//             goto release;
//         }
//     }

//     hg_atomic_set32(&op_id->status, op_s_deferred);

//     HG_QUEUE_PUSH_TAIL(&cache->deferrals, op_id, info.tx.link);

//     ret = NA_SUCCESS;
// release:
//     // TBD put the following comments into the right place or delete them.
//     //
//     // if dest_addr has no wire ID, increase refcount on dest_addr by 1,
//     //     start wireup with dest_addr as callback arg; set wire ID on
//     //     dest_addr; enqueue op_id on dest_addr; in wireup callback,
//     //     set sender ID on dest_addr, decrease refcount by 1, return false
//     //     to stop callbacks.
//     // if dest_addr has wire ID but no sender ID, enqueue op_id on dest_addr.
//     // if dest_addr has sender ID, put it into the header and send the
//     message. wiring_unlock(&nuctx->wiring); return ret;
// }

// /*---------------------------------------------------------------------------*/
// static void
// op_ref_reclaim(wiring_ref_t *ref)
// {
//     na_op_id_t *op = (na_op_id_t *) ((char *) ref - offsetof(na_op_id_t,
//     ref));

//     header_free(op->nucl->request_size, alignof(na_op_id_t), op);
// }

/*---------------------------------------------------------------------------*/

// /*---------------------------------------------------------------------------*/
// static void
// send_callback(void *request, ucs_status_t status, void NA_UNUSED *user_data)
// {
//     na_op_id_t *op = request;
//     na_ucx_context_t *nuctx = op->ctx.nu;
//     struct na_cb_info *cbinfo = &op->completion_data.callback_info;
//     const op_status_t expected_status =
//         (status == UCS_ERR_CANCELED) ? op_s_canceled : op_s_underway;

//     if (hg_atomic_get32(&op->status) != (hg_util_int32_t) expected_status) {
//         NA_LOG_ERROR("op id %p: %s expected status %s, found %s", (void *)
//         op,
//             na_cb_type_string(op->completion_data.callback_info.type),
//             op_status_string(expected_status), op_status_string(op->status));
//     }
//     hg_atomic_set32(&op->status, op_s_complete);

//     if (status == UCS_OK)
//         cbinfo->ret = NA_SUCCESS;
//     else if (status == UCS_ERR_CANCELED)
//         cbinfo->ret = NA_CANCELED;
//     else
//         cbinfo->ret = NA_PROTOCOL_ERROR;

//     wiring_ref_put(&nuctx->wiring, &op->ref);

//     na_cb_completion_add(op->ctx.na, &op->completion_data);
// }

// static na_mem_handle_t
// resolve_mem_handle_locked(ucp_ep_h ep, na_mem_handle_t mh)
// {
//     na_mem_handle_header_t hdr;
//     unpacked_rkey_t unpacked;
//     packed_rkey_t *packed = &mh->handle.packed_remote;
//     ucs_status_t status;

//     if (hg_atomic_get32(&mh->kind) != na_ucx_mem_packed_remote)
//         return mh;

//     memcpy(&hdr, packed->buf, sizeof(hdr));

//     status = ucp_ep_rkey_unpack(ep, packed->buf + sizeof(hdr),
//     &unpacked.rkey); if (status != UCS_OK) {
//         NA_LOG_ERROR("ucp_rkey_pack failed %s", ucs_status_string(status));
//         return NULL;
//     }

//     // TBD convert from network endianness
//     unpacked.remote_base_addr = hdr.base_addr;

//     free(packed->buf);

//     mh->handle.unpacked_remote = unpacked;
//     hg_atomic_set32(&mh->kind, na_ucx_mem_unpacked_remote);

//     return mh;
// }

// static na_mem_handle_t
// resolve_mem_handle(ucp_ep_h ep, na_mem_handle_t mh)
// {
//     if (hg_atomic_get32(&mh->kind) != na_ucx_mem_packed_remote)
//         return mh;

//     hg_thread_mutex_lock(&mh->unpack_lock);
//     mh = resolve_mem_handle_locked(ep, mh);
//     hg_thread_mutex_unlock(&mh->unpack_lock);

//     return mh;
// }

// static na_return_t
// na_ucx_copy(na_context_t *ctx, na_cb_t callback, void *arg,
//     na_mem_handle_t local_mh, na_offset_t local_offset,
//     na_mem_handle_t remote_mh, na_offset_t remote_offset, na_size_t length,
//     na_addr_t remote_addr, na_uint8_t NA_UNUSED remote_id, na_op_id_t *op,
//     bool put)
// {
//     const ucp_request_param_t params = {
//         .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK |
//         UCP_OP_ATTR_FIELD_REQUEST, .cb = {.send = send_callback}, .request =
//         op};
//     ucp_ep_h ep;
//     na_ucx_context_t *nuctx;
//     address_wire_t *cache = &remote_addr->wire_cache;
//     ucs_status_ptr_t request;
//     unpacked_rkey_t *unpacked = &remote_mh->handle.unpacked_remote;

//     if (hg_atomic_get32(&local_mh->kind) != na_ucx_mem_local ||
//         hg_atomic_get32(&remote_mh->kind) == na_ucx_mem_local) {
//         return NA_INVALID_ARG;
//     }

//     for (;;) {
//         const address_wire_aseq_t aseq = address_wire_read_begin(cache);
//         nuctx = atomic_load_explicit(&cache->ctx, memory_order_relaxed);
//         ep = atomic_load_explicit(&cache->ep, memory_order_relaxed);
//         if (address_wire_read_end(aseq))
//             break;
//     }

//     /* XXX Need to verify that `ep` cannot be NULL here. */

//     assert(nuctx == ctx->plugin_context);

//     if ((remote_mh = resolve_mem_handle(ep, remote_mh)) == NULL)
//         return NA_PROTOCOL_ERROR;

//     /* TBD: verify original status */
//     hg_atomic_set32(&op->status, op_s_underway);
//     op->ctx.na = ctx;
//     op->ctx.nu = nuctx;
//     op->completion_data.callback_info.type = put ? NA_CB_PUT : NA_CB_GET;
//     op->completion_data.callback = callback;
//     op->completion_data.callback_info.arg = arg;

//     wiring_ref_get(&nuctx->wiring, &op->ref);

//     if (put) {
//         request = ucp_put_nbx(ep, local_mh->handle.local.buf + local_offset,
//             length, unpacked->remote_base_addr + remote_offset,
//             unpacked->rkey, &params);
//     } else {
//         request = ucp_get_nbx(ep, local_mh->handle.local.buf + local_offset,
//             length, unpacked->remote_base_addr + remote_offset,
//             unpacked->rkey, &params);
//     }

//     if (UCS_PTR_IS_ERR(request)) {
//         NA_LOG_ERROR(
//             "ucp_put_nbx: %s", ucs_status_string(UCS_PTR_STATUS(request)));
//         wiring_ref_put(&nuctx->wiring, &op->ref);
//         hg_atomic_set32(&op->status, op_s_complete);
//         return NA_PROTOCOL_ERROR;
//     } else if (request == UCS_OK) {
//         // send was immediate: queue completion
//         wiring_ref_put(&nuctx->wiring, &op->ref);
//         hg_atomic_set32(&op->status, op_s_complete);
//         op->completion_data.callback_info.ret = NA_SUCCESS;
//         na_cb_completion_add(op->ctx.na, &op->completion_data);
//     }

//     return NA_SUCCESS;
// }

/********************/
/* Plugin callbacks */
/********************/

static na_bool_t
na_ucx_check_protocol(const char *protocol_name)
{
    ucp_config_t *config = NULL;
    ucp_params_t params = {.field_mask = UCP_PARAM_FIELD_FEATURES,
        .features = UCP_FEATURE_TAG | UCP_FEATURE_RMA};
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
    struct sockaddr_storage *listener_sockaddr = NULL;
    ucp_config_t *config;
    na_size_t unexpected_size_max = 0, expected_size_max = 0;
    ucs_thread_mode_t context_thread_mode = UCS_THREAD_MODE_SINGLE,
                      worker_thread_mode = UCS_THREAD_MODE_MULTI;
    na_return_t ret;
    ucs_status_t status;

    if (na_info->na_init_info != NULL) {
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
        &net_device, (listen) ? &listener_sockaddr : NULL);
    NA_CHECK_SUBSYS_NA_ERROR(
        cls, error, ret, "na_ucx_parse_hostname_info() failed");

    na_ucx_class = calloc(1, sizeof(*na_ucx_class));
    NA_CHECK_SUBSYS_ERROR(cls, na_ucx_class == NULL, error, ret, NA_NOMEM,
        "Could not allocate NA private data class");

    /* Keep a copy of the protocol name */
    na_ucx_class->protocol_name = (na_info->protocol_name)
                                      ? strdup(na_info->protocol_name)
                                      : strdup(NA_UCX_PROTOCOL_DEFAULT);
    NA_CHECK_SUBSYS_ERROR(cls, na_ucx_class->protocol_name == NULL, error, ret,
        NA_NOMEM, "Could not dup NA protocol name");

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
    ret = na_ucp_context_create(config, context_thread_mode,
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
            (const struct sockaddr *) listener_sockaddr,
            sizeof(*listener_sockaddr), (void *) na_ucx_class,
            &na_ucx_class->ucp_listener, &na_ucx_class->listener_addr);
        NA_CHECK_SUBSYS_NA_ERROR(
            cls, error, ret, "Could not create UCX listener");
    }

    /* Create self address */
    ret = na_ucx_addr_self_create(
        (const struct sockaddr *) na_ucx_class->listener_addr,
        sizeof(*na_ucx_class->listener_addr), &na_ucx_class->self_addr);
    NA_CHECK_SUBSYS_NA_ERROR(cls, error, ret, "Could not create self address");

    /* Create connection hash table */

    // rc = hg_thread_mutex_init(&nucl->addr_lock);
    // NA_CHECK_SUBSYS_ERROR(cls, rc != HG_UTIL_SUCCESS, cleanup, ret, NA_NOMEM,
    //     "Could not initialize address lock");

    // nucl->addr_tbl = hg_hash_table_new(na_ucx_addr_hash, na_ucx_addr_equal);
    // NA_CHECK_SUBSYS_ERROR(cls, nucl->addr_tbl == NULL, cleanup, ret,
    // NA_NOMEM,
    //     "Could not allocate address table");

    na_class->plugin_class = (void *) na_ucx_class;

    return NA_SUCCESS;

error:
    if (na_ucx_class) {
        if (na_ucx_class->self_addr)
            na_ucx_addr_self_destroy(na_ucx_class->self_addr);
        if (na_ucx_class->ucp_listener)
            na_ucp_listener_destroy(
                na_ucx_class->ucp_listener, na_ucx_class->listener_addr);
        if (na_ucx_class->ucp_worker)
            na_ucp_worker_destroy(na_ucx_class->ucp_worker);
        if (na_ucx_class->ucp_context)
            na_ucp_context_destroy(na_ucx_class->ucp_context);
        free(na_ucx_class);
    }
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

    if (na_ucx_class->self_addr)
        na_ucx_addr_self_destroy(na_ucx_class->self_addr);
    if (na_ucx_class->ucp_listener)
        na_ucp_listener_destroy(
            na_ucx_class->ucp_listener, na_ucx_class->listener_addr);
    if (na_ucx_class->ucp_worker)
        na_ucp_worker_destroy(na_ucx_class->ucp_worker);
    if (na_ucx_class->ucp_context)
        na_ucp_context_destroy(na_ucx_class->ucp_context);

    // if (nucl->addr_tbl != NULL)
    //     hg_hash_table_free(nucl->addr_tbl);

    // (void) hg_thread_mutex_destroy(&nucl->addr_lock);

    free(na_ucx_class);
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
    //     na_ucx_addr_t *addr;
    //     size_t buflen = 0, noctets;
    //     int i = 0, nread, rc;
    //     uint8_t *buf;

    //     noctets = (strlen(name) + 1) / 3;

    //     if (noctets < 1)
    //         return 0;

    //     if ((addr = malloc(sizeof(*addr) + noctets)) == NULL)
    //         return NA_NOMEM;

    //     address_wire_init(&addr->wire_cache, addr, NULL);

    //     addr->refcount = 1;
    //     addr->addrlen = 0;

    //     buf = &addr->addr[0];

    //     rc = sscanf(&name[i], "%02" SCNx8 "%n", &buf[buflen], &nread);
    //     if (rc == EOF) {
    //         goto out;
    //     } else if (rc != 1) {
    //         NA_LOG_ERROR("parse error at '%s'", &name[i]);
    //         free(addr);
    //         return NA_INVALID_ARG;
    //     }

    //     for (buflen = 1, i = nread;
    //          (rc = sscanf(&name[i], ":%02" SCNx8 "%n", &buf[buflen], &nread))
    //          == 1; i += nread) {
    //         buflen++;
    //     }

    //     if (rc != EOF || name[i] != '\0') {
    //         NA_LOG_ERROR("residual characters '%s'", &name[i]);
    //         free(addr);
    //         return NA_INVALID_ARG;
    //     }

    //     assert(buflen == noctets);

    // out:
    //     addr->addrlen = buflen;
    //     *addrp = na_ucx_addr_dedup(nacl, addr);

    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_return_t
na_ucx_addr_free(na_class_t *nacl, na_addr_t _addr)
{
    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_return_t
na_ucx_addr_set_remove(na_class_t NA_UNUSED *nacl, na_addr_t NA_UNUSED addr)
{
    return NA_SUCCESS;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_return_t
na_ucx_addr_self(na_class_t *na_class, na_addr_t *addr_p)
{
    na_ucx_addr_ref_incr(&NA_UCX_CLASS(na_class)->self_addr);
    *addr_p = NA_UCX_CLASS(na_class)->self_addr;

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

    NA_CHECK_SUBSYS_ERROR(addr, na_ucx_addr->sockaddr.addr == NULL, error, ret,
        NA_OPNOTSUPPORTED, "Cannot convert address to string");

    rc = getnameinfo(na_ucx_addr->sockaddr.addr, na_ucx_addr->sockaddr.addrlen,
        host_string, sizeof(host_string), serv_string, sizeof(serv_string),
        NI_NUMERICHOST | NI_NUMERICSERV);
    NA_CHECK_SUBSYS_ERROR(addr, rc != 0, error, ret, NA_PROTOCOL_ERROR,
        "getnameinfo() failed (%s)", gai_strerror(rc));

    buf_size = strlen(host_string) + strlen(serv_string) +
               strlen(na_ucx_class->protocol_name) + 5;
    if (buf) {
        rc = snprintf(buf, buf_size, "%s://%s:%s", na_ucx_class->protocol_name,
            host_string, serv_string);
        NA_CHECK_SUBSYS_ERROR(addr, rc < 0 || rc > buf_size, error, ret,
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
na_ucx_msg_get_max_tag(const na_class_t *nacl)
{
    // const na_ucx_class_t *nucl = na_ucx_class_const(nacl);
    // const na_tag_t maxtag =
    //     (na_tag_t) MIN(NA_TAG_MAX, nucl->context.msg.tagmax);

    // assert(maxtag >= 3);

    // return maxtag;
    return NA_UCX_MAX_TAG;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_msg_send_unexpected(na_class_t NA_UNUSED *nacl, na_context_t *context,
    na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
    void NA_UNUSED *plugin_data, na_addr_t dest_addr,
    na_uint8_t NA_UNUSED dest_id, na_tag_t tag, na_op_id_t *op_id)
{
    // return na_ucx_msg_send(context, callback, arg, buf, buf_size, dest_addr,
    //     tag, NA_CB_SEND_UNEXPECTED, op_id);
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

    // NA_UCX_OP_ID_INIT(context, NA_CB_RECV_UNEXPECTED, callback, arg);

    na_ucx_op_id->context = context;
    na_ucx_op_id->completion_data.callback_info.type = NA_CB_RECV_UNEXPECTED;
    na_ucx_op_id->completion_data.callback = callback;
    na_ucx_op_id->completion_data.callback_info.arg = arg;
    na_ucx_op_id->addr = NULL;
    hg_atomic_set32(&na_ucx_op_id->status, 0);

    // /* We assume buf remains valid (safe because we pre-allocate buffers) */
    // na_ofi_op_id->info.msg.buf.ptr = buf;
    // na_ofi_op_id->info.msg.buf_size = buf_size;
    // na_ofi_op_id->info.msg.actual_buf_size = 0;
    // na_ofi_op_id->info.msg.fi_addr = FI_ADDR_UNSPEC;
    // na_ofi_op_id->info.msg.fi_mr = plugin_data;
    // na_ofi_op_id->info.msg.tag = 0;

    ret = na_ucp_msg_recv(
        NA_UCX_CLASS(na_class)->ucp_worker, buf, buf_size, 0, 0, na_ucx_op_id);

    // na_ucx_context_t *nuctx = ctx->plugin_context;

    // return na_ucx_msg_recv(ctx, callback, arg, buf, buf_size,
    // nuctx->unexp.tag,
    //     nuctx->msg.tagmask, NA_CB_RECV_UNEXPECTED, op_id);

    return NA_SUCCESS;

error:
    return ret;
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_msg_send_expected(na_class_t NA_UNUSED *nacl, na_context_t *ctx,
    na_cb_t callback, void *arg, const void *buf, na_size_t buf_size,
    void NA_UNUSED *plugin_data, na_addr_t dest_addr,
    na_uint8_t NA_UNUSED dest_id, na_tag_t tag, na_op_id_t *op_id)
{
    // return na_ucx_msg_send(ctx, callback, arg, buf, buf_size, dest_addr, tag,
    //     NA_CB_SEND_EXPECTED, op_id);
}

/*---------------------------------------------------------------------------*/
static na_return_t
na_ucx_msg_recv_expected(na_class_t NA_UNUSED *nacl, na_context_t *ctx,
    na_cb_t callback, void *arg, void *buf, na_size_t buf_size,
    void NA_UNUSED *plugin_data, na_addr_t NA_UNUSED source_addr,
    na_uint8_t NA_UNUSED source_id, na_tag_t proto_tag, na_op_id_t *op_id)
{
    // na_ucx_context_t *nuctx = ctx->plugin_context;
    // const na_tag_t NA_DEBUG_USED maxtag =
    //     (na_tag_t) MIN(NA_TAG_MAX, nuctx->msg.tagmax);

    // assert(proto_tag <= maxtag);

    // return na_ucx_msg_recv(ctx, callback, arg, buf, buf_size,
    //     nuctx->exp.tag | (proto_tag << nuctx->msg.tagshift), UINT64_MAX,
    //     NA_CB_RECV_EXPECTED, op_id);
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
static NA_INLINE int
na_ucx_poll_get_fd(na_class_t *nacl, na_context_t *ctx)
{
    return NA_PROTOCOL_ERROR;
}

/*---------------------------------------------------------------------------*/
static NA_INLINE na_bool_t
na_ucx_poll_try_wait(na_class_t *nacl, na_context_t *ctx)
{
    return NA_PROTOCOL_ERROR;
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
na_ucx_cancel(na_class_t NA_UNUSED *nacl, na_context_t *context, na_op_id_t *op)
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
