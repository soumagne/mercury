#ifndef WIRING_IMPL_H_
#define WIRING_IMPL_H_

#include <stdint.h> /* uint32_t, uint16_t, uint8_t */

#include "wiring.h"

typedef enum {
      OP_REQ        = 0
    , OP_ACK        = 1
    , OP_KEEPALIVE  = 2
    , OP_STOP       = 3
} wireup_op_t;

typedef struct wireup_msg {
    uint32_t sender_id;
    uint16_t op;        // wireup_op_t
    uint16_t addrlen;
    uint8_t addr[];
} wireup_msg_t;

const char *wireup_op_string(wireup_op_t);

struct wire;
typedef struct wire wire_t;

struct wire_state;
typedef struct wire_state wire_state_t;

typedef struct timeout_link {
    sender_id_t prev, next;
    uint64_t due;
} timeout_link_t;

typedef struct timeout_head {
    sender_id_t first, last;
} timeout_head_t;

enum {
  timo_expire = 0
, timo_wakeup
, timo_nlinks
};

struct wire {
    timeout_link_t tlink[timo_nlinks];
    const wire_state_t *state;
    ucp_ep_h ep;        /* Endpoint connected to this wire's remote peer */
    wireup_msg_t *msg;  /* In initial state, the request to be
                         * (re)transmitted.  In all other states,
                         * NULL.
                         */
    size_t msglen;
    sender_id_t next;   /* ID of next closed wire or next free wire, depending
                         * which list this wire is on.
                         */
    sender_id_t id;     /* Sender ID assigned by this wire's remote peer */
    wire_event_cb_t cb;
    void *cb_arg;
};

struct wstorage {
    sender_id_t first_free;
    timeout_head_t thead[timo_nlinks];
    sender_id_t nwires;
    wire_t wire[];
};

static inline sender_id_t
wire_index(wstorage_t *storage, wire_t *w)
{
    return (sender_id_t)(w - &storage->wire[0]);
}

static inline sender_id_t
wiring_free_get(wstorage_t *storage)
{
    wire_t *w;
    sender_id_t id;
    int which;

    if ((id = storage->first_free) == sender_id_nil)
        return sender_id_nil;
    w = &storage->wire[id];
    for (which = 0; which < timo_nlinks; which++) {
        timeout_link_t * wiring_debug_used link = &w->tlink[which];
        assert(link->next == id && link->prev == id);
    }
    storage->first_free = w->next;
    w->next = sender_id_nil;

    return id;
}

static inline void
wiring_free_put(wstorage_t *storage, sender_id_t id)
{
    assert(id != sender_id_nil);

    storage->wire[id].next = storage->first_free;
    storage->first_free = id;
}

#endif /* WIRING_IMPL_H_ */
