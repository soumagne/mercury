/*
 * See wireup.md for a discussion of the "wireup" protocol
 * whose data structures and message format are defined here.
 */

#ifndef WIRES_H_
#define WIRES_H_

#include <assert.h>
#include <inttypes.h>   /* PRIu32 */
#include <stdbool.h>
#include <stdint.h>     /* int32_t */
#include <unistd.h>     /* size_t, SIZE_MAX */

#include <sys/queue.h>

#include <ucp/api/ucp.h>

#include "../util/mercury_thread.h"
#include "../util/mercury_thread_mutex.h"
#include "../util/mercury_thread_condition.h"

#include "wiring_compat.h"

typedef uint32_t sender_id_t;

#define SENDER_ID_MAX UINT32_MAX

#define PRIuSENDER PRIu32

#define sender_id_nil SENDER_ID_MAX

struct wiring;
typedef struct wiring wiring_t;

struct wstorage;
typedef struct wstorage wstorage_t;

typedef struct wire_id {
    sender_id_t wiring_atomic id;
} wire_id_t;

/* Wire event message types. */
typedef enum {
  wire_ev_estd = 0      // wire was established
, wire_ev_closed        // an established wire was closed
, wire_ev_reclaimed     // a closed wire was reclaimed
} wire_event_t;

typedef struct wire_event_info {
    wire_event_t event;         /* message type */
    ucp_ep_h ep;                /* local endpoint */
    sender_id_t sender_id;      /* identifier for the local wire slot */
} wire_event_info_t;

/* Wire-event callbacks have this type.  When a wire is established, closed,
 * or reclaimed, wireup calls the user back on an optional callback of this
 * type.
 */
typedef bool (*wire_event_cb_t)(wire_event_info_t, void *);

typedef struct wire_accept_info {
    const ucp_address_t *addr;
    size_t addrlen;
    wire_id_t wire_id;  /* TBD mention which ID is which here */
    sender_id_t sender_id;
    ucp_ep_h ep;
} wire_accept_info_t;

/* When a new wire is accepted from a remote peer, wireup calls the user
 * back on an optional callback of this type.
 */
typedef void *(*wire_accept_cb_t)(wire_accept_info_t, void *,
    wire_event_cb_t *, void **);

struct wiring_request;
typedef struct wiring_request wiring_request_t;

typedef struct wiring_request {
    wiring_request_t *next;
} wiring_request_t;

struct wiring_ref;
typedef struct wiring_ref wiring_ref_t;

struct wiring_ref {
    volatile bool wiring_atomic busy;
    volatile uint64_t wiring_atomic epoch;
    wiring_ref_t *next;
    void (*reclaim)(wiring_ref_t *);
};

typedef struct wiring_garbage_bin {
    sender_id_t first_closed;
    void **assoc;
    wstorage_t *storage;
    wiring_ref_t * volatile wiring_atomic first_ref;
} wiring_garbage_bin_t;

typedef struct wiring_garbage_schedule {
    /* A writer both initiates new epochs and reclaims resources
     * connected with prior epochs. first <= last, always.  If first <
     * last, then there are resources to reclaim in the `last - first`
     * circular-buffer bins starting at bin[first % NELTS(bin)].
     */
    struct {
        volatile uint64_t wiring_atomic first, last;
    } epoch;
    volatile uint64_t wiring_atomic work_available;
    /* The wire_t storage and the associated-data table cannot
     * be reallocated more than 64 times during a program's
     * lifetime, because the size of each doubles with each reallocation
     * and we do not expect for 2^64 bytes to be available for
     * either.  So 64 bins should be enough to hold all of the
     * garbage related to those reallocations.  64 additional bins
     * are for chains of closed wires whose reclamation is deferred.
     */
    wiring_garbage_bin_t bin[128];
} wiring_garbage_schedule_t;

typedef enum {
  phase_stopped = 0
, phase_running
, phase_stopping
} wiring_phase_t;

struct wiring {
    hg_thread_mutex_t mtx;
    wire_accept_cb_t accept_cb;
    void *accept_cb_arg;
    rxpool_t *rxpool;
    wstorage_t *storage;
    void **assoc;   /* assoc[i] is a pointer to wire i's optional
                     * "associated data"
                     */
    ucp_worker_h worker;
    size_t request_size;
    /* wiring_request_t queues are protected by the wiring_t lock, lkb. */
    wiring_request_t *req_outst_head;    // ucp_request_t's outstanding
    wiring_request_t **req_outst_tailp;  // ucp_request_ts outstanding
    wiring_request_t *req_free_head;     // ucp_request_t free list
    wiring_garbage_schedule_t garbage_sched;
    hg_thread_t thread;
    hg_thread_cond_t cv;
    volatile bool wiring_atomic ready_to_progress;
    volatile wiring_phase_t wiring_atomic phase;
    volatile bool wiring_atomic armed;
};

#define wire_id_nil (wire_id_t){.id = sender_id_nil}

wiring_t *wiring_create(ucp_worker_h, size_t, wire_accept_cb_t, void *);
bool wiring_worker_arm(wiring_t *);
bool wiring_init(wiring_t *, ucp_worker_h, size_t, wire_accept_cb_t, void *);
int wireup_once(wiring_t *);
void wiring_destroy(wiring_t *, bool);
void wiring_teardown(wiring_t *, bool);
wire_id_t wireup_start(wiring_t *, ucp_address_t *, size_t,
    ucp_address_t *, size_t, wire_event_cb_t, void *, void *);
bool wireup_stop(wiring_t *, wire_id_t, bool);
void wireup_app_tag(wiring_t *, uint64_t *, uint64_t *);
const char *wire_event_string(wire_event_t);
void *wire_get_data(wiring_t *, wire_id_t);

hg_thread_mutex_t *wiring_lock(wiring_t *);
void wiring_unlock(wiring_t *);
void wiring_assert_locked_impl(wiring_t *, const char *, int);

void wiring_ref_init(wiring_t *, wiring_ref_t *,
    void (*reclaim)(wiring_ref_t *));

/* Assert that the wiring lock is held, if a lock was established by
 * `wiring_create`/`wiring_init`.  Otherwise, do nothing.
 */
#define wiring_assert_locked(wiring)                            \
do {                                                            \
    wiring_t *wal_wiring = (wiring);                            \
    wiring_assert_locked_impl(wal_wiring, __FILE__, __LINE__);  \
} while (0)

/* Reserved value for the associated-data pointer of an unopened or
 * already-closed wire.
 */
extern void * const wire_data_nil;

/* Return true iff the slot number is valid. */
static inline bool
wire_is_valid(wire_id_t wid)
{
    return wid.id != sender_id_nil;
}

/* Acquire a reference to the current wiring condition and store it at
 * `ref`.  The reference can be released with a call to `wiring_ref_get`
 * with the same `ref`.
 *
 * Calls to `wiring_ref_get` and `wiring_ref_put` form matching pairs.
 * Pairs should not nest.
 *
 * Callers are responsible for serializing wiring_ref_get() and
 * wiring_ref_put() calls affecting the same `ref`.
 */
static inline void
wiring_ref_get(wiring_t *wiring, wiring_ref_t *ref)
{
    wiring_garbage_schedule_t *sched = &wiring->garbage_sched;
    const uint64_t last = atomic_load_explicit(&sched->epoch.last,
        memory_order_acquire);

    assert(!atomic_load_explicit(&ref->busy, memory_order_relaxed));

    atomic_store_explicit(&ref->busy, true, memory_order_release);

    const uint64_t epoch = atomic_load_explicit(&ref->epoch,
        memory_order_relaxed);

    if (epoch == last)
        return;

    atomic_store_explicit(&ref->epoch, last, memory_order_release);

    atomic_fetch_add_explicit(&sched->work_available, 1,
                              memory_order_relaxed);
}

/* Release the reference at `ref` to the wiring condition that was
 * obtained by the previous call to `wiring_ref_get` with the same
 * `ref`.
 *
 * Calls to `wiring_ref_get` and `wiring_ref_put` form matching pairs.
 * Pairs should not nest.
 *
 * Callers are responsible for serializing `wiring_ref_get` and
 * `wiring_ref_put` calls affecting the same `ref`.
 */
static inline void
wiring_ref_put(wiring_t *wiring, wiring_ref_t *ref)
{
    wiring_garbage_schedule_t *sched = &wiring->garbage_sched;
    const uint64_t last = atomic_load_explicit(&sched->epoch.last,
        memory_order_acquire);

    assert(atomic_load_explicit(&ref->busy, memory_order_relaxed));

    atomic_store_explicit(&ref->busy, false, memory_order_release);

    const uint64_t epoch = atomic_load_explicit(&ref->epoch,
        memory_order_relaxed);

    if (epoch == last)
        return;

    atomic_store_explicit(&ref->epoch, last, memory_order_release);

    atomic_fetch_add_explicit(&sched->work_available, 1,
                              memory_order_relaxed);
}

/* Mark the reference `ref` as ready for destruction.  Wiring may still
 * holds references to `ref`.  When wiring has finished with `ref`, it
 * will call the `reclaim` routine that was registered with `ref` by
 * `wiring_ref_init`.  The call to `reclaim` ordinarily will come
 * an arbitrary amount of time after `wiring_ref_free` has returned,
 * but before `wiring_destroy(wiring)` or `wiring_teardown(wiring)`
 * returns.
 */
static inline void
wiring_ref_free(wiring_t *wiring, wiring_ref_t *ref)
{
    wiring_garbage_schedule_t *sched = &wiring->garbage_sched;

    assert(!atomic_load_explicit(&ref->busy, memory_order_relaxed));

    ref->epoch = UINT64_MAX;

    atomic_fetch_add_explicit(&sched->work_available, 1,
                              memory_order_relaxed);
}

#endif /* WIRES_H_ */
