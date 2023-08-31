/* MIT License

   Copyright (c) 2023 Gus Waldspurger

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.
   */

#include "cache.h"
#include "../utils/uthash.h"
#include "../utils/alloc.h"
#include "../utils/fifo.h"
#include "../utils/log.h"
#include <stdbool.h>
#include <pthread.h>
#include <errno.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define N_HT_LOCKS 16
#define PORT_DEFAULT 8080
#define MAX_QUEUE_REQUESTS 64

#define MIN(a, b) (a) > (b) ? (a) : (b)

/* --------- */
/*   MISC.   */
/* --------- */

/* Copy IN to OUT, but reformatted to fit shm naming requirements. */
void
shmify(char *in, char *out, size_t in_length, size_t out_length)
{
    assert(out_length > 0);

    out[0] = '/';
    for (int i = 0; i < MIN(in_length, out_length - 1); i++) {
        /* Replace all occurences of '/' with '_'. */
        out[i + 1] = in[i] == '/' ? '_' : in[i];
        if (in[i] == '\0') {
            break;
        }
    }
}

/* ----------- */
/*   NETWORK   */
/* ----------- */

/* Announce our existence to other members of the distributed cache. */
int
cache_register(cache_t *c)
{
    /* TODO. */
}

/* Handles a remote read request. */
void
monitor_handle_connection(void *arg)
{
    int client_fd = (int) arg;
    /* TODO. */
}

/* Monitor main loop. Handles all incoming remote read requests. Should never
   return when running correctly. On failure returns negative errno value. */
int
monitor_loop(cache_t *c)
{
    
    /* Open the listening socket. */
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        return -errno;
    }

    /* Allow address to be re-used. */
    int opt = 1;
    if (setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) { /* Needed? */
        return -errno;
    }

    /* Bind to PORT_DEFAULT. */
    struct sockaddr_in addr;
    int len = sizeof(addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT_DEFAULT);
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        return -errno;
    }

    /* Start listening. */
    if (listen(lfd, MAX_QUEUE_REQUESTS)) {
        return -errno;
    }

    while (true) {
        int cfd = accept(lfd, (struct sockaddr *) &addr, (socklen_t *) &len);
        if (cfd >= 0) {
            pthread_t tid; /* This thread will terminate gracefully on its own and we don't need to track it. */
            pthread_create(&tid, NULL, &monitor_handle_connection, (void *) cfd);
        }
    }

    /* Not reached. */
    return 0;
}

/* Spawns a new thread running the monitor loop. Returns 0 on success, -errno on
   failure. */
int
monitor_spawn(cache_t *c)
{
    return -pthread_create(&c->monitor_thread, NULL, monitor_loop, c);
}


/* ------------------------- */
/*   LOCAL CACHE INTERFACE   */
/* ------------------------- */

/* Checks the local cache for PATH. Returns TRUE if contained, FALSE if not. */
bool
cache_local_contains(lcache_t *lc, char *path)
{
    /* TODO. */
}

/* Caches SIZE bytes of DATA using PATH as the key. Returns 0 on success, and
   a negative errno value on failure. */
int
cache_local_store(lcache_t *lc, char *path, uint8_t *data, size_t size)
{
    /* TODO. */
}

int
cache_local_load(lcache_t *lc, request_t *request)
{
    /* TODO. */
}


/* -------------------------- */
/*   REMOTE CACHE INTERFACE   */
/* -------------------------- */

/* Checks the remote cache for PATH. Returns TRUE if contained, FALSE if not. */
bool
cache_remote_contains(rcache_t *rc, char *path)
{
    /* TODO. */
}

int
cache_remote_load(rcache_t *rc, request_t *request)
{
    /* TODO. */
}


/* ----------- */
/*   MANAGER   */
/* ----------- */

/* Check whether USTATE has a pending request, and execute it if it does.
   Returns 0 on sucess, -errno on failure. */
int
manager_check_ready(cache_t *c, ustate_t *ustate)
{
    request_t *pending;

    /* Check if there's a request waiting in the ready queue. */
    QUEUE_POP_SAFE(ustate->ready, &ustate->read_lock, next, prev, pending);
    if (pending == NULL) {
        return 0;
    }

    /* Check the local cache. */
    if (cache_local_contains(&c->lcache, pending->path)) {
        int status = cache_local_load(&c->lcache, pending);
        if (status < 0) {
            /* ISSUE: we leak a request struct here. */
            return status;
        }

        QUEUE_PUSH_SAFE(&ustate->done, &ustate->done_lock, next, prev, pending);
    }

    /* Check the remote cache. */
    if (cache_remote_contains(&c->rcache, pending->path)) {
        int status = cache_remote_load(&c->rcache, pending);
        if (status < 0) {
            /* ISSUE: we leak a request struct here. */
            return status;
        }

        QUEUE_PUSH(&ustate->network_inflight, next, prev, pending);
    }

    /* If not cached, issue IO. */

    /* TODO. */

    QUEUE_PUSH(&ustate->storage_inflight, next, prev, pending);
}

/* Check if any storage requests have completed their IO. Note that the network
   monitor handles completed network requests. Returns 0 on sucess, -errno on
   failure. */
int
manager_check_done(cache_t *c, ustate_t *ustate)
{
    /* TODO. */
}

/* Manager main loop. Handles all pending requests. */
void
manager_loop(cache_t *c)
{
    ustate_t *ustate;
    request_t *pending;

    /* Loop round-robin through the user ustates and check for pending and
       completed requests that require status queue updates. */
    for (unsigned i = 0; true; ustate = &c->ustates[i++ % c->n_users]) {
        manager_check_ready(c, ustate);
        manager_check_done(c, ustate);
    }
}

/* Spawns a new thread running the manager loop. Returns 0 on success, -errno on
   failure. */
int
manager_spawn(cache_t *c)
{
    return -pthread_create(&c->manager_thread, NULL, manager_loop, c);
}


/* ---------------------------------- */
/*   GENERIC INTERFACE (user scope)   */
/* ---------------------------------- */

/* Submit a request for the file at PATH to be loaded for USER. Returns 0 on
   success, -errno on failure. */
int
cache_get_submit(ustate_t *user, char *path)
{
    /* Generate request. */
    request_t *request = NULL;
    QUEUE_POP_SAFE(&user->free, &user->free_lock, next, prev, request);
    if (request == NULL) {
        return -EAGAIN; /* Try again once completed requests have been freed. */
    }
    memset(request, 0, sizeof(request_t));
    strncpy(request->path, path, MAX_PATH_LEN);
    shmify(request->path, request->shm_path, MAX_PATH_LEN + 1, MAX_PATH_LEN + 2);

    /* Submit request to the monitor. */
    QUEUE_PUSH_SAFE(&user->ready, &user->read_lock, next, prev, request);
    
    return 0;
}

/* Reap a completed request for USER. Points OUT to a completed request. Returns
   0 on sucess, -errno on failure. */
int
cache_get_reap(ustate_t *user, request_t *out)
{
    /* Try to get a completed request. */
    out = NULL;
    QUEUE_POP_SAFE(&user->done, &user->done_lock, next, prev, out);
    if (out == NULL) {
        return -EAGAIN; /* Try again once request has been fulfilled. */
    }

    return 0;
}


/* -------------- */
/*   ALLOCATION   */
/* -------------- */

/* Get a cache_t struct using shared memory. Returns NULL on failure. */
cache_t *
cache_new(void)
{
    return mmap_alloc(sizeof(cache_t));
}

/* Destroy a complete cache. Allows for the destruction of both partially and
   fully allocated caches. */
void
cache_destroy(cache_t *c)
{
    if (c == NULL) {
        return;
    }

    if (c->ustates != NULL) {
        /* Free the queues. */
        for (int i = 0; i < c->n_users; i++) {
            mmap_free(c->ustates[i].head, c->qdepth * sizeof(request_t));
        }

        /* Free the user states. */
        mmap_free(c->ustates, c->n_users * sizeof(ustate_t));
    }

    /* Destroy the cache struct itself. */
    mmap_free(c, sizeof(cache_t));
}

/* Allocate a complete cache. Returns 0 on success and -errno on failure. */
int
cache_init(cache_t *c, size_t capacity, int queue_depth, int n_users)
{
    /* Allocate user states. */
    if ((c->ustates = mmap_alloc(n_users * sizeof(ustate_t))) == NULL) {
        return -ENOMEM;
    }

    /* Initialize user states. */
    for (int i = 0; i < c->n_users; i++) {
        ustate_t *ustate = &c->ustates[i];

        /* Allocate requests (queue entries). */
        if ((ustate->free = mmap_alloc(queue_depth * sizeof(request_t))) == NULL) {
            cache_destroy(c);
            return -ENOMEM;
        }
        ustate->head = ustate->free;

        /* Initialize requests. */
        for (int j = 0; j < queue_depth; j++) {
            ustate->free[i].next = &ustate->free[(i + 1) % queue_depth];
            ustate->free[i].prev = &ustate->free[(i - 1) % queue_depth];
        }

        /* Ensure the list is NULL terminated. */
        ustate->free[0].prev = NULL;
        ustate->free[queue_depth - 1].next = NULL;
        

        /* The other queues start empty. */
        ustate->ready = NULL;
        ustate->storage_inflight = NULL;
        ustate->network_inflight = NULL;
        ustate->done = NULL;

        /* Initialize the locks. */
        pthread_spinlock_init(&ustate->free_lock, PTHREAD_PROCESS_SHARED);
        pthread_spinlock_init(&ustate->ready_lock, PTHREAD_PROCESS_SHARED);
        pthread_spinlock_init(&ustate->done_lock, PTHREAD_PROCESS_SHARED);
    }

    /* Set up the local cache. */
    c->lcache.ht = NULL;
    c->lcache.capacity = capacity;
    c->lcache.used = 0;

    /* Set up the remote cache. */
    c->rcache.ht = NULL;

    /* Set up the total cache. */
    c->n_users = n_users;
    c->qdepth = queue_depth;

    return 0;
}
