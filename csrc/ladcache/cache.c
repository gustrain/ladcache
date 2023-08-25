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

#define N_HT_LOCKS

/* --------- */
/*   MISC.   */
/* --------- */

void
shmify(char *in, char *out, size_t in_length, size_t out_length)
{
    /* TODO. */
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
monitor_handle_connection(request_t *r)
{
    /* TODO. */
}

/* Monitor main loop. Handles all incoming remote read requests. */
void
monitor_loop(cache_t *c)
{
    /* TODO. */
}

/* Spawn a thread running MONITOR_LOOP. */
int
cache_spawn_monitor(cache_t *c)
{
    /* TODO. */
}


/* ---------------------------------------- */
/*   LOCAL CACHE INTERFACE (shared scope)   */
/* ---------------------------------------- */

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

/* Load the file at PATH from the local cache. Return a pointer to the file data
   in an shm object named with the shm-ified filename. Returns NULL on
   failure. */
uint8_t *
cache_local_load(lcache_t *lc, char *path, size_t *size)
{
    /* TODO. */
}

/* ----------------------------------------- */
/*   REMOTE CACHE INTERFACE (shared scope)   */
/* ----------------------------------------- */

/* Checks the remote cache for PATH. Returns TRUE if contained, FALSE if not. */
bool
cache_remote_contains(rcache_t *rc, char *path)
{
    /* TODO. */
}

/* Load the file at PATH from the remote cache. Return a pointer to the file
   data in an shm object named with the shm-ified filename. Returns NULL on
   failure. */
uint8_t *
cache_remote_load(rcache_t *rc, char *path, size_t *size)
{
    /* TODO. */
}


/* ----------- */
/*   MANAGER   */
/* ----------- */

/* Manager main loop. Handles all pending requests. */
void
manager_loop(cache_t *c)
{
    /* TODO. */
}

/* */
void
manager_spawn(cache_t *c)
{
    /* TODO. */
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

/* Allocate a complete cache. */
int
cache_init(cache_t *c, int queue_depth, int n_users)
{
    /* TODO. */
}

/* Destroy a complete cache. */
void
cache_destroy(cache_t *c)
{
    /* TODO. */
}
