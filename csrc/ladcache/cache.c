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
#include <sys/shm.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#define N_HT_LOCKS (16)
#define PORT_DEFAULT (8080)
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

/* On success, returns the size of a file in bytes. On failure, returns -errno
   value. */
static off_t
file_get_size(int fd)
{
    struct stat st;
    if (fstat(fd, &st) < 0) {
        return -errno;
    }

    /* Check device type. */
    if (S_ISBLK(st.st_mode)) {
        /* Block device. */
        uint64_t bytes;
        if (ioctl(fd, BLKGETSIZE64, &bytes) != 0) {
            return -errno;
        }
        
        return bytes;
    } else if (S_ISREG(st.st_mode)) {
        return st.st_size;
    }
    
    /* Unknown device type. */
    return -ENODEV;
}

/* --------------------------- */
/*   NETWORK (manager scope)   */
/* --------------------------- */

/* Announce our existence to other members of the distributed cache. */
int
cache_register(cache_t *c)
{

    /* TODO. */
}

int
cache_sync_ownership()
{
    /* TODO. Announce */
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
        DEBUG_LOG("setsockopt failed\n");
        return -errno;
    }

    /* Bind to PORT_DEFAULT. */
    struct sockaddr_in addr;
    int len = sizeof(addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT_DEFAULT);
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        DEBUG_LOG("bind failed\n");
        return -errno;
    }

    /* Start listening. */
    if (listen(lfd, MAX_QUEUE_REQUESTS)) {
        DEBUG_LOG("listen failed\n");
        return -errno;
    }

    /* Handle all incoming connections. */
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


/* ----------------------------------------- */
/*   LOCAL CACHE INTERFACE (manager scope)   */
/* ----------------------------------------- */

/* Checks the local cache for PATH. Returns TRUE if contained, FALSE if not. */
bool
cache_local_contains(lcache_t *lc, char *path)
{
    lloc_t *loc = NULL;
    HASH_FIND_STR(lc->ht, path, loc);

    return (loc != NULL);
}

/* Caches SIZE bytes of DATA using PATH as the key. Copies DATA into a newly
   allocated shm object. Returns 0 on success, and a negative errno value on
   failure. */
int
cache_local_store(lcache_t *lc, char *path, uint8_t *data, size_t size)
{
    /* Verify we can fit this in the cache. */
    if (lc->used + size > lc->capacity) {
        DEBUG_LOG("item of %lu bytes too big to fit in local cache.\n", size);
        return -E2BIG;
    }

    /* Get a new location record. */
    lloc_t *loc = malloc(sizeof(lloc_t));
    if (loc == NULL) {
        DEBUG_LOG("malloc failed\n");
        return -ENOMEM;
    }

    /* Create the shm object. */
    shmify(path, loc->shm_path, MAX_PATH_LEN + 1, MAX_SHM_PATH_LEN + 1);
    loc->shm_fd = shm_open(loc->shm_path, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (loc->shm_fd < 0) {
        DEBUG_LOG("shm_open failed\n");
        return -errno;
    }

    /* Size the shm object. */
    loc->size = size;
    if (ftruncate(loc->shm_fd, size) < 0) {
        DEBUG_LOG("ftruncate failed\n");
        shm_unlink(loc->shm_fd);
        close(loc->shm_fd);
        return -errno;
    }

    /* Create the mmap. */
    loc->data = mmap(NULL, size, PROT_WRITE, MAP_SHARED, loc->shm_fd, 0);
    if (loc->data == NULL) {
        DEBUG_LOG("mmap failed\n");
        shm_unlink(loc->shm_path);
        close(loc->shm_fd);
        return -ENOMEM;
    }

    /* Page-lock the memory. */
    mlock(loc->data, size);

    /* Copy data to cache. */
    memcpy(loc->data, data, size);

    /* Insert into hash table. */
    strncpy(loc->path, path, 128);
    HASH_ADD_STR(lc->ht, path, loc);

    return 0;
}

/* Fill a request with data from the local cache. Returns 0 on success, -errno
   on failure. */
int
cache_local_load(lcache_t *lc, request_t *request)
{
    /* Get the location record of the cached file. */
    lloc_t *loc = NULL;
    HASH_FIND_STR(lc->ht, request->path, loc);
    if (loc == NULL) {
        DEBUG_LOG("attempted to load uncached file; %s", request->path);
        return -ENODATA;
    }

    /* Fill the request. */
    request->_ldata = loc->data;
    request->_lfd_shm = loc->shm_fd;

    return 0;
}


/* ------------------------------------------ */
/*   REMOTE CACHE INTERFACE (Manager scope)   */
/* ------------------------------------------ */

/* Checks the remote cache for PATH. Returns TRUE if contained, FALSE if not. */
bool
cache_remote_contains(rcache_t *rc, char *path)
{
    rloc_t *loc = NULL;
    HASH_FIND_STR(rc->ht, path, loc);
    
    return (loc != NULL);
}

/* Arguments to cache_remote_load. */
typedef struct cache_remote_load_args {
    rcache_t *rc;
    ustate_t *user;
    request_t *request;
};

/* Thread target to request a file from a peer. Should be passed a malloc'd
   cache_remote_load_args struct, which will be freed once arguments haev been
   parsed. Assumes that the caller has already removed REQUEST from USER's ready
   queue. The completed request will be placed into USER's done queue. */
void
cache_remote_load(void *args)
{
    /* Get the arguments passed to us. */
    rcache_t *rc = ((struct cache_remote_load_args *) args)->rc;
    ustate_t *user = ((struct cache_remote_load_args *) args)->user;
    request_t *request = ((struct cache_remote_load_args *) args)->request;
    free(args);

    /* Find who to request the file from. */
    rloc_t *loc = NULL;
    HASH_FIND_STR(rc->ht, request->path, loc);
    if (loc == NULL) {
        return -ENODATA;
    }
    struct sockaddr_in peer_addr = {
        .sin_addr = loc->ip,
        .sin_family = AF_INET,
        .sin_port = loc->port
    };

    /* Construct transfer request message according to cache.h specification. */
    int path_len = strlen(request->path);
    int message_len = sizeof(message_t) + sizeof(int) + path_len;
    message_t *message = malloc(message_len);
    if (message == NULL) {
        return -ENOMEM;
    }
    message->header = TYPE_RQST;                                /* Header. */
    memcpy(&message->data[0], (void *) path_len, sizeof(int));  /* Length. */
    memcpy(&message->data[4], request->path, path_len);         /* Path. */

    /* Connect to the peer's manager socket. */
    int peer_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (peer_fd < 0) {
        return -errno;
    }
    if (connect(peer_fd, &peer_addr, sizeof(peer_addr)) < 0) {
        close(peer_fd);
        return -errno;
    }

    /* Send our request. */
    assert(send(peer_fd, (void *) message, message_len, 0) == message_len);

    return 0;
}


/* --------------------------- */
/*   MANAGER (manager scope)   */
/* --------------------------- */

/* Submit an IO request to io_uring. Returns 0 on success, -errno on failure. */
int
manager_submit_io(ustate_t *ustate, request_t *r)
{
    /* Open the file. */
    r->_lfd_file = open(r->path, O_RDONLY | __O_DIRECT);
    if (r->_lfd_file < 0) {
        DEBUG_LOG("open failed; %s\n", r->path);
        return -ENOENT;
    }

    /* Get the size of the file, rounding the size up to the nearest multiple of
       4KB for O_DIRECT compatibility. */
    off_t size = file_get_size(r->_lfd_file);
    if (size < 0) {
        DEBUG_LOG("file_get_size failed\n");
        return (int) size;
    }
    r->size = (((size_t) size) | 0xFFF) + 1;

    /* Create buffer using shm. */
    r->_lfd_shm = shm_open(r->shm_path, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (r->_lfd_shm < 0) {
        DEBUG_LOG("shm_open failed; %s\n", r->shm_path);
        return -errno;
    }

    /* Size buffer to fit file data. */
    if (ftruncate(r->_lfd_shm, r->size) < 0) {
        DEBUG_LOG("ftruncate failed\n");
        shm_unlink(r->shm_path);
        close(r->_lfd_shm);
        close(r->_lfd_file);
        return -errno;
    }

    /* Create mmap for the shm object. */
    r->_ldata = mmap(NULL, r->size, PROT_WRITE, MAP_SHARED, r->_lfd_shm, 0);
    if (r->_ldata == NULL) {
        DEBUG_LOG("mmap failed\n");
        shm_unlink(r->shm_path);
        close(r->_lfd_shm);
        close(r->_lfd_file);
        return -ENOMEM;
    }

    /* Tell io_uring to read the file into the buffer. */
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ustate->ring);
    io_uring_prep_read(sqe, r->_lfd_file, r->_ldata, r->size, 0);
    io_uring_sqe_set_data(sqe, r);

    return 0;
}

/* Check whether USTATE has a pending request, and execute it if it does.
   Returns 0 on sucess, -errno on failure. */
int
manager_check_ready(cache_t *c, ustate_t *ustate)
{
    request_t *pending;

    /* Check if there's a request waiting in the ready queue. */
    QUEUE_POP_SAFE(ustate->ready, &ustate->ready_lock, next, prev, pending);
    if (pending == NULL) {
        return 0;
    }

    /* Check the local cache. */
    if (cache_local_contains(&c->lcache, pending->path)) {
        int status = cache_local_load(&c->lcache, pending);
        if (status < 0) {
            /* ISSUE: we leak a request struct here. */
            DEBUG_LOG("cache_local_load failed\n");
            return status;
        }

        QUEUE_PUSH_SAFE(ustate->done, &ustate->done_lock, next, prev, pending);
    }

    /* Check the remote cache. */
    if (cache_remote_contains(&c->rcache, pending->path)) {
        /* Prepare arguments for cache_remote_load. */
        struct cache_remote_load_args *args = malloc(sizeof(struct cache_remote_load_args));
        if (args == NULL) {
            return -ENOMEM;
        }
        args->rc = &c->rcache;
        args->request = pending;
        args->user = ustate;

        /* Spawn a thread to handling requesting the file from the peer. It will
           take care of itself and doesn't require management. */
        pthread_t _;
        assert(!pthread_create(&_, NULL, cache_remote_load, (void *) args));

        return 0;
    }

    /* If not cached, issue IO. */
    int status = manager_submit_io(ustate, pending);
    if (status < 0) {
        DEBUG_LOG("manager_submit_io failed\n");
        return status;
    }

    return 0;
}

/* Check if any storage requests have completed their IO. Note that the network
   monitor handles completed network requests. Returns 0 on sucess, -errno on
   failure. */
int
manager_check_done(cache_t *c, ustate_t *ustate)
{
    /* Drain the io_uring completion queue into our completion queue. Using
       peek (instead of wait) to ensure the check is non-blocking. */
    struct io_uring_cqe *cqe;
    while (!io_uring_peek_cqe(&ustate->ring, &cqe)) {
        request_t *request = io_uring_cqe_get_data(cqe);
        io_uring_cqe_seen(&ustate->ring, cqe);

        /* Try to cache this file. */
        if (c->lcache.used + request->size <= c->lcache.capacity) {
            lloc_t *loc = malloc(sizeof(lloc_t));
            if (loc == NULL) {
                DEBUG_LOG("malloc fail\n");
                goto skip_cache;
            }

            /* Prepare the location record and append it to the list of unsynced
               filepaths for this epoch. */
            *loc = (lloc_t) {
                .data = request->_ldata,
                .shm_fd = request->_lfd_shm,
                .size = request->size,
            };
            strncpy(loc->path, request->path, MAX_PATH_LEN);
            strncpy(loc->shm_path, request->shm_path, MAX_SHM_PATH_LEN);

            /* Add to the hash table indexed by PATH. */
            HASH_ADD_STR(c->lcache.ht, path, loc);
            c->lcache.used += loc->size;
            request->_skip_clean = true;

            /* Add to list of filenames to be synchronized. */
            QUEUE_PUSH(c->lcache.unsynced, next, prev, loc);
        }

       skip_cache:
        QUEUE_PUSH_SAFE(ustate->done, &ustate->done_lock, next, prev, request);
    }
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
    QUEUE_POP_SAFE(user->free, &user->free_lock, next, prev, request);
    if (request == NULL) {
        DEBUG_LOG("&user->free is empty\n");
        return -EAGAIN; /* Try again once completed requests have been freed. */
    }
    memset(request, 0, sizeof(request_t));
    strncpy(request->path, path, MAX_PATH_LEN);
    shmify(request->path, request->shm_path, MAX_PATH_LEN + 1, MAX_SHM_PATH_LEN + 1);

    /* Submit request to the monitor. */
    QUEUE_PUSH_SAFE(user->ready, &user->ready_lock, next, prev, request);
    
    return 0;
}

/* Reap a completed request for USER. Points OUT to a completed request. Returns
   0 on sucess, -errno on failure. */
int
cache_get_reap(ustate_t *user, request_t *out)
{
    /* Try to get a completed request. */
    out = NULL;
    QUEUE_POP_SAFE(user->done, &user->done_lock, next, prev, out);
    if (out == NULL) {
        DEBUG_LOG("&user->done is empty\n");
        return -EAGAIN; /* Try again once request has been fulfilled. */
    }

    return 0;
}


/* --------------------------- */
/*   ALLOCATION (user scope)   */
/* --------------------------- */

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

    /* Free all of the user states. */
    if (c->ustates != NULL) {
        /* Free the queues. */
        for (int i = 0; i < c->n_users; i++) {
            mmap_free(c->ustates[i].head, c->qdepth * sizeof(request_t));
            io_uring_queue_exit(&c->ustates[i].ring);
        }

        /* Free the user states. */
        mmap_free(c->ustates, c->n_users * sizeof(ustate_t));
    }

    /* Destroy the cache struct itself. */
    mmap_free(c, sizeof(cache_t));
}

/* Allocate a complete cache. Returns 0 on success and -errno on failure. */
int
cache_init(cache_t *c, size_t capacity, unsigned queue_depth, int n_users)
{
    /* Allocate user states. */
    if ((c->ustates = mmap_alloc(n_users * sizeof(ustate_t))) == NULL) {
        DEBUG_LOG("mmap_alloc failed\n");
        return -ENOMEM;
    }

    /* Initialize user states. */
    for (int i = 0; i < c->n_users; i++) {
        ustate_t *ustate = &c->ustates[i];

        /* Allocate requests (queue entries). */
        if ((ustate->free = mmap_alloc(queue_depth * sizeof(request_t))) == NULL) {
            cache_destroy(c);
            DEBUG_LOG("mmap_alloc failed\n");
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
        ustate->done = NULL;

        /* Initialize the io_uring queues. */
        int status = io_uring_queue_init(queue_depth, &ustate->ring, 0);
        if (status < 0) {
            DEBUG_LOG("io_uring_queue_init failed\n");
            cache_destroy(c);
            return status;
        }

        /* Initialize the locks. */
        assert(!pthread_spinlock_init(&ustate->free_lock, PTHREAD_PROCESS_SHARED));
        assert(!pthread_spinlock_init(&ustate->ready_lock, PTHREAD_PROCESS_SHARED));
        assert(!pthread_spinlock_init(&ustate->done_lock, PTHREAD_PROCESS_SHARED));
    }

    /* Set up the local cache. */
    c->lcache.ht = NULL;
    c->lcache.unsynced = NULL;
    c->lcache.capacity = capacity;
    c->lcache.used = 0;

    /* Set up the remote cache. */
    c->rcache.ht = NULL;
    assert(!pthread_spinlock_init(&c->rcache.ht_lock));

    /* Set up the total cache. */
    c->n_users = n_users;
    c->qdepth = queue_depth;

    return 0;
}
