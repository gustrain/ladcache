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

#include <stdint.h>
#include <pthread.h>
#include <liburing.h>
#include "../utils/uthash.h"

#ifndef __CACHE_H__
#define __CACHE_H__

#define MAX_PATH_LEN (128)                      /* Not including \0. */
#define MAX_SHM_PATH_LEN (MAX_PATH_LEN + 1)     /* Not including \0. */
#define MAX_NAME_LEN (128)                      /* Not including \0. */
#define MAX_SYNC_SIZE (16 * 1024 * (MAX_PATH_LEN + 1))

#define N_HEADER_BYTES (1)

#define TYPE_SYNC (0b0001) /* File ownership synchronization. */
#define TYPE_RQST (0b0000) /* File transfer request. */

#define FLAG_NONE (0b00000000)
#define FLAG_CRCT (0b00001000)  /* This message is a correction. */
#define FLAG_FLG2 (0b00000100)  /* Unused flag. */
#define FLAG_FLG3 (0b00000010)  /* Unused flag. */
#define FLAG_FLG4 (0b00000001)  /* Unused flag. */

/* File load request (queue entry). Shared memory accessible by both API users
   and the ladcache loader process. */
typedef struct file_request {
    /* File metadata. */
    size_t  size;                           /* Size of file data in bytes. */
    char    path[MAX_PATH_LEN + 1];         /* Path to file. */
    char    shm_path[MAX_SHM_PATH_LEN + 1]; /* PATH, but for shm object, and
                                               conforming to shm name rules. */

    /* Loader state. */
    void *_ldata;       /* Loader's pointer to the shm object's memory. */
    int   _lfd_shm;     /* Loader's FD for the shm object. */
    int   _lfd_file;    /* Loader's FD for the file being loaded. */
    bool  _skip_clean;  /* Whether to skip shm cleanup for this request. Set to
                           prevent shm cleanup for newly cached items. */

    /* User state. */
    void *udata;        /* User's pointer to the shm object's memory. */
    int   ufd_shm;      /* User's FD for the shm object. */

    /* Free list. */
    struct file_request *next;
    struct file_request *prev;

    UT_hash_handle hh;
} request_t;

/* File data location for the local cache. */
typedef struct local_location {
    char    path[MAX_PATH_LEN + 1];         /* Index in hash table. */
    char    shm_path[MAX_PATH_LEN + 2];     /* Path to the shm object. */
    int     shm_fd;                         /* FD for shm object. */
    void   *data;                           /* Pointer to shm obj's memory. */
    size_t  size;                           /* Size of file in bytes. */

    /* Update (new) list. */
    struct local_location *next;    /* Next entry in the new list. */
    struct local_location *prev;    /* Previous entry in the new list. */

    /* Hash table. */
    UT_hash_handle hh;
} lloc_t;

/* Local cache state. */
typedef struct {
    lloc_t *ht;         /* Hash table. */
    lloc_t *unsynced;   /* Link list of unsynced filenames. */
    size_t  capacity;   /* Maximum capacity of cache in bytes. */
    size_t  used;       /* Current usage of cache in bytes. */
} lcache_t;

/* General purpose network message struct. Messages follow the format below.

            ┌────────┬─────────┬───────────┬──────────┬───┬───────────┬──────────┐
    Sync    │header  │# entries│path length│filepath  │   │path length│filepath  │
    Message │0000xxxx│4 bytes  │4 bytes    │var. bytes│...│4 bytes    │var. bytes│
    (0001)  └────────┴─────────┴───────────┴──────────┴───┴───────────┴──────────┘
            ┌────────┬───────────┬──────────┐
    File    │header  │path length│filepath  │
    Request │0000xxxx│4 bytes    │var. bytes│
    (0000)  └┬───────┴───────────┴──────────┘
             │
             │ ┌──────┬──┬──┬──┬──┐
             └►│type  │CR│FL│FL│FL│
               │4 bits│CT│AG│AG│AG│
               └──────┴──┴──┴──┴──┘
                        BIT FLAGS

*/
typedef struct {
    uint8_t header;
    uint8_t data[];
} message_t;

/* Peer record. Hash table entry for peer IP -> socket. All records will be 
   shared by the network manager process, and used by the manager's threads. */
typedef struct {
    int sfd;                    /* Socket fd for this peer. */
    pthread_spinlock_t *lock;   /* Protects SFD from concurrent usage. */

    /* Hash table. */
    UT_hash_handle hh;
} peer_t;

/* File data location for a remote cache. */
typedef struct remote_location {
    uint32_t  ip;       /* IP of file owner. */
    peer_t   *owner;    /* Peer state for owner. Also accessible through HT. */
    uint16_t  port;     /* Port of file owner. */
    size_t    size;     /* Size of file in bytes. */

    /* Hash table. */
    UT_hash_handle hh;
} rloc_t;

/* Remote cache state. */
typedef struct {
    rloc_t             *ht;             /* Filepath -> rloc_t hash table. */
    pthread_spinlock_t  ht_lock;        /* Protects HT. */

    peer_t             *peers;          /* Hash table of peer IP -> socket. */
    pthread_spinlock_t  peers_lock;     /* Protects PEERS. */
} rcache_t;

/* User states. Private between users, shared with loader. */
typedef struct {
    /* Status queues and hash tables. */
    request_t *head;                /* Only used for teardown. */
    request_t *free;                /* Unused request_t structs. */
    request_t *ready;               /* Ready requests waiting to be executed. */
    request_t *network;             /* Requests being served by network (HT). */
    request_t *done;                /* Fulfilled requests. */

    /* Asynchronous IO. */
    struct io_uring ring;

    /* Synchronization. */
    pthread_spinlock_t free_lock;
    pthread_spinlock_t ready_lock;
    pthread_spinlock_t done_lock;
} ustate_t;

/* Peer record. Hash table entry for peer IP -> socket. All records will be 
   shared by the network manager process, and used by the manager's threads. */
typedef struct {
    int sfd;                    /* Socket fd for this peer. */
    pthread_spinlock_t *lock;   /* Protects SFD from concurrent usage. */

    /* Hash table. */
    UT_hash_handle hh;
} peer_t;

/* Complete/total cache state. */
typedef struct {
    lcache_t    lcache;     /* Local cache. */
    rcache_t    rcache;     /* Remote cache. */
    int         n_users;    /* Number of users. */
    int         qdepth;     /* Queue depth. */

    /* Threading info. */
    pthread_t manager_thread;
    pthread_t monitor_thread;

    /* User-shared memory. */
    ustate_t *ustates;  /* N_USERS + 1 user states. +1 for remote requests. */
} cache_t;

#endif