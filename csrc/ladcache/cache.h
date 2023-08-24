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
#include "../utils/uthash.h"

#ifndef __CACHE_H__
#define __CACHE_H__

#define MAX_PATH_LEN (128)

/* File load request (queue entry). Shared memory accessible by both API users
   and the ladcache loader process. */
typedef struct file_request {
    /* File metadata. */
    size_t  size;                           /* Size of file data in bytes. */
    char    path[MAX_PATH_LEN + 1];         /* Path to file. */
    char    shm_path[MAX_PATH_LEN + 2];     /* PATH, but for shm object, and
                                               conforming to shm name rules. */

    /* Loader state. */
    void *_ldata;       /* Loader's pointer to the shm object's memory. */
    int   _lfd_shm;     /* Loader's FD for the shm object. */
    int   _lfd_file;    /* Loader's FD for the file being loaded. */

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
    char    shm_path[MAX_PATH_LEN + 2];     /* Path to the shm object. */
    int     shm_fd;                         /* FD for shm object. */
    void   *data;                           /* Pointer to shm obj's memory. */
    size_t  size;                           /* Size of file in bytes. */

    /* Free/new list. */
    struct local_location *next;    /* Next entry in the free/new list. */
    struct local_location *prev;    /* Previous entry in the free/new list. */

    /* Hash table. */
    UT_hash_handle hh;
} lloc_t;

/* File data location for a remote cache. */
typedef struct remote_location {
    uint32_t ip;    /* IP of file owner. */
    uint16_t port;  /* Port of file owner. */
    size_t   size;  /* Size of file in bytes. */

    /* Free list. */
    struct remote_location *next;   /* Next entry in the free list. */
    struct remote_location *prev;   /* Previous entry in the free list. */

    /* Hash table. */
    UT_hash_handle hh;
} rloc_t;

/* Local cache state. */
typedef struct {
    lloc_t ht;         /* Hash table. */
    size_t capacity;   /* Maximum capacity of cache in bytes. */
    size_t used;       /* Current usage of cache in bytes. */
} lcache_t;

/* Remote cache state. */
typedef struct {
    rloc_t ht;  /* Hash table. */
} rcache_t;

/* Complete/total cache state. */
typedef struct cache {
    char        name[MAX_NAME_LEN + 1];         /* Name of this cache. */
    char        shm_name[MAX_NAME_LEN + 2];     /* Prefix for shm objects. */
    lcache_t    lcache;                         /* Local cache. */
    rcache_t    rcache;                         /* Remote cache. */
    int         n_users;                        /* Number of users. */

    /* Shared memory with users. */
    int         qdepth;                         /* Queue depth. */
    request_t  *requests;                       /* Array of (N_USERS+1)*QDEPTH
                                                   request structs. The extra
                                                   is for remote requests. */

    /* Status queues. */
    request_t **free;       /* Unused request structs. */
    request_t **ready;      /* Requests prepared by users or network monitor. */
    request_t **done;       /* Requests that have been served. */
} cache_t;

#endif