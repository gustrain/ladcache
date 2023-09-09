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
#include <signal.h>
#include <sys/socket.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>

#define N_HT_LOCKS (16)
#define PORT_DEFAULT (8080)
#define MAX_QUEUE_REQUESTS 64
#define SOCKET_TIMEOUT_S (5)
#define REGISTER_PERIOD_S (15)

#define MIN(a, b) ((a) > (b) ? (a) : (b))
#define NOT_REACHED()       \
    do {                    \
        assert(false);      \
    } while (0)
#define SPINLOCK_MUST_INIT(spinlock)    \
    assert(!pthread_spin_init(spinlock, PTHREAD_PROCESS_SHARED))

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

/* Open a socket to IP on the default port. Returns FD on success, -errno on
   failure. */
int
network_connect(in_addr_t ip)
{
    struct sockaddr_in peer_addr = {
        .sin_addr.s_addr = ip,
        .sin_family = AF_INET,
        .sin_port = PORT_DEFAULT
    };

    /* Open the socket. */
    int peer_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (peer_fd < 0) {
        /* ISSUE: leaking this request. */
        DEBUG_LOG("Failed to open socket; %s\n", strerror(errno));
        return -errno;
    }
    if (connect(peer_fd, (struct sockaddr *) &peer_addr, sizeof(peer_addr)) < 0) {
        /* ISSUE: leaking this request. */
        DEBUG_LOG("Failed to connect to peer; %s\n", strerror(errno));
        close(peer_fd);
        return -errno;
    }

    return peer_fd;
}

/* Allocates a message_t struct, points OUT to it, and reads a message from FD
   (socket) into it. OUT must only be freed by the user if the function returns
   successfully. Returns 0 on success, -errno on failure. */
int
network_get_message(int fd, message_t **out)
{
    ssize_t bytes;
    uint32_t len;

    /* Get the request header. */
    message_t *message = malloc(sizeof(message_t));
    if ((bytes = read(fd, (void *) message, sizeof(message_t))) != sizeof(message_t)) {
        DEBUG_LOG("Received a message that was too short (%ld bytes).\n", bytes);
        free(message);
        return -EBADMSG;
    }

    /* Sanity check. */
    if (message->header.magic != HEADER_MAGIC) {
        DEBUG_LOG("Received message with invalid header magic (0x%hx, should be 0x%hx).\n", message->header.magic, HEADER_MAGIC);
        free(message);
        return -EBADMSG;
    }
    if ((len = message->header.length) == 0) {
        return 0;
    }

    /* Allocate space for the rest of the message. */
    if (realloc(message, sizeof(message_t) + len) == NULL) {
        DEBUG_LOG("Unable to allocate an additional %u bytes for full message.\n", len);
        free(message);
        return -ENOMEM;
    }

    /* Read the rest of the message. */
    if ((bytes = read(fd, (void *) message->data, len)) != len) {
        DEBUG_LOG("Expected %u bytes but got %ld.\n", len, bytes);
        free(message);
        return -EBADMSG;
    }

    *out = message;
    return 0;
}

/* Constructs and sends a message to the socket on FD with SIZE bytes of DATA
   as the payload. Does NOT close FD once finished. Returns 0 on sucess and
   -errno on failure. */
int
network_send_message(mtype_t type, int flags, void *data, uint32_t size, int fd)
{
    /* Configure and send the header. */
    message_t header;
    memset(&header, 0, sizeof(message_t));

    /* Configure the header. */
    header.header.type = type;
    header.header.magic = HEADER_MAGIC;
    header.header.length = size;

    /* Send the header. */
    ssize_t bytes;
    if ((bytes = send(fd, (void *) &header, sizeof(message_t), 0)) != sizeof(message_t)) {
        if (bytes < 0) {
            DEBUG_LOG("Failed to send header; %s\n", strerror(errno));
            return -errno;
        } else {
            DEBUG_LOG("Failed to send entire header (%ld/%lu bytes sent).\n", bytes, sizeof(message_t));
            return -EAGAIN;
        }
    }
    
    /* Send the data. */
    if ((bytes = send(fd, data, size, 0)) != size) {
        if (bytes < 0) {
            DEBUG_LOG("Failed to send payload; %s\n", strerror(errno));
            return -errno;
        } else {
            DEBUG_LOG("Failed to send entire payload (%ld/%u bytes sent).\n", bytes, size);
            return -EAGAIN;
        }
    }

    return 0;
}


/* --------------------------- */
/*   MONITOR (manager scope)   */
/* --------------------------- */

/* Announce our existence to other members of the distributed cache. Returns 0
   on success and -errno on failure. */
int
cache_register(cache_t *c)
{
    /* Create broadcast socket. */
    int broadcast_fd = socket(AF_INET, SOCK_DGRAM, 0);
    int broadcast = 1;
    int status = setsockopt(broadcast_fd,
                            SOL_SOCKET,
                            SO_BROADCAST,
                            &broadcast,
                            sizeof(broadcast));
    if (status < 0) {
        DEBUG_LOG("failed to configure socket for broadcast; %s\n", strerror(errno));
        return -errno;
    }

    /* Registration "hello" message with reply required. */
    message_t header = {
        .header.magic = HEADER_MAGIC,
        .header.type = TYPE_HLLO,
        .header.crct = false,
        .header.unbl = false,
        .header.rply = true,
        .header.flg3 = false,
        .header.length = 0
    };

    /* Broadcast the message. */
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_BROADCAST),
        .sin_port = htons(PORT_DEFAULT)
    };
    ssize_t bytes = sendto(broadcast_fd,
                           (void *) &header,
                           sizeof(message_t),
                           FLAG_NONE,
                           (struct sockaddr *) &addr,
                           sizeof(addr));
    if (bytes != sizeof(message_t)) {
        if (bytes < 0) {
            DEBUG_LOG("failed to broadcast hello; %s\n", strerror(errno));
            return -errno;
        } else {
            DEBUG_LOG("failed to broadcast entire message (%ld/%lu bytes).\n", bytes, sizeof(message_t));
            return -EBADMSG;
        }
    }

    close(broadcast_fd);
    return 0;
}

/* Send a message to every known peer with our list of newly-cached files.
   Returns 0 on success, -errno on failure. Assumes that there is at least one
   unsynced filepath in the list. */
int
cache_sync(cache_t *c)
{
    /* No-op if the unsynced list is already empty. */
    lloc_t *loc = c->lcache.unsynced;
    if (loc == NULL) {
        return 0;
    }

    /* Determine the sum of all filepath lengths. */
    uint32_t n_entries = 0;
    size_t payload_len = 0;
    do {
        payload_len += strlen(loc->path) + 1; /* +1 for '\0' byte. */
        n_entries++;
    } while ((loc = loc->next) != NULL);

    /* Allocate our message payload. */
    char *payload = malloc(sizeof(uint32_t) + payload_len);
    if (payload == NULL) {
        DEBUG_LOG("Unable to allocate %lu bytes for sync payload.\n", payload_len);
        return -ENOMEM;
    }
    *((uint32_t *) payload) = n_entries;

    /* Write all of the filepaths and clear the unsynced list. */
    char *fp_dest = payload + sizeof(uint32_t);
    do {
        QUEUE_POP(c->lcache.unsynced, next, prev, loc);
        strncpy(fp_dest, loc->path, MAX_PATH_LEN + 1);
        fp_dest += strlen(loc->path + 1);
    } while (c->lcache.unsynced != NULL);


    /* Send the message to everyone we know. */
    pthread_spin_lock(&c->peer_lock);
    peer_t *peer, *tmp;
    HASH_ITER(hh, c->peers, peer, tmp) {
        /* Open the socket. */
        int peer_fd = network_connect(peer->ip);
        if (peer_fd < 0) {
            DEBUG_LOG("network_connect failed; %s\n", strerror(-peer_fd));
            free(payload);
            return peer_fd;
        }

        /* Send the message. */
        DEBUG_LOG("Sending SYNC to %s with %u files.\n", inet_ntoa((struct in_addr) {.s_addr = peer->ip}), n_entries);
        int status = network_send_message(TYPE_SYNC,
                                          FLAG_NONE,
                                          (void *) payload,
                                          payload_len,
                                          peer_fd);
        if (status < 0) {
            DEBUG_LOG("failed to send sync message; %s\n", strerror(-status));
            free(payload);
            return status;
        }
        close(peer_fd);
    };
    pthread_spin_unlock(&c->peer_lock);

    free(payload);
    return 0;
}

/* Handle a file request by sending the requested file data. Returns 0 on
   success, -errno on failure. */
int
monitor_handle_request(message_t *message, cache_t *c, int fd)
{
    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(addr);
    if (getpeername(fd, (struct sockaddr *) &addr, &addr_size) < 0) {
        DEBUG_LOG("getpeername failed; %s\n", strerror(-errno));
        return -errno;
    }

    /* TODO. Verify the filepath is the correct length (i.e., \0 terminated). */
    char *path = (char *) message->data;
    DEBUG_LOG("Received request from %s for %s.\n", inet_ntoa(addr.sin_addr), message->data);

    /* Try to retrieve the requested file from our cache. If uncached, reply
       that we are unable to fulfill their request. */
    lloc_t *loc;
    HASH_FIND_STR(c->lcache.ht, (char *) message->data, loc);
    if (loc == NULL) {
        DEBUG_LOG("File %s is not cached.\n", message->data);
        return network_send_message(TYPE_RSPN, FLAG_UNBL, NULL, 0, fd);
    }

    /* Otherwise, reply with our cached file data. */
    DEBUG_LOG("Sending %s %s (%u bytes).\n", inet_ntoa(addr.sin_addr), path, message->header.length);
    return network_send_message(TYPE_RSPN, FLAG_NONE, loc->data, loc->size, fd);
}

/* Handle a directory sync message. */
int
monitor_handle_sync(message_t *message, cache_t *c, int fd)
{
    /* TODO. Verify filepaths are valid ('\0' terminated, etc.) */

    /* Figure out who we're talking to. */
    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(addr);
    if (getpeername(fd, (struct sockaddr *) &addr, &addr_size) < 0) {
        return -errno;
    }
    in_addr_t ip = addr.sin_addr.s_addr;

    /* Add their filepaths to the remote cache directory. */
    uint32_t n_entries = *((uint32_t *) message->data);
    char *filepath = ((char *) message->data) + sizeof(uint32_t);
    for (uint32_t i = 0; i < n_entries; i++) {
        /* Check string is in valid memory range. */
        size_t fp_len = strlen(filepath);
        if ((void *) (filepath + fp_len + 1) >
            (void *) (message->data + message->header.length)) {
            return -ERANGE;
        }

        /* Prepare the hash table entry.
        
           NOTE: it would be more efficient to malloc a single chunk of memory
           for all entries, however this would be more difficult to track. */
        rloc_t *loc = malloc(sizeof(rloc_t) + fp_len + 1);
        if (loc == NULL) {
            return -ENOMEM;
        }
        loc->ip = ip;
        strncpy(loc->path, filepath, fp_len + 1);

        /* Add to the remote cache directory. */
        HASH_ADD_STR(c->rcache.ht, path, loc);

        /* Move to the next filepath. */
        filepath += strlen(filepath) + 1;
    }
    DEBUG_LOG("Received SYNC from %s with %u files.\n", inet_ntoa(addr.sin_addr), n_entries);

    return 0;
}

/* Arguments to monitor_handle_connection. */
struct monitor_handle_connection_args {
    cache_t *c;
    int peer_fd;
};

/* Handles a remote read request. */
void *
monitor_handle_connection(void *args)
{
    /* Get the arguments passed to us. */
    cache_t *c = ((struct monitor_handle_connection_args *) args)->c;
    int peer_fd = ((struct monitor_handle_connection_args *) args)->peer_fd;

    /* Read the initial message from the socket. */
    message_t *message;
    int status = network_get_message(peer_fd, &message);
    if (status < 0) {
        DEBUG_LOG("network_get_message failed; %s\n", strerror(-status));
        close(peer_fd);
        return NULL;
    }

    /* Dispatch for the proper handler for this message type. */
    switch (message->header.type) {
        case TYPE_RQST: monitor_handle_request(message, c, peer_fd); break;
        case TYPE_SYNC: monitor_handle_sync(message, c, peer_fd); break;
        default:
            DEBUG_LOG("Received an invalid first message; type = 0x%hx.\n", message->header.type);
    }

    free(message);
    close(peer_fd);
    return NULL;
}

/* Monitor main loop. Handles all incoming remote read requests. Should never
   return when running correctly. On failure returns negative errno value. */
void *
monitor_loop(void *args)
{
    cache_t *c = (cache_t *) args;

    /* Open the listening socket. */
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        return NULL;
    }

    /* Allow address to be re-used (needed?) */
    int opt = 1;
    if (setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        DEBUG_LOG("setsockopt failed; %s\n", strerror(errno));
        return NULL;
    }

    /* Bind to PORT_DEFAULT. */
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons(PORT_DEFAULT)
    };
    socklen_t addr_len = sizeof(addr);
    if (bind(lfd, (struct sockaddr *)&addr, addr_len) < 0) {
        DEBUG_LOG("bind failed; %s\n", strerror(errno));
        return NULL;
    }

    /* Start listening. */
    if (listen(lfd, MAX_QUEUE_REQUESTS)) {
        DEBUG_LOG("listen failed; %s\n", strerror(errno));
        return NULL;
    }

    /* Handle all incoming connections. */
    while (true) {
        int cfd = accept(lfd, (struct sockaddr *) &addr, (socklen_t *) &addr_len);
        if (cfd >= 0) {
            /* Prepare arguments. */
            struct monitor_handle_connection_args *conn_args = malloc(
                sizeof(struct monitor_handle_connection_args)
            );
            if (conn_args == NULL) {
                DEBUG_LOG("failed to allocate arguments for connection handler.\n");
                return NULL;
            }
            conn_args->c = c;
            conn_args->peer_fd = cfd;

            /* This thread will terminate gracefully on its own and we don't
               need to track it. */
            pthread_t _;
            pthread_create(&_, NULL, monitor_handle_connection, conn_args);
        }
    }

    NOT_REACHED();
    return 0;
}

/* Spawns a new thread running the monitor loop. Returns 0 on success, -errno on
   failure. */
int
monitor_spawn(cache_t *c)
{
    return -pthread_create(&c->monitor_thread, NULL, monitor_loop, c);
}


/* ----------------------------- */
/*   REGISTRAR (manager scope)   */
/* ----------------------------- */

/* Loop to listen for incoming UDP registration datagrams. */
void *
registrar_loop(void *args)
{
    cache_t *c = (cache_t *) args;
    int status;

    /* Create listening socket. */
    int sfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sfd < 0) {
        DEBUG_LOG("Failed to create registrar listening socket; %s\n", strerror(errno));
        return NULL;
    }

    /* Set socket timeout to SOCKET_TIMEOUT_MS milliseconds. */
    struct timeval tv = {
        .tv_sec = SOCKET_TIMEOUT_S,
        .tv_usec = 0,
    };
    if ((status = setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv))) < 0) {
        DEBUG_LOG("Failed to set registrar socket timeout; %s\n", strerror(errno));
        return NULL;
    }

    /* Accept all incoming connections. */
    socklen_t addr_len = sizeof(struct sockaddr_in);
    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons(PORT_DEFAULT)
    };
    if ((status = bind(sfd, (const struct sockaddr *) &server_addr, addr_len)) < 0) {
        DEBUG_LOG("bind failed; %s\n", strerror(errno));
        return NULL;
    }

    /* Continually await new datagrams, and respond in kind upon reception. */
    message_t header;
    struct sockaddr_in client_addr;
    time_t last_bc = 0, now;
    while (true) {
        /* Broadcast a registration message every REGISTRATION_PERIOD_MS
           milliseconds to ensure no peers are missed by drops, etc. */
        if ((now = time(NULL)) - last_bc >= REGISTER_PERIOD_S) {
            cache_register(c);
            last_bc = now;
        }

        /* Receive new datagram. */
        ssize_t bytes = recvfrom(sfd,
                                 (void *) &header,
                                 sizeof(message_t),
                                 FLAG_NONE,
                                 (struct sockaddr *) &client_addr,
                                 &addr_len);
        if (bytes != sizeof(message_t)) {
            if (bytes < 0) {
                /* Ignore timeout failures. They're necessary to ensure we can
                   continue to broadcast our existence periodically. */
                if (errno != EAGAIN) {
                    DEBUG_LOG("recvfrom failed; %s\n", strerror(errno));
                }
            } else {
                DEBUG_LOG("received incomplete header (%ld/%lu bytes).\n", bytes, sizeof(message_t));
            }
            continue;
        }

        /* Check validity of message. */
        if (header.header.magic != HEADER_MAGIC || header.header.type != TYPE_HLLO) {
            continue;
        }

        /* Add sender to our directory if it isn't already in it. */
        peer_t *peer = NULL;
        HASH_FIND_INT(c->peers, &client_addr.sin_addr.s_addr, peer);
        if (peer == NULL) {
            peer_t *peer = malloc(sizeof(peer_t));
            if (peer == NULL) {
                DEBUG_LOG("unable to allocate peer record.\n");
                return NULL;
            }
            peer->ip = client_addr.sin_addr.s_addr;
            HASH_ADD_INT(c->peers, ip, peer);
            DEBUG_LOG("added %s to set of peers\n", inet_ntoa(client_addr.sin_addr));
        }

        /* If reply is required, send a no-reply-required response by re-using
           the client address and their message. */
        if (header.header.rply) {
            header.header.rply = false;
            if ((bytes = sendto(sfd,
                                 (void *) &header,
                                 sizeof(message_t),
                                 FLAG_NONE,
                                 (struct sockaddr *) &client_addr,
                                 sizeof(client_addr)) != sizeof(message_t))) {
                if (bytes < 0) {
                    DEBUG_LOG("failed to send registration reply; %s\n", strerror(errno));
                } else {
                    DEBUG_LOG("failed to send entire registration reply (%ld/%lu bytes).\n", bytes, sizeof(message_t));
                }
            }
        }
    }
}

/* Spawn a thread running the registrar loop. */
int
registrar_spawn(cache_t *c)
{
    return -pthread_create(&c->registrar_thread, NULL, registrar_loop, c);
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

    /* Allocate shared memory. */
    loc->size = size;
    shmify(path, loc->shm_path, MAX_PATH_LEN + 1, MAX_SHM_PATH_LEN + 1);
    loc->shm_fd = shm_alloc(loc->shm_path, &loc->data, loc->size);
    if (loc->shm_fd < 0) {
        int status = loc->shm_fd;
        free(loc);
        return status;
    }

    /* Copy data in. */
    memcpy(loc->data, data, size);

    /* Insert into hash table. */
    strncpy(loc->path, path, MAX_PATH_LEN + 1);
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
        DEBUG_LOG("attempted to load uncached file; %s\n", request->path);
        return -ENODATA;
    }

    /* Fill the request. */
    request->_ldata = loc->data;
    request->_lfd_shm = loc->shm_fd;

    return 0;
}


/* ------------------------------------------ */
/*   REMOTE CACHE INTERFACE (manager scope)   */
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
struct cache_remote_load_args {
    rcache_t *rc;
    ustate_t *user;
    request_t *request;
};

/* Thread target to request a file from a peer. Should be passed a malloc'd
   cache_remote_load_args struct, which will be freed once arguments haev been
   parsed. Assumes that the caller has already removed REQUEST from USER's ready
   queue. The completed request will be placed into USER's done queue. */
void *
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
        /* ISSUE: leaking this request. */
        DEBUG_LOG("tried to load file that's not in the remote cache; %s\n", request->path);
        return NULL;
    }

    /* Connect to them. */
    int peer_fd = network_connect(loc->ip);
    if (peer_fd < 0) {
        DEBUG_LOG("network_connect failed; %s\n", strerror(-peer_fd));
        return NULL;
    }

    /* Send them a request for the file. */
    DEBUG_LOG("Requesting file %s from %s.\n", request->path, inet_ntoa((struct in_addr) {.s_addr = loc->ip}));
    int status = network_send_message(TYPE_RQST,
                                      FLAG_NONE,
                                      request->path,
                                      strlen(request->path) + 1,
                                      peer_fd);
    if (status < 0) {
        DEBUG_LOG("Failed to send message; %s\n", strerror(-status));
        close(peer_fd);
        return NULL;
    }

    /* Wait for a response. */
    message_t *response;
    status = network_get_message(peer_fd, &response);
    close(peer_fd); /* Socket use finished here. */
    if (status < 0) {
        /* ISSUE: leaking this request. */
        DEBUG_LOG("network_get_message failed; %s\n", strerror(-status));
        return NULL;
    }

    /* Make sure we got a sensible response. */
    if (response->header.type != TYPE_RSPN) {
        /* ISSUE: leaking this request. */
        DEBUG_LOG("Received an incorrect message type (type = 0x%hx)\n", response->header.type);
        free(response);
        return NULL;
    }

    /* Was the peer unable to fulfill the request? */
    if (response->header.unbl) {
        /* ISSUE: leaking this request. */
        DEBUG_LOG("%s unable to fulfill request for %s.\n", inet_ntoa((struct in_addr) {.s_addr = loc->ip}), request->path);
        free(response);
        return NULL;
    }

    /* Allocate an shm object for the file data. Note it would be more efficient
       to have read() read directly into the shm object, however this would
       complicate the get_message interface and so we'll just eat the copy cost
       for now. */
    request->size = response->header.length;
    shmify(request->path, request->shm_path, MAX_PATH_LEN + 1, MAX_SHM_PATH_LEN + 1);
    request->_lfd_shm = shm_alloc(request->shm_path, &request->_ldata, request->size);
    memcpy(request->_ldata, response->data, request->size);
    
    DEBUG_LOG("Received %s (%u bytes) from %s.\n", request->path, response->header.length, inet_ntoa((struct in_addr) {.s_addr = loc->ip}));
    free(response);
    return NULL;
}


/* --------------------------- */
/*   MANAGER (manager scope)   */
/* --------------------------- */

/* Submit an IO request to io_uring. Returns 0 on success, -errno on failure. */
int
manager_submit_io(ustate_t *ustate, request_t *r)
{
    DEBUG_LOG("Loading %s from the local cache.\n", r->path);

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
    r->_lfd_shm = shm_alloc(r->shm_path, &r->_ldata, r->size);
    if (r->_lfd_shm < 0) {
        close(r->_lfd_file);
        return r->_lfd_shm;
    }

    /* Tell io_uring to read the file into the buffer. */
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ustate->ring);
    io_uring_prep_read(sqe, r->_lfd_file, r->_ldata, r->size, 0);
    io_uring_sqe_set_data(sqe, r);

    return 0;
}

/* Check whether USTATE has any backend resources to be cleaned up. Returns 0 on
   success, -errno on failure. */
void
manager_check_cleanup(cache_t *c, ustate_t *ustate)
{
    /* Check if there's anything in the queue. */
    request_t *to_clean = NULL;
    QUEUE_POP_SAFE(ustate->cleanup, &ustate->cleanup_lock, next, prev, to_clean);
    if (to_clean == NULL) {
        return;
    }

    /* Check if it should be cleaned up. */
    if (!to_clean->_skip_clean) {
        munmap(to_clean->_ldata, to_clean->size);
        close(to_clean->_lfd_shm);
        close(to_clean->_lfd_file);
        shm_unlink(to_clean->shm_path);
    }

    /* Wipe it. */
    memset(to_clean, 0, sizeof(request_t));

    /* Move it to the free queue. */
    QUEUE_PUSH_SAFE(ustate->free, &ustate->free_lock, next, prev, to_clean);
}

/* Check whether USTATE has a pending request and execute it if it does. Returns
   0 on sucess, -errno on failure. */
int
manager_check_ready(cache_t *c, ustate_t *ustate)
{
    /* Check if there's a request waiting in the ready queue. */
    request_t *pending = NULL;
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
        assert(!pthread_create(&_, NULL, cache_remote_load, args));
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
void
manager_check_done(cache_t *c, ustate_t *ustate)
{
    /* Drain the io_uring completion queue into our completion queue. Using
       peek (instead of wait) to ensure the check is non-blocking. */
    struct io_uring_cqe *cqe;
    while (!io_uring_peek_cqe(&ustate->ring, &cqe)) {
        request_t *request = io_uring_cqe_get_data(cqe);
        DEBUG_LOG("io_uring finished %s\n", request->path);
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
            strncpy(loc->path, request->path, MAX_PATH_LEN + 1);
            strncpy(loc->shm_path, request->shm_path, MAX_SHM_PATH_LEN + 1);

            /* Add to the hash table indexed by PATH. */
            HASH_ADD_STR(c->lcache.ht, path, loc);
            c->lcache.used += loc->size;
            request->_skip_clean = true;

            /* Add to list of filenames to be synchronized. */
            QUEUE_PUSH(c->lcache.unsynced, next, prev, loc);
            c->lcache.n_unsynced++;
            DEBUG_LOG("pushed to unsynced; now n_unsynced = %lu\n", c->lcache.n_unsynced);
        }

       skip_cache:
        DEBUG_LOG("pushed %s to done\n", request->path);
        QUEUE_PUSH_SAFE(ustate->done, &ustate->done_lock, next, prev, request);
    }
}

/* Manager main loop. Handles all pending requests. */
void *
manager_loop(void *args)
{
    cache_t *c = (cache_t *) args;
    size_t prev_length;
    size_t idle_iters = 0;
    uint64_t i = 0;

    /* Loop round-robin through the user ustates and check for pending and
       completed requests that require status queue updates. */
    while (true) {
        ustate_t *ustate = &c->ustates[i++ % c->n_users];
        /* Check if we need to sync our newly cached files with peers. We do
           this when we've either reached the submission threshold, or when
           we've looped many times without caching anything new. A threshold of
           zero indicates no limit. */
        if ((c->lcache.n_unsynced >= c->lcache.threshold && c->lcache.threshold > 0) ||
            (idle_iters > (MAX_IDLE_ITERS) && c->lcache.n_unsynced > 0)) {
            DEBUG_LOG("Syncing %lu filepaths.\n", c->lcache.n_unsynced);
            idle_iters = 0;
            cache_sync(c);
        }

        prev_length = c->lcache.n_unsynced;
        manager_check_cleanup(c, ustate);
        manager_check_ready(c, ustate);
        manager_check_done(c, ustate);

        /* Reset the idle count if we've got new unsynced data. Otherwise,
           continue to increment it. */
        if (c->lcache.n_unsynced > prev_length) {
            idle_iters = 0;
        } else {
            idle_iters++;
            if (idle_iters % (8 * 1024 * 1024) == 0) {
                DEBUG_LOG("idle_iters = %lu, n_unsynced = %lu.\n", idle_iters, c->lcache.n_unsynced);
            }
        }
    }

    NOT_REACHED();
    return NULL;
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

/* Spawn the manager, the monitor, and the registrar. Returns 0 on success,
   -errno on failure. */
int
cache_start(cache_t *c)
{
    int status;
    if ((status = manager_spawn(c)) < 0) {
        return status;
    }
    if ((status = monitor_spawn(c)) < 0) {
        kill(c->manager_thread, SIGKILL);
        return status;
    }
    if ((status = registrar_spawn(c)) < 0) {
        kill(c->manager_thread, SIGKILL);
        kill(c->monitor_thread, SIGKILL);
        return status;
    }

    return 0;
}

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
    strncpy(request->path, path, MAX_PATH_LEN + 1);
    shmify(request->path, request->shm_path, MAX_PATH_LEN + 1, MAX_SHM_PATH_LEN + 1);

    /* Submit request to the monitor. */
    QUEUE_PUSH_SAFE(user->ready, &user->ready_lock, next, prev, request);
    
    return 0;
}

/* Reap a completed request for USER. Points OUT to a completed request. Returns
   0 on sucess, -errno on failure. */
int
cache_get_reap(ustate_t *user, request_t **out)
{
    /* Try to get a completed request. */
    request_t *r = *out;
    QUEUE_POP_SAFE(user->done, &user->done_lock, next, prev, r);
    if (r == NULL) {
        return -EAGAIN; /* Try again once request has been fulfilled. */
    }

    /* Open the shm object. */
    if ((r->ufd_shm = shm_open(r->shm_path, O_RDONLY, S_IRUSR)) < 0) {
        DEBUG_LOG("shm_open failed; %s\n", strerror(errno));
        return -errno;
    }

    /* Create the mmap. */
    if (mmap(r->udata, r->size, PROT_READ, FLAG_NONE, r->ufd_shm, 0) < 0) {
        DEBUG_LOG("mmap failed; %s\n", strerror(errno));
        return -errno;
    }

    return 0;
}

/* Spin on cache_get_reap until an entry becomes ready. Returns 0 on success,
   -errno on failure. */
int
cache_get_reap_wait(ustate_t *user, request_t **out)
{
    int status;
    DEBUG_LOG("reap_wait start\n");
    while ((status = cache_get_reap(user, out)) == -EAGAIN) sched_yield();
    DEBUG_LOG("reap_wait end\n");
    return status;
}

/* Release REQUEST, free user resources and move the request into the cleanup
   queue (for backend resources to be evaluated and reclaimed). */
void
cache_release(ustate_t *user, request_t *request)
{
    munmap(request->udata, request->size);
    close(request->ufd_shm);
    QUEUE_PUSH_SAFE(user->cleanup, &user->cleanup_lock, next, prev, request);
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
    /* TODO. Update to clean up rloc_t and lloc_t structs from hash tables, and
             free all of the peer_t records. */

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
cache_init(cache_t *c,
           size_t capacity,
           unsigned queue_depth,
           int max_unsynced,
           int n_users)
{
    /* Allocate user states. */
    if ((c->ustates = mmap_alloc(n_users * sizeof(ustate_t))) == NULL) {
        DEBUG_LOG("mmap_alloc failed\n");
        return -ENOMEM;
    }

    /* Initialize user states. */
    c->n_users = n_users;
    c->qdepth = queue_depth;
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
        ustate->cleanup = NULL;

        /* Initialize the io_uring queues. */
        int status = io_uring_queue_init(queue_depth, &ustate->ring, 0);
        if (status < 0) {
            DEBUG_LOG("io_uring_queue_init failed\n");
            cache_destroy(c);
            return status;
        }

        /* Initialize the locks. */
        SPINLOCK_MUST_INIT(&ustate->free_lock);
        SPINLOCK_MUST_INIT(&ustate->ready_lock);
        SPINLOCK_MUST_INIT(&ustate->done_lock);
        SPINLOCK_MUST_INIT(&ustate->cleanup_lock);
    }

    /* Set up the local cache. */
    c->lcache = (lcache_t) {
        .ht = NULL,
        .unsynced = NULL,
        .n_unsynced = 0,
        .threshold = max_unsynced,
        .capacity = capacity,
        .used = 0
    };

    /* Set up the remote cache. */
    c->rcache.ht = NULL;
    SPINLOCK_MUST_INIT(&c->rcache.ht_lock);

    /* Set up the total cache. */
    c->peers = NULL;
    SPINLOCK_MUST_INIT(&c->peer_lock);

    return 0;
}
