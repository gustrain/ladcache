# LADCache - Locality Aware Distributed Cache
*Based on ideas from "Accelerating Data Loading in Deep Neural Network Training" (2019)*

## *Warning: this project is still a work-in-progress, and is not yet completely stable!*

![3-way demo](./assets/3-way-example.PNG)
*Demo of distributed cache with three nodes, using the interactive test mode.*

## Project Structure

### `<repo>/csrc` - project source

#### `ladcache/cache.c` & `ladcache/cache.h`
Core implementation of distributed cache. Implements the cache in various sections:
* *Misc* - Utility functions that don't merit an entire file in `/csrc/utility/`.
* *Network* - Generalized functions to interact with peers across the network.
* *Monitor* - Monitor thread functions, used to implement the `monitor_loop` thread, which handles all networked aspected of the cache.
* *Local cache interface* - High level interface to the local cache (`contains`/`load`/`store`).
* *Remote cache interface* - High level interface to the remote cache (`contains`/`load`/`store`).
* *Manager* - Manager thread functions, used to implement the `manager_loop` thread, which handles all interactions with the users, and accesses to the local cache and local IO.
* *Generic interface* - Interface exposed to library users. Interacts with manager and monitor processes through various queues.
* *Allocation* - Creation, initialization, and teardown functions for the `cache_t` type.

At a high level there are 2 process scopes:
1. User (interacts with LADCache through shared queues, etc.)
2. Backend (manages the cache).

The user scope is composed of various processes that will use the cache, each of which has a unique `ustate_t` struct which contains queues in shared memory. Each user has their own queues, and there is no sharing between users. The user configures requests and moves them from the free queue into the ready queue in order to tell the backend to handle the configured requests. The user then retrieves completed requests from the done queue, and once finished with them, replaces them back into the free queue.

The backend scope is composed of two persistent threads.
1. The **manager** is in charge interacting with the ready queue and issuing both network and storage IO requests. Each request requiring network IO spawns a new thread which connects to a peer's monitor to request file data. Storage IO requests are fulfilled by the manager using io_uring.
2. The **monitor** is in charge of handling incoming network traffic from peers. There are various types of traffic, however the two most important types are *file requests* and *file syncs*. File requests contain a filepath and it is the monitor's responsibility to fetch the file data from its cache and send it to the requestor. File syncs contain updated remote cache information, indicating which peers have cached which file data.

#### `utils/alloc.c` & `utils/alloc.h`
Utility functions for memory allocation.

#### `utils/fifo.h`
Utility macros for FIFO queues.

#### `utils/log.c` & `utils/log.h`
Logging macros.

#### `utils/uthash.h`
Hash table macro library ([source](https://troydhanson.github.io/uthash/)).

#### `/ladcachemodule/*` - CPython wrapper
*TODO*

### `<repo>/test` - project tests
*TODO*
