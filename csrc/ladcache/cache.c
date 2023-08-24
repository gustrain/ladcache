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
#include "monitor.h"


/* ----------- */
/*   NETWORK   */
/* ----------- */

/* Broadcast our existence to other caches. */
int
cache_register(cache_t *c)
{
    /* TODO. */
}

int
cache_spawn_monitor(cache_t *c)
{
    /* TODO. */
}

int
cache_get_remote(cache_t *c, rloc_t *location)
{
    /* TODO. */
}


/* ------------- */
/*   INTERFACE   */
/* ------------- */

int
cache_contains(cache_t *c, char *path)
{
    /* TODO. */
}

int
cache_store(cache_t *c, char *path, uint8_t *data)
{
    /* TODO. */
}

int
cache_load(cache_t *c, request_t *r)
{
    /* TODO. */
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
