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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <assert.h>
#include <errno.h>
#include <time.h>

#include "../../csrc/ladcache/cache.h"
#include "../../csrc/utils/log.h"
#include "../../csrc/utils/fifo.h"

#define DEFAULT_MAX_UNSYNCED 2
#define DEFAULT_CAPACITY 64 * 1024 * 1024
#define DEFAULT_QDEPTH 64
#define DEFAULT_USERS 1

#define CHECK_ARG_MUTEX(mode)                                                  \
   do {                                                                        \
      if (mode) {                                                              \
         printf("error: testing modes are mutually exclusive\n");              \
         return EINVAL;                                                        \
      }                                                                        \
   } while (0)
#define NOT_REACHED()                                                          \
    do {                                                                       \
        assert(false);                                                         \
    } while (0)


/* Mutually exclusive testing modes. */
enum test_mode {
   MODE_NONE,
   MODE_INTERACTIVE,
   MODE_DIRECTORY,
   N_MODES
};

/* Just like getline(), but reads only from stdin and displays a prompt. Returns
   bytes read. */
int
get_input(char *buf)
{
   printf(" > ");
   size_t max_len = MAX_PATH_LEN;
   return getline(&buf, &max_len, stdin);
}

/* Interactive test mode. Allows user to specify files to be loaded. Returns 0
   on success, -errno on failure. */
int
test_interactive(cache_t *c)
{
   int status;
   char *input = malloc(MAX_PATH_LEN + 1);
   if (input == NULL) {
      return -ENOMEM;
   }

   /* Repeatedly get and load a filepath. */
   bool running = true;
   while (running) {
      ssize_t n = get_input(input);
      if (n == 1) {
         continue;
      }

      /* Remove the newline. */
      input[n - 1] = '\0';

      printf("loading %s...\n", input);
      struct timespec time_start;
      clock_gettime(CLOCK_REALTIME, &time_start);

      /* Submit the request. */
      if ((status = cache_get_submit(c->ustates, input)) < 0) {
         DEBUG_LOG("cache_get_submit failed; %s\n", strerror(-status));
         continue;
      }

      /* Retrieve the loaded file. */
      request_t *out;
      if ((status = cache_get_reap_wait(c->ustates, &out))) {
         DEBUG_LOG("cache_get_reap_wait failed; %s\n", strerror(-status));
         continue;
      }

      struct timespec time_end;
      clock_gettime(CLOCK_REALTIME, &time_end);
      printf("done (%lu ns)\n", (time_end.tv_nsec - time_start.tv_nsec));

      cache_release(c->ustates, out);
   }

   return 0;
}

/* Directory test mode. Loads all files in the directory at PATH. Returns 0 on
   sucess, -errno on failure. */
int
test_directory(cache_t *c, char *path)
{
   return -ENOSYS;
}

int
main(int argc, char **argv)
{
   int opt;
   enum test_mode mode = MODE_NONE;
   char *path;
   int status;

   /* Parse arguments. */
   while ((opt = getopt(argc, argv, ":id:c:")) != -1) {
      switch (opt) {
         case 'd': /* Directory mode. */
            CHECK_ARG_MUTEX(mode);
            printf("directory mode...\n");
            mode = MODE_DIRECTORY;
            path = optarg;
            break;
         case 'i': /* Interactive mode. */
            CHECK_ARG_MUTEX(mode);
            printf("interactive mode...\n");
            mode = MODE_INTERACTIVE;
            break;
         case '?':
            printf("Unknown option: %c\n", optopt);
            break;
      }
   }

   /* Create the cache. */
   cache_t *cache = cache_new();
   if ((status = cache_init(cache, DEFAULT_CAPACITY, DEFAULT_QDEPTH, DEFAULT_MAX_UNSYNCED, DEFAULT_USERS)) < 0) {
      DEBUG_LOG("cache_init failed; %s\n", strerror(-status));
      return -status;
   }

   /* Start the cache threads. */
   if ((status = cache_start(cache)) < 0) {
      DEBUG_LOG("cache_start failed; %s\n", strerror(-status));
      return -status;
   }

   /* Select test based on input. */
   switch (mode) {
      case MODE_INTERACTIVE:
         if ((status = test_interactive(cache)) < 0) {
            DEBUG_LOG("test_interactive failed; %s\n", strerror(-status));
            return -status;
         }
      case MODE_DIRECTORY:
         if ((status = test_directory(cache, path)) < 0) {
            DEBUG_LOG("test_directory failed; %s\n", strerror(-status));
            return -status;
         }
      default:
         printf("error: invalid test mode\n");
         return EINVAL;
   }

   NOT_REACHED();
   return 0;
}
