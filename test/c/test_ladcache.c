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
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>

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

/* Interactive test mode. Allows user to specify files to be loaded. Returns 0
   on success, -errno on failure. */
int
test_interactive()
{

}

/* Directory test mode. Loads all files in the directory at PATH. Returns 0 on
   sucess, -errno on failure. */
int
test_directory(char *path)
{

}

int
main(int argc, char **argv)
{
   int opt;
   enum test_mode mode = MODE_NONE;
   char *path;

   /* Parse arguments. */
   while ((opt = getopt(argc, argv, ":d:i"))) {
      switch (opt) {
         case 'd': /* Directory mode. */
            CHECK_ARG_MUTEX(mode);
            printf("directory mode...");
            mode = MODE_DIRECTORY;
            path = optarg;
            break;
         case 'i': /* Interactive mode. */
            CHECK_ARG_MUTEX(mode);
            printf("interactive mode...");
            mode = MODE_INTERACTIVE;
            break;
         case '?':
            printf("Unknown option: %c\n", optopt);
            break;
      }
   }

   /* Select test based on input. */
   switch (mode) {
      case MODE_INTERACTIVE:
         return -test_interactive();
      case MODE_DIRECTORY:
         return -test_directory(path);
      default:
         printf("error: invalid test mode\n");
         return EINVAL;
   }

   NOT_REACHED();
   return 0;
}