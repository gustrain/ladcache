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

/* General-purpose pop method.
      - head: head of queue struct.
      - next: name of "next" field.
      - prev: name of "prev" field.
      - out: queue struct pointer, pointed to popped elem.
 */
#define QUEUE_POP(head, next, prev, out)                                      \
      do {                                                                    \
            if (head == NULL) {                                               \
                  continue;                                                   \
            }                                                                 \
            out = head;                                                       \
            head = head->next;                                                \
            if (head != NULL) {                                               \
                  head->prev = NULL;                                          \
            }                                                                 \
      } while (0)

/* General-purpose pop method that acquires a spinlock while working.
      - head: head of queue struct.
      - lock: name of "lock" field.
      - next: name of "next" field.
      - prev: name of "prev" field.
      - out: queue struct pointer, pointed to popped elem.
 */
#define QUEUE_POP_SAFE(head, lock, next, prev, out)                           \
      do {                                                                    \
            pthread_spin_lock(lock);                                          \
            QUEUE_POP(head, next, prev, out);                                 \
            pthread_spin_unlock(lock);                                        \
      } while (0)

/* General-purpose push method.
      - head: head of queue struct.
      - next: name of "next" field.
      - prev: name of "prev" field.
      - elem: pointer to queue struct to insert.
 */
#define QUEUE_PUSH(head, next, prev, elem)                                    \
      do {                                                                    \
            if (head == NULL) {                                               \
                  head = elem;                                                \
                  elem->prev = NULL;                                          \
                  elem->next = NULL;                                          \
                  continue;                                                   \
            }                                                                 \
            head->prev = elem;                                                \
            elem->next = head->next;                                          \
            elem->prev = NULL;                                                \
            head = elem;                                                      \
      } while (0)

/* General-purpose push method that acquires a spinlock while working.
      - head: head of queue struct.
      - lock: name of "lock" field.
      - next: name of "next" field.
      - prev: name of "prev" field.
      - elem: pointer to queue struct to insert.

 */
#define QUEUE_PUSH_SAFE(head, lock, next, prev, elem)                         \
      do {                                                                    \
            pthread_spin_lock(lock);                                          \
            QUEUE_PUSH(head, next, prev, elem);                               \
            pthread_spin_unlock(lock);                                        \
      } while (0)