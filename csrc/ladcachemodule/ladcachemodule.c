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

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "../ladcache/cache.h"
#include "../utils/alloc.h"
#include "../utils/log.h"

/* Input validation. */
#define ARG_CHECK(valid_condition, error_string, return_fail)                  \
   if (!(valid_condition)) {                                                   \
      PyErr_SetString(PyExc_Exception, error_string);                          \
      return return_fail;                                                      \
   }


/* --------- */
/*   TYPES   */
/* --------- */

/* Python ustate_t wrapper. */
typedef struct {
   PyObject_HEAD

   ustate_t *ustate;
} UserState;

/* Python cache_t wrapper. */
typedef struct {
   PyObject_HEAD

   cache_t *cache;
} Cache;

/* Python request_t wrapper. */
typedef struct {
   PyObject_HEAD

   request_t *request;
} Request;


/* ----------------------- */
/*   `UserState` METHODS   */
/* ----------------------- */

/* UserState initializer. TODO. */
static int
UserState_init(PyObject *self, PyObject *args, PyObject *kwds)
{
   return -1;
}

/* TODO. Submit a request for a file to be loaded. */
PyObject *
UserState_submit()
{
   return NULL;
}

/* TODO. Reap a request, returning None if none are available. */
PyObject *
UserState_reap()
{
   return NULL;
}

/* TODO. Reap a request, waiting until one becomes available. */
PyObject *
UserState_reap_wait()
{
   return NULL;
}

/* UserState methods array. */
static PyMethodDef UserState_methods[] = {
   {
   "submit",
   (PyCFunction) UserState_submit,
   METH_VARARGS | METH_KEYWORDS,
   "Submit a request for a file to be loaded."
   },
   {
      "reap",
      (PyCFunction) UserState_reap,
      METH_NOARGS,
      "Reap a request, returning None if none are available."
   },
   {
      "reap_wait",
      (PyCFunction) UserState_reap_wait,
      METH_NOARGS,
      "Reap a request, waiting until one becomes available."
   },
};

/* UserState type declaration. */
static PyTypeObject PythonUserStateType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "LADCache.UserState",
    .tp_doc = PyDoc_STR("LADCache user context"),
    .tp_basicsize = sizeof(UserState),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,

    /* Methods. */
    .tp_init = UserState_init,
    .tp_methods = UserState_methods,
};

/* --------------------  */
/*   `Request` METHODS   */
/* --------------------- */

/* Request initializer. TODO. */
static int
Request_init(PyObject *self, PyObject *args, PyObject *kwds)
{
   return -1;
}

/* TODO. Get the filepath this request loaded. */
PyObject *
Request_get_filepath()
{

}

/* TODO. Get the data loaded by this request. */
PyObject *
Request_get_data()
{
   return NULL;
}

/* TODO. Release this request. */
PyObject *
Request_release()
{
   return NULL;
}

/* Request methods array. */
static PyMethodDef Request_methods[] = {
   {
      "get_filepath",
      (PyCFunction) Request_get_filepath,
      METH_NOARGS,
      "Get the filepath this request loaded."
   },
   {
      "get_data",
      (PyCFunction) Request_get_data,
      METH_NOARGS,
      "Get the data loaded by this request."
   },
   {
      "release",
      (PyCFunction) Request_release,
      METH_NOARGS,
      "Release this request."
   }
};

/* Request type declaration. */
static PyTypeObject PythonRequestType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "LADCache.Request",
    .tp_doc = PyDoc_STR("File request"),
    .tp_basicsize = sizeof(Request),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,

    /* Methods. */
    .tp_init = Request_init,
    .tp_methods = Request_methods,
};


/* ------------------- */
/*   `Cache` METHODS   */
/* ------------------- */

/* Cache deallocator. */
static void
Cache_dealloc(PyObject *self)
{
   /* Destroy the cache and free the wrapper. */
   cache_destroy(((Cache *) self)->cache);
   Py_TYPE(self)->tp_free(self);
}

/* Cache initializer. */
static int
Cache_init(PyObject *self, PyObject *args, PyObject *kwds)
{
   Cache *c = (Cache *) self;
   size_t capacity;
   uint32_t queue_depth;
   uint32_t max_unsynced = 1, n_users = 1;

   /* Parse arguments. */
   char *kwlist[] = {"capacity", "queue_depth", "max_unsynced", "n_users"};
   if (!PyArg_ParseTupleAndKeywords(args, kwds, "kI|I|I", kwlist,
                                    &capacity,
                                    &queue_depth,
                                    &max_unsynced,
                                    &n_users)) {
      PyErr_SetString(PyExc_Exception, "missing/invalid argument");
      return -1;
   }

   /* Validate arguments. Note that 0 is a valid value for max_unsynced. */
   ARG_CHECK(capacity > 0, "capacity must be >= 1 byte", -1);
   ARG_CHECK(queue_depth > 0, "queue_depth must be >= 1", -1);
   ARG_CHECK(n_users > 0, "n_users must be >= 1", -1);

   /* Allocate the cache_t struct. */
   if ((c->cache = cache_new()) == NULL) {
      PyErr_Format(PyExc_Exception, "Failed to allocate cache_t struct.\n");
      return -1;
   }

   /* Initialize the cache. */
   int status = cache_init(c->cache,
                           capacity,
                           queue_depth,
                           max_unsynced,
                           n_users);
   if (status < 0) {
      PyErr_Format(PyExc_Exception,
                   "Failed to initialize cache; %s\n",
                   strerror(-status));
      return -1;
   }

   return 0;
}

/* Get the wrapped ustate_t for the given user index. */
PyObject *
Cache_get_user_state(PyObject *self, PyObject *args, PyObject *kwds)
{
   Cache *c = (Cache *) self;
   uint32_t index;

   /* Parse the arguments. */
   char *kwlist[] = {"index"};
   if (!PyArg_ParseTupleAndKeywords(args, kwds, "I", kwlist, &index)) {
      PyErr_SetString(PyExc_Exception, "missing/invalid argument");
      return -1;
   }

   /* Validate index is within range. */
   ARG_CHECK(index < c->cache->n_users, "invalid user index", -1);

   /* Allocate and fill the wrapper. */
   UserState *user_state = Py_TYPE(user_state)->tp_alloc(&PythonUserStateType, 0);
   if (user_state == NULL) {
      PyErr_SetString(PyExc_Exception, "unable to allocate wrapper");
      return NULL;
   }
   user_state->ustate = &c->cache->ustates[index];

   return (PyObject *) user_state;
}

/* Cache methods array. */
static PyMethodDef Cache_methods[] = {
   {
      "get_user_state",
      (PyCFunction) Cache_get_user_state,
      METH_VARARGS | METH_KEYWORDS,
      "Get the context for the specified user"
   }
};

/* Cache type declaration. */
static PyTypeObject PythonCacheType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "LADCache.Cache",
    .tp_doc = PyDoc_STR("LADCache cache"),
    .tp_basicsize = sizeof(Cache),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,

    /* Methods. */
    .tp_init = Cache_init,
    .tp_dealloc = Cache_dealloc,
    .tp_methods = Cache_methods,
};


/* --------------- */
/*   MODULE INIT   */
/* --------------- */

/* Module definition. */
static struct PyModuleDef LADCacheModule = {
   PyModuleDef_HEAD_INIT,
   .m_name = "LADCache",
   .m_doc = "Locality-aware distributed cache.",
   .m_size = -1,
   .m_methods = NULL,
};

/* Register a Python type with a module. */
#define REGISTER_TYPE(module, name, type_addr)                                 \
   Py_INCREF(type_addr);                                                       \
   if (PyModule_AddObject(module, name, (PyObject *) type_addr) < 0) {         \
      Py_DECREF(type_addr);                                                    \
      Py_DECREF(module);                                                       \
      return NULL;                                                             \
   }

PyMODINIT_FUNC
PyInit_AsyncLoader(void)
{
   /* Create module. */
   PyObject *module;
   if ((module = PyModule_Create(&LADCacheModule)) == NULL) {
      return NULL;
   }

   /* Ready all types. */
   if (PyType_Ready(&PythonUserStateType) < 0 ||
       PyType_Ready(&PythonCacheType)     < 0 ||
       PyType_Ready(&PythonRequestType)   < 0) {
      return NULL;
   }

   /* Register all types. */
   REGISTER_TYPE(module, "UserState", &PythonUserStateType);
   REGISTER_TYPE(module, "Cache", &PythonCacheType);
   REGISTER_TYPE(module, "Request", &PythonRequestType);

   return module;
}