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

} UserState;

/* Python cache_t wrapper. */
typedef struct {
   PyObject_HEAD

} Cache;

/* Python request_t wrapper. */
typedef struct {
   PyObject_HEAD

} Request;


/* ----------------------- */
/*   `UserState` METHODS   */
/* ----------------------- */

/* UserState deallocator. TODO. */
static void
UserState_dealloc(PyObject *self)
{

}

/* UserState allocator. TODO. */
static PyObject *
UserState_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
   return NULL;
}

/* UserState initializer. TODO. */
static int
UserState_init(PyObject *self, PyObject *args, PyObject *kwds)
{
   return -1;
}

/* UserState methods array. */
static PyMethodDef UserState_methods[] = {
   {NULL}
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
    .tp_dealloc = UserState_dealloc,
    .tp_new = UserState_new,
    .tp_init = UserState_init,
    .tp_methods = UserState_methods,
};


/* ------------------- */
/*   `Cache` METHODS   */
/* ------------------- */

/* Cache deallocator. TODO. */
static void
Cache_dealloc(PyObject *self)
{

}

/* Cache allocator. TODO. */
static PyObject *
Cache_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
   return NULL;
}

/* Cache initializer. TODO. */
static int
Cache_init(PyObject *self, PyObject *args, PyObject *kwds)
{
   return -1;
}

/* Cache methods array. */
static PyMethodDef Cache_methods[] = {
   {NULL}
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
    .tp_dealloc = Cache_dealloc,
    .tp_new = Cache_new,
    .tp_init = Cache_init,
    .tp_methods = Cache_methods,
};


/* --------------------  */
/*   `Request` METHODS   */
/* --------------------- */

/* deallocator. TODO. */
static void
Request_dealloc(PyObject *self)
{

}

/* allocator. TODO. */
static PyObject *
Request_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
   return NULL;
}

/* initializer. TODO. */
static int
Request_init(PyObject *self, PyObject *args, PyObject *kwds)
{
   return -1;
}

/* Request methods array. */
static PyMethodDef Request_methods[] = {
   {NULL}
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
    .tp_dealloc = Request_dealloc,
    .tp_new = Request_new,
    .tp_init = Request_init,
    .tp_methods = Request_methods,
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