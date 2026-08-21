/*
 * Python bindings for libdtrace.
 *
 * This module exposes a thin object oriented wrapper around libdtrace so that
 * Python applications can compile, enable, and control tracing programs while
 * also consuming aggregation results as native Python objects.
 *
 * Oracle Linux DTrace is licensed under the Universal Permissive License v 1.0.
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <sys/param.h>
#include <sys/types.h>
#include <pthread.h>

#include <dtrace.h>
#include "dt_aggregate.h"

#ifndef UNUSED
#define UNUSED(x) ((void)(x))
#endif

/*
 * libdtrace handles are serialized by a per-session lock.  It protects a
 * handle across all libdtrace operations, including calls that release the
 * GIL while they may block.  The GIL is dropped only where the libdtrace call
 * and its callbacks do not access Python objects.
 *
 * Compilation additionally uses a process-wide lock because libdtrace's
 * compiler has global state shared by all sessions.
 */
typedef struct {
	PyObject_HEAD
	dtrace_hdl_t *dtp;
	FILE *fp;
	int pids;      /* pid()s _create()ed or grab()bed */
	int pids_live; /* _continue()d active processes */
	int status;    /* EXITed or STOPPED */
	int exit_status;
	int closed;
	pthread_mutex_t dt_lock; /* Serialize access to this libdtrace handle. */
} PyDTraceSession;

typedef struct {
	PyObject_HEAD
	PyDTraceSession *session;
	dtrace_prog_t *prog;
} PyDTraceProgram;

typedef struct {
	PyObject_HEAD
	PyDTraceSession *session;
	struct dtrace_proc *proc;
} PyDTraceProc;

static PyObject *PyExc_DTraceError = NULL;

/* ------------------------------------------------------------------------- */
/* Utility helpers                                                           */
/* ------------------------------------------------------------------------- */

static int
ensure_open(PyDTraceSession *self)
{
	if (self->closed || self->dtp == NULL) {
		PyErr_SetString(PyExc_DTraceError, "DTrace session is closed");
		return -1;
	}

	return 0;
}

/*
 * Do not hold the GIL while waiting for a libdtrace operation in another
 * thread.  In particular, work() drops the GIL while it waits for data but
 * retains this lock to keep its handle alive.
 */
static void
session_dtrace_lock(PyDTraceSession *self)
{
	Py_BEGIN_ALLOW_THREADS
	pthread_mutex_lock(&self->dt_lock);
	Py_END_ALLOW_THREADS
}

static void
session_dtrace_unlock(PyDTraceSession *self)
{
	pthread_mutex_unlock(&self->dt_lock);
}

static int
session_dtrace_lock_open(PyDTraceSession *self)
{
	session_dtrace_lock(self);
	if (self->closed || self->dtp == NULL) {
		session_dtrace_unlock(self);
		PyErr_SetString(PyExc_DTraceError, "DTrace session is closed");
		return -1;
	}
	return 0;
}

static PyObject *
raise_dtrace_error_with_code(dtrace_hdl_t *dtp, int error, const char *ctx)
{
	const char *msg =
		dtp != NULL ? dtrace_errmsg(dtp, error) : "unknown error";

	if (ctx != NULL)
		PyErr_Format(PyExc_DTraceError, "%s: %s", ctx, msg);
	else
		PyErr_SetString(PyExc_DTraceError, msg);

	return NULL;
}

static PyObject *
raise_dtrace_error(PyDTraceSession *self, const char *ctx)
{
	int error = dtrace_errno(self->dtp);
	return raise_dtrace_error_with_code(self->dtp, error, ctx);
}

static int
dict_set_ulong(PyObject *dict, const char *key, unsigned long value)
{
	PyObject *obj = PyLong_FromUnsignedLong(value);
	int rc;

	if (obj == NULL)
		return -1;

	rc = PyDict_SetItemString(dict, key, obj);
	Py_DECREF(obj);
	return rc;
}

/* ------------------------------------------------------------------------- */
/* Aggregation walk context                                                  */
/* ------------------------------------------------------------------------- */

typedef struct {
	PyObject *list;
	PyDTraceSession *session;
} agg_walk_ctx_t;

typedef struct {
	PyObject *probes;
	PyObject *current_probe;
	PyObject *records;
	PyDTraceSession *session;
	int capture;
	int aborted;
} work_ctx_t;

static inline uint64_t
read_uint(const void *addr, size_t size)
{
	uint8_t v8;
	uint16_t v16;
	uint32_t v32;
	uint64_t v64;

	switch (size) {
	case 1:
		memcpy(&v8, addr, sizeof(v8));
		return v8;
	case 2:
		memcpy(&v16, addr, sizeof(v16));
		return v16;
	case 4:
		memcpy(&v32, addr, sizeof(v32));
		return v32;
	case 8:
		memcpy(&v64, addr, sizeof(v64));
		return v64;
	default:
		return 0;
	}
}

static const char *
agg_action_label(uint16_t action)
{
	switch (action) {
	case DT_AGG_AVG:
		return "avg";
	case DT_AGG_COUNT:
		return "count";
	case DT_AGG_LLQUANTIZE:
		return "llquantize";
	case DT_AGG_LQUANTIZE:
		return "lquantize";
	case DT_AGG_MAX:
		return "max";
	case DT_AGG_MIN:
		return "min";
	case DT_AGG_QUANTIZE:
		return "quantize";
	case DT_AGG_STDDEV:
		return "stddev";
	case DT_AGG_SUM:
		return "sum";
	default:
		return "unknown";
	}
}

static inline PyObject *
quant_dict_add(PyObject *dict, int64_t bucket, uint64_t count)
{
	PyObject *key = PyLong_FromLongLong(bucket);
	PyObject *val;

	if (key == NULL)
		return NULL;

	val = PyLong_FromUnsignedLongLong(count);
	if (val == NULL) {
		Py_DECREF(key);
		return NULL;
	}

	if (PyDict_SetItem(dict, key, val) < 0) {
		Py_DECREF(key);
		Py_DECREF(val);
		return NULL;
	}

	Py_DECREF(key);
	Py_DECREF(val);
	return dict;
}

static PyObject *
convert_aggregate_value(PyDTraceSession *session,
			const dtrace_aggdata_t *aggdata,
			const dtrace_recdesc_t *rec)
{
	dtrace_aggvalue_bucket_t *buckets;
	dtrace_aggvalue_t value = { 0 };
	PyObject *result = NULL;

	buckets = calloc(rec->dtrd_size / sizeof(int64_t) + 2,
			 sizeof(*buckets));
	if (buckets == NULL)
		return PyErr_NoMemory();
	value.dtagv_buckets = buckets;
	value.dtagv_bucket_capacity = rec->dtrd_size / sizeof(int64_t) + 2;
	if (dtrace_aggregate_value(aggdata, &value) < 0) {
		free(buckets);
		return raise_dtrace_error(session, "dtrace_aggregate_value");
	}
	if (value.dtagv_kind == DTRACE_AGGVALUE_QUANTIZED) {
		result = PyDict_New();
		for (size_t i = 0; result != NULL && i < value.dtagv_bucket_count; i++)
			if (quant_dict_add(result, value.dtagv_buckets[i].bucket,
					   value.dtagv_buckets[i].count) == NULL) {
				Py_DECREF(result);
				result = NULL;
			}
	} else if (value.dtagv_kind == DTRACE_AGGVALUE_FLOAT) {
		result = PyFloat_FromDouble(value.dtagv_value.real);
	} else if (value.dtagv_kind == DTRACE_AGGVALUE_INTEGER) {
		result = PyLong_FromLongLong(value.dtagv_value.integer);
	} else if (value.dtagv_kind == DTRACE_AGGVALUE_UNSIGNED) {
		result = PyLong_FromUnsignedLongLong(
			value.dtagv_value.unsigned_integer);
	} else {
		result = PyBytes_FromStringAndSize(value.dtagv_value.raw.data,
						   value.dtagv_value.raw.size);
	}
	free(buckets);
	return result;
}

static PyObject *
quantization_metadata(const dtrace_aggdesc_t *agg, uint16_t action)
{
	uint64_t sig = agg->dtagd_sig;

	switch (action) {
	case DT_AGG_LQUANTIZE:
		return Py_BuildValue("{s:s,s:i,s:I,s:I}",
		    "action", "lquantize",
		    "base", DTRACE_LQUANTIZE_BASE(sig),
		    "step", (unsigned int)DTRACE_LQUANTIZE_STEP(sig),
		    "levels", (unsigned int)DTRACE_LQUANTIZE_LEVELS(sig));
	case DT_AGG_LLQUANTIZE:
		return Py_BuildValue("{s:s,s:I,s:I,s:I,s:I}",
		    "action", "llquantize",
		    "factor", (unsigned int)DTRACE_LLQUANTIZE_FACTOR(sig),
		    "lmag", (unsigned int)DTRACE_LLQUANTIZE_LMAG(sig),
		    "hmag", (unsigned int)DTRACE_LLQUANTIZE_HMAG(sig),
		    "steps", (unsigned int)DTRACE_LLQUANTIZE_STEPS(sig));
	default:
		return NULL;
	}
}

static inline int
key_requires_format(dtrace_actkind_t action)
{
	switch (action) {
	case DTRACEACT_STACK:
	case DTRACEACT_USTACK:
	case DTRACEACT_JSTACK:
	case DTRACEACT_SYM:
	case DTRACEACT_USYM:
	case DTRACEACT_MOD:
	case DTRACEACT_UMOD:
	case DTRACEACT_UADDR:
		return 1;
	default:
		return 0;
	}
}

static PyObject *
convert_aggregate_key_descriptor(const dtrace_aggkey_t *key)
{
	if (key->dtagk_kind == DTRACE_AGGKEY_INTEGER)
		return PyLong_FromLongLong(key->dtagk_value.integer);
	if (key->dtagk_kind == DTRACE_AGGKEY_BYTES)
		return PyBytes_FromStringAndSize(key->dtagk_value.bytes.data,
				(Py_ssize_t)key->dtagk_value.bytes.size);
	if (key->dtagk_kind == DTRACE_AGGKEY_STRING ||
	    key->dtagk_kind == DTRACE_AGGKEY_SYMBOL ||
	    key->dtagk_kind == DTRACE_AGGKEY_MODULE)
		return PyUnicode_FromString(key->dtagk_value.name);
	if (key->dtagk_kind == DTRACE_AGGKEY_ADDRESS) {
		PyObject *address = PyLong_FromUnsignedLongLong(
			key->dtagk_value.user_address.address);
		PyObject *pid = PyLong_FromUnsignedLong(
			(unsigned long)key->dtagk_value.user_address.pid);
		PyObject *result;
		if (!address || !pid) {
			Py_XDECREF(address);
			Py_XDECREF(pid);
			return NULL;
		}
		result = PyTuple_Pack(2, pid, address);
		Py_DECREF(pid);
		Py_DECREF(address);
		return result;
	}
	if (key->dtagk_kind == DTRACE_AGGKEY_STACK) {
		PyObject *list = PyList_New((Py_ssize_t)key->dtagk_value.stack.depth);
		if (!list)
			return NULL;
		for (size_t i = 0; i < key->dtagk_value.stack.depth; i++) {
			PyObject *frame = PyUnicode_FromString(
				key->dtagk_value.stack.frames[i]);
			if (!frame) {
				Py_DECREF(list);
				return NULL;
			}
			PyList_SET_ITEM(list, (Py_ssize_t)i, frame);
		}
		return list;
	}
	PyErr_SetString(PyExc_ValueError, "unknown aggregation key kind");
	return NULL;
}

static PyObject *
convert_aggdata(PyDTraceSession *session, agg_walk_ctx_t *ctx,
		const dtrace_aggdata_t *aggdata)
{
	const dtrace_aggdesc_t *agg = aggdata->dtada_desc;
	const dtrace_recdesc_t *counter_rec =
		&agg->dtagd_drecs[DT_AGGDATA_COUNTER];
	const dtrace_recdesc_t *value_rec =
		&agg->dtagd_drecs[DT_AGGDATA_RECORD];
	PyObject *entry = PyDict_New();

	if (entry == NULL)
		return NULL;

	PyObject *name = agg->dtagd_name != NULL
				 ? PyUnicode_FromString(agg->dtagd_name)
				 : Py_None;
	if (name == NULL)
		goto error;
	if (name == Py_None)
		Py_INCREF(Py_None);
	if (PyDict_SetItemString(entry, "name", name) < 0) {
		Py_DECREF(name);
		goto error;
	}
	Py_DECREF(name);

	PyObject *aggid = PyLong_FromLong(agg->dtagd_varid);
	if (aggid == NULL)
		goto error;
	if (PyDict_SetItemString(entry, "id", aggid) < 0) {
		Py_DECREF(aggid);
		goto error;
	}
	Py_DECREF(aggid);

	PyObject *action =
		PyUnicode_FromString(agg_action_label(value_rec->dtrd_action));
	if (action == NULL)
		goto error;
	if (PyDict_SetItemString(entry, "action", action) < 0) {
		Py_DECREF(action);
		goto error;
	}
	Py_DECREF(action);

	PyObject *keys = PyList_New(0);
	if (keys == NULL)
		goto error;
	/* Keep a uniform list representation: [] for zero keys, one element
	 * for scalar keys, and a nested list for stack keys. */

	uint_t nkeys = agg->dtagd_nkrecs ? agg->dtagd_nkrecs - 1 : 0;
	dtrace_aggkey_t *keydesc = nkeys ? calloc(nkeys, sizeof(*keydesc)) : NULL;
	if (nkeys && !keydesc)
		goto error;
	if (dtrace_aggregate_keys(aggdata, keydesc, nkeys) < 0) {
		free(keydesc);
		Py_DECREF(keys);
		goto error;
	}
	for (uint_t i = 0; i < nkeys; i++) {
		PyObject *item = convert_aggregate_key_descriptor(&keydesc[i]);
		PyObject *key_list;

		if (item == NULL) {
			for (uint_t j = 0; j < nkeys; j++)
				dtrace_aggregate_key_free(&keydesc[j]);
			free(keydesc);
			Py_DECREF(keys);
			goto error;
		}
		/* Every key is represented as a list.  Stack keys therefore become
		 * a nested list of frame strings. */
		key_list = PyList_New(1);
		if (key_list == NULL) {
			Py_DECREF(item);
			for (uint_t j = 0; j < nkeys; j++)
				dtrace_aggregate_key_free(&keydesc[j]);
			free(keydesc);
			Py_DECREF(keys);
			goto error;
		}
		PyList_SET_ITEM(key_list, 0, item);
		if (PyList_Append(keys, key_list) < 0) {
			Py_DECREF(key_list);
			for (uint_t j = 0; j < nkeys; j++)
				dtrace_aggregate_key_free(&keydesc[j]);
			free(keydesc);
			Py_DECREF(keys);
			goto error;
		}
		Py_DECREF(key_list);
	}
	for (uint_t i = 0; i < nkeys; i++)
		dtrace_aggregate_key_free(&keydesc[i]);
	free(keydesc);

	if (PyDict_SetItemString(entry, "keys", keys) < 0) {
		Py_DECREF(keys);
		goto error;
	}
	Py_DECREF(keys);

	uint64_t samples =
		read_uint(aggdata->dtada_data + counter_rec->dtrd_offset,
			  counter_rec->dtrd_size);
	PyObject *samples_obj = PyLong_FromUnsignedLongLong(samples);
	if (samples_obj == NULL)
		goto error;
	if (PyDict_SetItemString(entry, "samples", samples_obj) < 0) {
		Py_DECREF(samples_obj);
		goto error;
	}
	Py_DECREF(samples_obj);

	uint64_t normal = agg->dtagd_normal ? agg->dtagd_normal : 1;
	PyObject *normal_obj = PyLong_FromUnsignedLongLong(normal);
	if (normal_obj == NULL)
		goto error;
	if (PyDict_SetItemString(entry, "normal", normal_obj) < 0) {
		Py_DECREF(normal_obj);
		goto error;
	}
	Py_DECREF(normal_obj);

	PyObject *value = convert_aggregate_value(session, aggdata, value_rec);
	if (value == NULL)
		goto error;
	if (PyDict_SetItemString(entry, "value", value) < 0) {
		Py_DECREF(value);
		goto error;
	}
	Py_DECREF(value);

	PyObject *quantization = quantization_metadata(agg, value_rec->dtrd_action);
	if (quantization != NULL) {
		if (PyDict_SetItemString(entry, "quantization", quantization) < 0) {
			Py_DECREF(quantization);
			goto error;
		}
		Py_DECREF(quantization);
	}

	PyObject *raw = PyBytes_FromStringAndSize(
		(const char *)(aggdata->dtada_data + value_rec->dtrd_offset),
		(Py_ssize_t)value_rec->dtrd_size);
	if (raw == NULL)
		goto error;
	if (PyDict_SetItemString(entry, "raw", raw) < 0) {
		Py_DECREF(raw);
		goto error;
	}
	Py_DECREF(raw);

	return entry;

error:
	Py_DECREF(entry);
	return NULL;
}

static int
agg_walk_callback(const dtrace_aggdata_t *aggdata, void *arg)
{
	agg_walk_ctx_t *ctx = (agg_walk_ctx_t *)arg;
	PyObject *entry = convert_aggdata(ctx->session, ctx, aggdata);

	if (entry == NULL)
		return DTRACE_AGGWALK_ERROR;

	if (PyList_Append(ctx->list, entry) < 0) {
		Py_DECREF(entry);
		return DTRACE_AGGWALK_ERROR;
	}

	Py_DECREF(entry);
	return DTRACE_AGGWALK_NEXT;
}

/* ------------------------------------------------------------------------- */
/* PyDTraceProgram                                                           */
/* ------------------------------------------------------------------------- */

static void
PyDTraceProgram_dealloc(PyDTraceProgram *self)
{
	if (self->session)
		Py_XDECREF(self->session);
	PyObject_Del(self);
}

static PyTypeObject PyDTraceProgramType;

static PyObject *
PyDTraceProgram_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	UNUSED(args);
	UNUSED(kwds);
	PyDTraceProgram *self = (PyDTraceProgram *)type->tp_alloc(type, 0);
	if (self != NULL) {
		self->session = NULL;
		self->prog = NULL;
	}
	return (PyObject *)self;
}

static PyMethodDef PyDTraceProgram_methods[] = {{NULL, NULL, 0, NULL}};

static PyTypeObject PyDTraceProgramType = {
	PyVarObject_HEAD_INIT(NULL, 0).tp_name = "dtrace.DTraceProgram",
	.tp_basicsize = sizeof(PyDTraceProgram),
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_new = PyDTraceProgram_new,
	.tp_dealloc = (destructor)PyDTraceProgram_dealloc,
	.tp_methods = PyDTraceProgram_methods,
};

/* ------------------------------------------------------------------------- */
/* PyDTraceSession                                                           */
/* ------------------------------------------------------------------------- */

static void
PyDTraceSession_dealloc(PyDTraceSession *self)
{
	session_dtrace_lock(self);
	if (self->dtp != NULL && !self->closed) {
		Py_BEGIN_ALLOW_THREADS dtrace_close(self->dtp);
		Py_END_ALLOW_THREADS
	}
	self->dtp = NULL;
	session_dtrace_unlock(self);
	pthread_mutex_destroy(&self->dt_lock);
	if (self->fp)
		fclose(self->fp);
	self->closed = 1;
	PyObject_Del(self);
}

static PyObject *
PyDTraceSession_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	UNUSED(args);
	UNUSED(kwds);
	PyDTraceSession *self = (PyDTraceSession *)type->tp_alloc(type, 0);
	if (self != NULL) {
		self->dtp = NULL;
		self->closed = 1;
		if (pthread_mutex_init(&self->dt_lock, NULL) != 0) {
			PyObject_Del(self);
			PyErr_SetString(PyExc_RuntimeError,
					"unable to initialize DTrace session lock");
			return NULL;
		}
	}
	return (PyObject *)self;
}

static void
prochandler(pid_t pid, const char *msg, void *arg)
{
	PyDTraceSession *self = arg;

	if (pid < 0 && self->pids_live) {
		self->pids_live--;
		if (self->pids_live == 0)
			dtrace_stop(self->dtp);
	}
}

static int
PyDTraceSession_init(PyDTraceSession *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {"version", "flags", NULL};
	int version = DTRACE_VERSION;
	unsigned int flags = 0;
	int err = 0;
	int rc;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|iI", kwlist, &version,
					 &flags))
		return -1;

	Py_BEGIN_ALLOW_THREADS
	self->dtp = dtrace_open(version, flags, &err);
	Py_END_ALLOW_THREADS
	if (self->dtp == NULL)
		return raise_dtrace_error_with_code(NULL, err, "dtrace_open") ==
				       NULL
			       ? -1
			       : -1;

	if (dtrace_setopt(self->dtp, "aggsize", "4m") != 0 ||
	    dtrace_setopt(self->dtp, "bufsize", "4m") != 0) {
		dtrace_close(self->dtp);
		self->dtp = NULL;
		return -1;
	}
	dtrace_setoptenv(self->dtp, "DTRACE_OPT_");

	self->fp = fopen("/dev/null", "a");
	if (self->fp == NULL) {
		PyErr_SetFromErrno(PyExc_OSError);
		dtrace_close(self->dtp);
		self->dtp = NULL;
		return -1;
	}
	Py_BEGIN_ALLOW_THREADS
	rc = dtrace_init(self->dtp);
	Py_END_ALLOW_THREADS
	if (rc != 0) {
		raise_dtrace_error(self, "dtrace_init");
		dtrace_close(self->dtp);
		if (self->fp)
			fclose(self->fp);
		self->dtp = NULL;
		self->fp = NULL;
		return -1;
	}
	if (dtrace_handle_proc(self->dtp, &prochandler, self) != 0) {
		raise_dtrace_error(self, "dtrace_handle_proc");
		dtrace_close(self->dtp);
		if (self->fp)
			fclose(self->fp);
		self->dtp = NULL;
		self->fp = NULL;
		return -1;
	}
	self->closed = 0;
	return 0;
}

static PyObject *
PyDTraceSession_close(PyDTraceSession *self, PyObject *Py_UNUSED(args))
{
	session_dtrace_lock(self);
	if (!self->closed && self->dtp != NULL) {
		Py_BEGIN_ALLOW_THREADS dtrace_close(self->dtp);
		Py_END_ALLOW_THREADS
		if (self->fp)
			fclose(self->fp);
		self->dtp = NULL;
		self->fp = NULL;
		self->closed = 1;
	}
	session_dtrace_unlock(self);

	Py_RETURN_NONE;
}

static PyObject *
PyDTraceSession_enter(PyDTraceSession *self, PyObject *Py_UNUSED(args))
{
	if (ensure_open(self) < 0)
		return NULL;

	Py_INCREF(self);
	return (PyObject *)self;
}

static PyObject *
PyDTraceSession_exit(PyDTraceSession *self, PyObject *args)
{
	UNUSED(args);

	session_dtrace_lock(self);
	if (!self->closed && self->dtp != NULL) {
		Py_BEGIN_ALLOW_THREADS dtrace_close(self->dtp);
		Py_END_ALLOW_THREADS
		if (self->fp)
			fclose(self->fp);
		self->dtp = NULL;
		self->fp = NULL;
		self->closed = 1;
	}
	session_dtrace_unlock(self);

	Py_RETURN_FALSE;
}

static PyObject *
PyDTraceSession_setopt(PyDTraceSession *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {"option", "value", NULL};
	const char *opt = NULL;
	PyObject *value_obj = Py_None;
	PyObject *value_str = NULL;
	const char *cvalue = NULL;

	if (ensure_open(self) < 0)
		return NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|O", kwlist, &opt,
					 &value_obj))
		return NULL;

	if (value_obj == Py_None) {
		cvalue = NULL;
	} else {
		PyObject *string_obj = PyObject_Str(value_obj);
		if (string_obj == NULL)
			return NULL;
		value_str = PyUnicode_AsEncodedString(string_obj, "utf-8",
						      "replace");
		Py_DECREF(string_obj);
		if (value_str == NULL)
			return NULL;
		cvalue = PyBytes_AS_STRING(value_str);
	}

	if (session_dtrace_lock_open(self) < 0) {
		Py_XDECREF(value_str);
		return NULL;
	}
	if (dtrace_setopt(self->dtp, opt, cvalue) != 0) {
		session_dtrace_unlock(self);
		Py_XDECREF(value_str);
		return raise_dtrace_error(self, "dtrace_setopt");
	}
	session_dtrace_unlock(self);

	Py_XDECREF(value_str);
	Py_RETURN_NONE;
}

/*
 * Need a lock because compilation uses global state; we would like to remove
 * this eventually.
 */
pthread_mutex_t compile_lock = PTHREAD_MUTEX_INITIALIZER;

static PyObject *
PyDTraceSession_compile(PyDTraceSession *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {"program", "cflags", "argv", "spec",
					 "defines", NULL};
	const char *source = NULL;
	unsigned int cflags = 0;
	PyObject *argv_obj = NULL;
	PyObject *defines_obj = NULL;
	int spec = DTRACE_PROBESPEC_NAME;
	PyObject *argv_seq = NULL;
	char **argv = NULL;
	PyObject **encoded = NULL;
	Py_ssize_t argc = 0;
	dtrace_prog_t *prog = NULL;
	PyDTraceProgram *wrapper = NULL;

	if (ensure_open(self) < 0)
		return NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|IOiO", kwlist, &source,
					 &cflags, &argv_obj, &spec, &defines_obj))
		return NULL;
	if (session_dtrace_lock_open(self) < 0)
		return NULL;
	pthread_mutex_lock(&compile_lock);

	if (defines_obj != NULL && defines_obj != Py_None) {
		PyObject *defines_seq = PySequence_Fast(
			defines_obj, "defines must be a sequence of strings");
		Py_ssize_t i, n;

		if (defines_seq == NULL) {
			pthread_mutex_unlock(&compile_lock);
			session_dtrace_unlock(self);
			return NULL;
		}
		n = PySequence_Fast_GET_SIZE(defines_seq);
		for (i = 0; i < n; i++) {
			PyObject *item = PySequence_Fast_GET_ITEM(defines_seq, i);
			PyObject *string_obj = PyObject_Str(item);
			PyObject *encoded_obj;
			int rc;

			if (string_obj == NULL) {
				Py_DECREF(defines_seq);
				pthread_mutex_unlock(&compile_lock);
				session_dtrace_unlock(self);
				return NULL;
			}
			encoded_obj = PyUnicode_AsEncodedString(string_obj, "utf-8",
								       "replace");
			Py_DECREF(string_obj);
			if (encoded_obj == NULL) {
				Py_DECREF(defines_seq);
				pthread_mutex_unlock(&compile_lock);
				session_dtrace_unlock(self);
				return NULL;
			}
			rc = dtrace_setopt(self->dtp, "define",
					   PyBytes_AS_STRING(encoded_obj));
			Py_DECREF(encoded_obj);
			if (rc != 0) {
				Py_DECREF(defines_seq);
				pthread_mutex_unlock(&compile_lock);
				session_dtrace_unlock(self);
				return raise_dtrace_error(self, "dtrace_setopt");
			}
		}
		Py_DECREF(defines_seq);
		cflags |= DTRACE_C_CPP;
	}
	if ((cflags & DTRACE_C_CPP) && spec != DTRACE_PROBESPEC_NAME) {
		pthread_mutex_unlock(&compile_lock);
		session_dtrace_unlock(self);
		PyErr_SetString(PyExc_ValueError,
				"non-default spec is unsupported with preprocessing");
		return NULL;
	}

	if (argv_obj != NULL && argv_obj != Py_None) {
		argv_seq = PySequence_Fast(
			argv_obj, "argv must be a sequence of strings");
		if (argv_seq == NULL) {
			pthread_mutex_unlock(&compile_lock);
			session_dtrace_unlock(self);
			return NULL;
		}

		argc = PySequence_Fast_GET_SIZE(argv_seq);
		if (argc > 0) {
			Py_ssize_t i;

			argv = PyMem_Calloc((size_t)argc + 1, sizeof(char *));
			encoded =
				PyMem_Calloc((size_t)argc, sizeof(PyObject *));
			if (argv == NULL || encoded == NULL) {
				PyMem_Free(argv);
				PyMem_Free(encoded);
				Py_DECREF(argv_seq);
				pthread_mutex_unlock(&compile_lock);
				session_dtrace_unlock(self);
				return PyErr_NoMemory();
			}

			for (i = 0; i < argc; i++) {
				PyObject *item =
					PySequence_Fast_GET_ITEM(argv_seq, i);
				PyObject *string_obj = PyObject_Str(item);
				if (string_obj == NULL) {
					Py_DECREF(argv_seq);
					goto compile_error;
				}
				encoded[i] = PyUnicode_AsEncodedString(
					string_obj, "utf-8", "replace");
				Py_DECREF(string_obj);
				if (encoded[i] == NULL) {
					Py_DECREF(argv_seq);
					goto compile_error;
				}
				argv[i] = PyBytes_AS_STRING(encoded[i]);
			}
			argv[i] = NULL;
		}
	}

	if (cflags & DTRACE_C_CPP) {
		FILE *fp = tmpfile();

		if (fp == NULL) {
			PyErr_SetFromErrno(PyExc_OSError);
			goto compile_error;
		}
		if (fputs(source, fp) == EOF || fflush(fp) != 0 ||
		    fseek(fp, 0, SEEK_SET) != 0) {
			fclose(fp);
			PyErr_SetFromErrno(PyExc_IOError);
			goto compile_error;
		}
		prog = dtrace_program_fcompile(self->dtp, fp, cflags,
					       (int)argc, argv);
		fclose(fp);
	} else {
		prog = dtrace_program_strcompile(self->dtp, source,
					 (dtrace_probespec_t)spec, cflags,
					 (int)argc, argv);
	}
	pthread_mutex_unlock(&compile_lock);
	session_dtrace_unlock(self);

	Py_XDECREF(argv_seq);

	if (prog == NULL) {
		for (Py_ssize_t i = 0; i < argc; i++)
			Py_XDECREF(encoded[i]);
		PyMem_Free(encoded);
		PyMem_Free(argv);
		return raise_dtrace_error(self, "dtrace_program_strcompile");
	}

	wrapper = (PyDTraceProgram *)PyObject_CallObject(
		(PyObject *)&PyDTraceProgramType, NULL);
	if (wrapper == NULL) {
		for (Py_ssize_t i = 0; i < argc; i++)
			Py_XDECREF(encoded[i]);
		PyMem_Free(encoded);
		PyMem_Free(argv);
		return NULL;
	}

	Py_INCREF(self);
	wrapper->session = self;
	wrapper->prog = prog;

	for (Py_ssize_t i = 0; i < argc; i++)
		Py_XDECREF(encoded[i]);
	PyMem_Free(encoded);
	PyMem_Free(argv);

	return (PyObject *)wrapper;

compile_error:
	pthread_mutex_unlock(&compile_lock);
	session_dtrace_unlock(self);
	for (Py_ssize_t i = 0; i < argc; i++)
		Py_XDECREF(encoded[i]);
	PyMem_Free(encoded);
	PyMem_Free(argv);
	return NULL;
}

static PyObject *
PyDTraceSession_enable(PyDTraceSession *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {"program", NULL};
	PyDTraceProgram *program = NULL;
	dtrace_proginfo_t info;
	PyObject *result = NULL;
	PyObject *attr = NULL;
	int rc;

	if (ensure_open(self) < 0)
		return NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!", kwlist,
					 &PyDTraceProgramType, &program))
		return NULL;

	if (program->session != self) {
		PyErr_SetString(PyExc_ValueError,
				"program was created by a different session");
		return NULL;
	}

	memset(&info, 0, sizeof(info));

	if (session_dtrace_lock_open(self) < 0)
		return NULL;
	Py_BEGIN_ALLOW_THREADS
	rc = dtrace_program_exec(self->dtp, program->prog, &info);
	Py_END_ALLOW_THREADS
	if (rc != 0) {
		session_dtrace_unlock(self);
		return raise_dtrace_error(self, "dtrace_program_exec");
	}
	session_dtrace_unlock(self);

	result = PyDict_New();
	if (result == NULL)
		return NULL;

	if (dict_set_ulong(result, "aggregations", info.dpi_aggregates) < 0)
		goto enable_error;

	if (dict_set_ulong(result, "recgens", info.dpi_recgens) < 0)
		goto enable_error;

	if (dict_set_ulong(result, "matches", info.dpi_matches) < 0)
		goto enable_error;

	if (dict_set_ulong(result, "speculations", info.dpi_speculations) < 0)
		goto enable_error;

	attr = PyDict_New();
	if (attr == NULL)
		goto enable_error;

	if (dict_set_ulong(attr, "name", info.dpi_descattr.dtat_name) < 0)
		goto enable_error;

	if (dict_set_ulong(attr, "data", info.dpi_descattr.dtat_data) < 0)
		goto enable_error;

	if (dict_set_ulong(attr, "class", info.dpi_descattr.dtat_class) < 0)
		goto enable_error;

	if (PyDict_SetItemString(result, "descattr", attr) < 0)
		goto enable_error;
	Py_DECREF(attr);
	attr = NULL;

	attr = PyDict_New();
	if (attr == NULL)
		goto enable_error;

	if (dict_set_ulong(attr, "name", info.dpi_stmtattr.dtat_name) < 0)
		goto enable_error;

	if (dict_set_ulong(attr, "data", info.dpi_stmtattr.dtat_data) < 0)
		goto enable_error;

	if (dict_set_ulong(attr, "class", info.dpi_stmtattr.dtat_class) < 0)
		goto enable_error;

	if (PyDict_SetItemString(result, "stmtattr", attr) < 0)
		goto enable_error;
	Py_DECREF(attr);
	attr = NULL;

	return result;

enable_error:
	Py_XDECREF(attr);
	Py_DECREF(result);
	return NULL;
}

static PyObject *
PyDTraceSession_go(PyDTraceSession *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {"cflags", NULL};
	unsigned int cflags = 0;
	int rc;

	if (ensure_open(self) < 0)
		return NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|I", kwlist, &cflags))
		return NULL;

	if (session_dtrace_lock_open(self) < 0)
		return NULL;
	Py_BEGIN_ALLOW_THREADS rc = dtrace_go(self->dtp, cflags);
	Py_END_ALLOW_THREADS
	session_dtrace_unlock(self);

	if (rc != 0)
		return raise_dtrace_error(self, "dtrace_go");

	Py_RETURN_NONE;
}

static PyObject *
PyDTraceSession_stop(PyDTraceSession *self, PyObject *Py_UNUSED(args))
{
	if (ensure_open(self) < 0)
		return NULL;

	if (session_dtrace_lock_open(self) < 0)
		return NULL;
	if (dtrace_stop(self->dtp) != 0) {
		session_dtrace_unlock(self);
		return raise_dtrace_error(self, "dtrace_stop");
	}
	session_dtrace_unlock(self);

	Py_RETURN_NONE;
}

static PyObject *
PyDTraceSession_update(PyDTraceSession *self, PyObject *Py_UNUSED(args))
{
	int rc;

	if (ensure_open(self) < 0)
		return NULL;

	if (session_dtrace_lock_open(self) < 0)
		return NULL;
	Py_BEGIN_ALLOW_THREADS
	rc = dtrace_update(self->dtp);
	Py_END_ALLOW_THREADS
	if (rc != 0) {
		session_dtrace_unlock(self);
		return raise_dtrace_error(self, "dtrace_update");
	}
	session_dtrace_unlock(self);

	Py_RETURN_NONE;
}

static PyObject *
PyDTraceSession_status(PyDTraceSession *self, PyObject *Py_UNUSED(args))
{
	int status;

	if (ensure_open(self) < 0)
		return NULL;

	if (session_dtrace_lock_open(self) < 0)
		return NULL;
	status = dtrace_status(self->dtp);
	if (status == DTRACE_STATUS_ERROR) {
		session_dtrace_unlock(self);
		return raise_dtrace_error(self, "dtrace_status");
	}
	/*
	 * We maintain some local status too for forced exit (see consume_rec()
	 * below)
	 */
	if (status == DTRACE_STATUS_OKAY && self->status)
		status = self->status;
	session_dtrace_unlock(self);
	return PyLong_FromLong(status);
}

static int
consume_rec(const dtrace_probedata_t *data, const dtrace_recdesc_t *rec,
	    void *arg)
{
	work_ctx_t *ctx = arg;
	PyDTraceSession *self = ctx->session;
	dtrace_actkind_t act;
	uintptr_t addr;

	if (!rec)
		return DTRACE_CONSUME_NEXT;

	act = rec->dtrd_action;
	addr = (uintptr_t)data->dtpda_data;

	switch (act) {
	case DTRACEACT_EXIT:
		memcpy(&self->exit_status, (const void *)addr,
		       sizeof(self->exit_status));
		self->status = DTRACE_STATUS_EXITED;
		return DTRACE_CONSUME_NEXT;
	default:
		if (!ctx->capture || ctx->current_probe == NULL)
			return DTRACE_CONSUME_THIS;

		PyObject *record = PyDict_New();
		PyObject *records = ctx->records;

		if (record == NULL || records == NULL)
			goto error;

		PyObject *action = PyLong_FromUnsignedLong(act);
		PyObject *size = PyLong_FromUnsignedLong(rec->dtrd_size);
		PyObject *offset = PyLong_FromUnsignedLong(rec->dtrd_offset);
		PyObject *alignment =
			PyLong_FromUnsignedLong(rec->dtrd_alignment);
		PyObject *arg_obj = PyLong_FromUnsignedLongLong(rec->dtrd_arg);
		/* dtrace_work() has already advanced dtpda_data to this record. */
		PyObject *raw = PyBytes_FromStringAndSize(
			(const char *)data->dtpda_data,
			rec->dtrd_size);

		if (action == NULL || size == NULL || offset == NULL ||
		    alignment == NULL || arg_obj == NULL || raw == NULL)
			goto error_record;

		if (PyDict_SetItemString(record, "action", action) < 0)
			goto error_record;
		if (PyDict_SetItemString(record, "size", size) < 0)
			goto error_record;
		if (PyDict_SetItemString(record, "offset", offset) < 0)
			goto error_record;
		if (PyDict_SetItemString(record, "alignment", alignment) < 0)
			goto error_record;
		if (PyDict_SetItemString(record, "arg", arg_obj) < 0)
			goto error_record;
		if (PyDict_SetItemString(record, "data", raw) < 0)
			goto error_record;

		Py_DECREF(action);
		Py_DECREF(size);
		Py_DECREF(offset);
		Py_DECREF(alignment);
		Py_DECREF(arg_obj);
		Py_DECREF(raw);

		if (PyList_Append(records, record) < 0)
			goto error_record;
		Py_DECREF(record);

		return DTRACE_CONSUME_THIS;

	error_record:
		Py_XDECREF(action);
		Py_XDECREF(size);
		Py_XDECREF(offset);
		Py_XDECREF(alignment);
		Py_XDECREF(arg_obj);
		Py_XDECREF(raw);
		Py_XDECREF(record);

	error:
		ctx->aborted = 1;
		return DTRACE_CONSUME_ABORT;
	}
}

static int
consume_probe(const dtrace_probedata_t *data, void *arg)
{
	work_ctx_t *ctx = arg;

	if (!ctx->capture)
		return DTRACE_CONSUME_THIS;

	PyObject *probe = PyDict_New();
	PyObject *records = PyList_New(0);
	PyObject *stid =
		PyLong_FromUnsignedLong((unsigned long)data->dtpda_stid);
	PyObject *cpu = PyLong_FromUnsignedLong(data->dtpda_cpu);
	PyObject *flow = PyLong_FromLong(data->dtpda_flow);
	PyObject *indent = PyLong_FromLong(data->dtpda_indent);
	PyObject *prefix = NULL;

	if (probe == NULL || records == NULL || stid == NULL || cpu == NULL ||
	    flow == NULL || indent == NULL)
		goto error;

	if (PyDict_SetItemString(probe, "stid", stid) < 0)
		goto error;
	if (PyDict_SetItemString(probe, "cpu", cpu) < 0)
		goto error;
	if (PyDict_SetItemString(probe, "flow", flow) < 0)
		goto error;
	if (PyDict_SetItemString(probe, "indent", indent) < 0)
		goto error;
	if (PyDict_SetItemString(probe, "records", records) < 0)
		goto error;

	if (data->dtpda_prefix != NULL) {
		prefix = PyUnicode_FromString(data->dtpda_prefix);
		if (prefix == NULL)
			goto error;
		if (PyDict_SetItemString(probe, "prefix", prefix) < 0)
			goto error;
	}

	if (data->dtpda_ddesc != NULL) {
		PyObject *argc = PyLong_FromLong(data->dtpda_ddesc->dtdd_nrecs);
		PyObject *user_data = PyLong_FromUnsignedLongLong(
			data->dtpda_ddesc->dtdd_uarg);

		if (argc == NULL || user_data == NULL)
			goto error;
		if (PyDict_SetItemString(probe, "argc", argc) < 0) {
			Py_DECREF(argc);
			Py_DECREF(user_data);
			goto error;
		}
		Py_DECREF(argc);
		if (PyDict_SetItemString(probe, "user_data", user_data) < 0) {
			Py_DECREF(user_data);
			goto error;
		}
		Py_DECREF(user_data);
	}

	if (data->dtpda_pdesc != NULL) {
		const dtrace_probedesc_t *pdesc = data->dtpda_pdesc;
		PyObject *info = PyDict_New();
		PyObject *id = PyLong_FromUnsignedLong(pdesc->id);

		if (info == NULL || id == NULL)
			goto error;
		if (PyDict_SetItemString(info, "id", id) < 0) {
			Py_DECREF(id);
			Py_DECREF(info);
			goto error;
		}
		Py_DECREF(id);

		if (pdesc->prv != NULL) {
			PyObject *prv = PyUnicode_FromString(pdesc->prv);
			if (prv == NULL) {
				Py_DECREF(info);
				goto error;
			}
			if (PyDict_SetItemString(info, "provider", prv) < 0) {
				Py_DECREF(prv);
				Py_DECREF(info);
				goto error;
			}
			Py_DECREF(prv);
		}

		if (pdesc->mod != NULL) {
			PyObject *mod = PyUnicode_FromString(pdesc->mod);
			if (mod == NULL) {
				Py_DECREF(info);
				goto error;
			}
			if (PyDict_SetItemString(info, "module", mod) < 0) {
				Py_DECREF(mod);
				Py_DECREF(info);
				goto error;
			}
			Py_DECREF(mod);
		}

		if (pdesc->fun != NULL) {
			PyObject *fun = PyUnicode_FromString(pdesc->fun);
			if (fun == NULL) {
				Py_DECREF(info);
				goto error;
			}
			if (PyDict_SetItemString(info, "function", fun) < 0) {
				Py_DECREF(fun);
				Py_DECREF(info);
				goto error;
			}
			Py_DECREF(fun);
		}

		if (pdesc->prb != NULL) {
			PyObject *prb = PyUnicode_FromString(pdesc->prb);
			if (prb == NULL) {
				Py_DECREF(info);
				goto error;
			}
			if (PyDict_SetItemString(info, "name", prb) < 0) {
				Py_DECREF(prb);
				Py_DECREF(info);
				goto error;
			}
			Py_DECREF(prb);
		}

		if (PyDict_SetItemString(probe, "probe", info) < 0) {
			Py_DECREF(info);
			goto error;
		}
		Py_DECREF(info);
	}

	if (PyList_Append(ctx->probes, probe) < 0)
		goto error;

	ctx->current_probe = probe;
	ctx->records = records;

	Py_DECREF(stid);
	Py_DECREF(cpu);
	Py_DECREF(flow);
	Py_DECREF(indent);
	Py_DECREF(records);
	Py_XDECREF(prefix);
	Py_DECREF(probe);

	return DTRACE_CONSUME_THIS;

error:
	ctx->aborted = 1;
	Py_XDECREF(probe);
	Py_XDECREF(records);
	Py_XDECREF(stid);
	Py_XDECREF(cpu);
	Py_XDECREF(flow);
	Py_XDECREF(indent);
	Py_XDECREF(prefix);
	return DTRACE_CONSUME_ABORT;
}

static PyObject *
PyDTraceSession_work(PyDTraceSession *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {"return_records", NULL};
	PyObject *captures = Py_False;
	work_ctx_t ctx = {0};
	PyObject *status_obj = NULL;
	PyObject *result = NULL;
	int workstatus;
	int status;

	if (ensure_open(self) < 0)
		return NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|O", kwlist, &captures))
		return NULL;

	ctx.capture = PyObject_IsTrue(captures);
	if (ctx.capture < 0)
		return NULL;

	ctx.session = self;

	if (ctx.capture) {
		ctx.probes = PyList_New(0);
		if (ctx.probes == NULL)
			return NULL;
	}

	if (session_dtrace_lock_open(self) < 0) {
		Py_XDECREF(ctx.probes);
		return NULL;
	}
	if (ctx.capture) {
		workstatus = dtrace_work(self->dtp, self->fp, consume_probe,
					 consume_rec, &ctx);
	} else {
		/* The no-capture callbacks do not access Python objects. */
		Py_BEGIN_ALLOW_THREADS
		workstatus = dtrace_work(self->dtp, self->fp, consume_probe,
					 consume_rec, &ctx);
		Py_END_ALLOW_THREADS
	}

	/* An interrupted polling wait does not invalidate the DTrace session. */
	if (workstatus == DTRACE_WORKSTATUS_ERROR &&
	    dtrace_errno(self->dtp) == EINTR)
		workstatus = DTRACE_WORKSTATUS_OKAY;

	if (workstatus == DTRACE_WORKSTATUS_ERROR ||
	    (ctx.capture && ctx.aborted)) {
		result = raise_dtrace_error(self, "dtrace_work");
		session_dtrace_unlock(self);
		Py_XDECREF(ctx.probes);
		return result;
	}

	status = dtrace_status(self->dtp);
	if (status == DTRACE_STATUS_ERROR) {
		result = raise_dtrace_error(self, "dtrace_status");
		session_dtrace_unlock(self);
		Py_XDECREF(ctx.probes);
		return result;
	}
	if (status == DTRACE_STATUS_OKAY && self->status)
		status = self->status;
	if (status == DTRACE_STATUS_OKAY && self->pids > 0 &&
	    self->pids_live == 0) {
		status = DTRACE_STATUS_EXITED;
		self->status = status;
	}
	session_dtrace_unlock(self);

	status_obj = PyLong_FromLong(status);
	if (status_obj == NULL) {
		Py_XDECREF(ctx.probes);
		return NULL;
	}

	if (ctx.probes == NULL) {
		ctx.probes = PyList_New(0);
		if (ctx.probes == NULL) {
			Py_DECREF(status_obj);
			return NULL;
		}
	}

	result = PyTuple_Pack(2, status_obj, ctx.probes);
	Py_DECREF(status_obj);
	Py_DECREF(ctx.probes);
	return result;
}

static PyObject *
PyDTraceSession_agg_snap(PyDTraceSession *self, PyObject *Py_UNUSED(args))
{
	int rc;

	if (ensure_open(self) < 0)
		return NULL;

	if (session_dtrace_lock_open(self) < 0)
		return NULL;
	Py_BEGIN_ALLOW_THREADS
	rc = dtrace_aggregate_snap(self->dtp);
	Py_END_ALLOW_THREADS
	if (rc != 0) {
		session_dtrace_unlock(self);
		return raise_dtrace_error(self, "dtrace_aggregate_snap");
	}
	session_dtrace_unlock(self);

	Py_RETURN_NONE;
}

static PyObject *
PyDTraceSession_agg_clear(PyDTraceSession *self, PyObject *Py_UNUSED(args))
{
	if (ensure_open(self) < 0)
		return NULL;

	if (session_dtrace_lock_open(self) < 0)
		return NULL;
	dtrace_aggregate_clear(self->dtp);
	session_dtrace_unlock(self);
	Py_RETURN_NONE;
}

static dtrace_aggregate_walk_f *
resolve_agg_walk(const char *mode)
{
	if (mode == NULL || strcmp(mode, "default") == 0)
		return dtrace_aggregate_walk;
	if (strcmp(mode, "keys") == 0)
		return dtrace_aggregate_walk_keysorted;
	if (strcmp(mode, "values") == 0)
		return dtrace_aggregate_walk_valsorted;
	if (strcmp(mode, "keyrev") == 0)
		return dtrace_aggregate_walk_keyrevsorted;
	if (strcmp(mode, "valrev") == 0)
		return dtrace_aggregate_walk_valrevsorted;
	if (strcmp(mode, "keyvar") == 0)
		return dtrace_aggregate_walk_keyvarsorted;
	if (strcmp(mode, "valvar") == 0)
		return dtrace_aggregate_walk_valvarsorted;
	if (strcmp(mode, "keyvarrev") == 0)
		return dtrace_aggregate_walk_keyvarrevsorted;
	if (strcmp(mode, "valvarrev") == 0)
		return dtrace_aggregate_walk_valvarrevsorted;
	return NULL;
}

static PyObject *
PyDTraceSession_agg_walk(PyDTraceSession *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {"mode", NULL};
	const char *mode = "values";
	dtrace_aggregate_walk_f *walker = NULL;
	agg_walk_ctx_t ctx;
	int rc;

	if (ensure_open(self) < 0)
		return NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|s", kwlist, &mode))
		return NULL;

	walker = resolve_agg_walk(mode);
	if (walker == NULL) {
		PyErr_SetString(PyExc_ValueError,
				"unknown aggregation walk mode");
		return NULL;
	}

	ctx.list = PyList_New(0);
	if (ctx.list == NULL)
		return NULL;
	ctx.session = self;

	if (session_dtrace_lock_open(self) < 0) {
		Py_DECREF(ctx.list);
		return NULL;
	}
	rc = walker(self->dtp, agg_walk_callback, &ctx);
	if (rc != 0) {
		PyObject *error = raise_dtrace_error(self, "dtrace_aggregate_walk");

		session_dtrace_unlock(self);
		Py_DECREF(ctx.list);
		return error;
	}
	session_dtrace_unlock(self);

	return ctx.list;
}

/* ------------------------------------------------------------------------- */
/* PyDTraceProc                                                              */
/* ------------------------------------------------------------------------- */

static PyObject *
PyDTraceProc_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	UNUSED(args);
	UNUSED(kwds);
	PyDTraceProc *self = (PyDTraceProc *)type->tp_alloc(type, 0);
	if (self != NULL) {
		self->session = NULL;
		self->proc = NULL;
	}
	return (PyObject *)self;
}

static void
PyDTraceProc_dealloc(PyDTraceProc *self)
{
	if (self->session) {
		if (self->proc) {
			session_dtrace_lock(self->session);
			if (self->session->dtp != NULL)
				dtrace_proc_release(self->session->dtp, self->proc);
			session_dtrace_unlock(self->session);
		}

		Py_XDECREF(self->session);
	}
	PyObject_Del(self);
}

static PyObject *
PyDTraceProc_getpid(PyDTraceProc *self, PyObject *Py_UNUSED(args))
{
	int pid;

	if (self->session == NULL || self->session->closed ||
	    self->session->dtp == NULL || self->proc == NULL) {
		PyErr_SetString(PyExc_DTraceError,
				"DTrace process handle is released");
		return NULL;
	}

	if (session_dtrace_lock_open(self->session) < 0)
		return NULL;
	if (self->proc == NULL) {
		session_dtrace_unlock(self->session);
		PyErr_SetString(PyExc_DTraceError,
				"DTrace process handle is released");
		return NULL;
	}
	pid = dtrace_proc_getpid(self->session->dtp, self->proc);
	session_dtrace_unlock(self->session);

	return PyLong_FromLong(pid);
}

static PyMethodDef PyDTraceProc_methods[] = {
	{"getpid", (PyCFunction)PyDTraceProc_getpid, METH_NOARGS, "Get pid."},
	{NULL, NULL, 0, NULL}};

static PyTypeObject PyDTraceProcType = {
	PyVarObject_HEAD_INIT(NULL, 0).tp_name = "dtrace.DTraceProc",
	.tp_basicsize = sizeof(PyDTraceProc),
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_new = PyDTraceProc_new,
	.tp_dealloc = (destructor)PyDTraceProc_dealloc,
	.tp_methods = PyDTraceProc_methods,
};

#define PROC_CREATE_ARGC_MAX 32

static PyObject *
PyDTraceSession_proc_create(PyDTraceSession *self, PyObject *args,
			    PyObject *kwds)
{
	static char *kwlist[] = {"args", NULL};
	PyObject *arglist = NULL;
	PyObject *encoded[PROC_CREATE_ARGC_MAX] = {};
	char *argvlist[PROC_CREATE_ARGC_MAX + 1];
	struct dtrace_proc *proc = NULL;
	PyDTraceProc *retproc;
	PyObject *ret = NULL;
	Py_ssize_t i, size;

	if (ensure_open(self) < 0)
		return NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!", kwlist, &PyList_Type,
					 &arglist))
		return NULL;
	size = PyList_Size(arglist);
	if (size < 1) {
		PyErr_SetString(PyExc_ValueError,
				"empty arglist for proc_create");
		return NULL;
	}
	if (size >= PROC_CREATE_ARGC_MAX) {
		PyErr_SetString(PyExc_ValueError,
				"too many arguments for proc_create");
		return NULL;
	}
	for (i = 0; i < size; i++) {
		PyObject *item = PyList_GetItem(arglist, i);

		if (!PyUnicode_Check(item)) {
			PyErr_SetString(PyExc_ValueError,
					"non-string in argument list");
			goto error;
		}
		encoded[i] = PyUnicode_AsUTF8String(item);
		if (encoded[i] == NULL)
			goto error;
		argvlist[i] = PyBytes_AS_STRING(encoded[i]);
	}
	argvlist[i] = NULL;
	if (session_dtrace_lock_open(self) < 0)
		goto error;
	proc = dtrace_proc_create(self->dtp, argvlist[0], argvlist, 0);
	if (proc == NULL) {
		ret = raise_dtrace_error(self, "dtrace_proc_create");
		session_dtrace_unlock(self);
		goto error;
	}

	ret = PyDTraceProcType.tp_alloc(&PyDTraceProcType, 0);
	if (ret == NULL) {
		dtrace_proc_release(self->dtp, proc);
		session_dtrace_unlock(self);
		goto error;
	}
	self->pids++;
	session_dtrace_unlock(self);
	retproc = (PyDTraceProc *)ret;
	retproc->session = self;
	Py_INCREF(self);
	retproc->proc = proc;
	for (i = 0; i < size; i++)
		Py_DECREF(encoded[i]);

	return ret;

error:
	while (i-- > 0)
		Py_XDECREF(encoded[i]);
	return ret;
}

static PyObject *
PyDTraceSession_proc_grab_pid(PyDTraceSession *self, PyObject *args,
			      PyObject *kwds)
{
	static char *kwlist[] = {"pid", NULL};
	struct dtrace_proc *proc = NULL;
	PyDTraceProc *retproc;
	PyObject *ret;
	int pid;

	if (ensure_open(self) < 0)
		return NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "i", kwlist, &pid))
		return NULL;

	if (session_dtrace_lock_open(self) < 0)
		return NULL;
	proc = dtrace_proc_grab_pid(self->dtp, pid, 0);
	if (!proc) {
		ret = raise_dtrace_error(self, "dtrace_proc_grab_pid");
		session_dtrace_unlock(self);
		return ret;
	}
	ret = PyDTraceProcType.tp_alloc(&PyDTraceProcType, 0);
	if (ret == NULL) {
		dtrace_proc_release(self->dtp, proc);
		session_dtrace_unlock(self);
		return ret;
	}
	self->pids++;
	session_dtrace_unlock(self);
	retproc = (PyDTraceProc *)ret;
	retproc->session = self;
	Py_INCREF(self);
	retproc->proc = proc;

	return ret;
}

static PyObject *
PyDTraceSession_proc_continue(PyDTraceSession *self, PyObject *args,
			      PyObject *kwds)
{
	static char *kwlist[] = {"proc", NULL};
	PyDTraceProc *proc = NULL;

	if (ensure_open(self) < 0)
		return NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!", kwlist,
					 &PyDTraceProcType, &proc))
		return NULL;
	if (proc->session != self) {
		PyErr_SetString(PyExc_ValueError,
				"proc was created by a different session");
		return NULL;
	}

	if (proc->proc == NULL) {
		PyErr_SetString(PyExc_DTraceError,
				"DTrace process handle is released");
		return NULL;
	}

	if (session_dtrace_lock_open(self) < 0)
		return NULL;
	if (proc->proc == NULL) {
		session_dtrace_unlock(self);
		PyErr_SetString(PyExc_DTraceError,
				"DTrace process handle is released");
		return NULL;
	}
	dtrace_proc_continue(self->dtp, proc->proc);
	self->pids_live++;
	session_dtrace_unlock(self);

	Py_RETURN_NONE;
}

static PyObject *
PyDTraceSession_proc_release(PyDTraceSession *self, PyObject *args,
			     PyObject *kwds)
{
	static char *kwlist[] = {"proc", NULL};
	PyDTraceProc *proc;

	if (ensure_open(self) < 0)
		return NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!", kwlist,
					 &PyDTraceProcType, &proc))
		return NULL;

	if (proc->session != self) {
		PyErr_SetString(PyExc_ValueError,
				"proc was created by a different session");
		return NULL;
	}

	if (proc->proc == NULL) {
		PyErr_SetString(PyExc_DTraceError,
				"DTrace process handle is already released");
		return NULL;
	}

	if (session_dtrace_lock_open(self) < 0)
		return NULL;
	if (proc->proc == NULL) {
		session_dtrace_unlock(self);
		PyErr_SetString(PyExc_DTraceError,
				"DTrace process handle is already released");
		return NULL;
	}
	dtrace_proc_release(self->dtp, proc->proc);
	session_dtrace_unlock(self);
	proc->proc = NULL;

	Py_RETURN_NONE;
}

static PyMethodDef PyDTraceSession_methods[] = {
	{"close", (PyCFunction)PyDTraceSession_close, METH_NOARGS,
	 "Close the session."},
	{"__enter__", (PyCFunction)PyDTraceSession_enter, METH_NOARGS,
	 "Context manager entry."},
	{"__exit__", (PyCFunction)PyDTraceSession_exit, METH_VARARGS,
	 "Context manager exit."},
	{"setopt", (PyCFunction)PyDTraceSession_setopt,
	 METH_VARARGS | METH_KEYWORDS, "Set a DTrace option."},
	{"compile", (PyCFunction)PyDTraceSession_compile,
	 METH_VARARGS | METH_KEYWORDS, "Compile a program from a string."},
	{"enable", (PyCFunction)PyDTraceSession_enable,
	 METH_VARARGS | METH_KEYWORDS, "Enable a compiled program."},
	{"go", (PyCFunction)PyDTraceSession_go, METH_VARARGS | METH_KEYWORDS,
	 "Start tracing."},
	{"stop", (PyCFunction)PyDTraceSession_stop, METH_NOARGS,
	 "Stop tracing."},
	{"update", (PyCFunction)PyDTraceSession_update, METH_NOARGS,
	 "Update module cache."},
	{"status", (PyCFunction)PyDTraceSession_status, METH_NOARGS,
	 "Retrieve tracing status."},
	{"work", (PyCFunction)PyDTraceSession_work,
	 METH_VARARGS | METH_KEYWORDS, "Do consumer loop work."},
	{"agg_snap", (PyCFunction)PyDTraceSession_agg_snap, METH_NOARGS,
	 "Snapshot aggregation buffers."},
	{"agg_clear", (PyCFunction)PyDTraceSession_agg_clear, METH_NOARGS,
	 "Clear aggregation buffers."},
	{"agg_walk", (PyCFunction)PyDTraceSession_agg_walk,
	 METH_VARARGS | METH_KEYWORDS, "Return aggregation results."},
	{"proc_create", (PyCFunction)PyDTraceSession_proc_create,
	 METH_VARARGS | METH_KEYWORDS, "Create process with args for tracing."},
	{"proc_grab_pid", (PyCFunction)PyDTraceSession_proc_grab_pid,
	 METH_VARARGS | METH_KEYWORDS, "Grab pid."},
	{"proc_continue", (PyCFunction)PyDTraceSession_proc_continue,
	 METH_VARARGS | METH_KEYWORDS, "Continue proc execution."},
	{"proc_release", (PyCFunction)PyDTraceSession_proc_release,
	 METH_VARARGS | METH_KEYWORDS, "Relase proc."},
	{NULL, NULL, 0, NULL}};

static PyTypeObject PyDTraceSessionType = {
	PyVarObject_HEAD_INIT(NULL, 0).tp_name = "dtrace.DTraceSession",
	.tp_basicsize = sizeof(PyDTraceSession),
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_new = PyDTraceSession_new,
	.tp_init = (initproc)PyDTraceSession_init,
	.tp_dealloc = (destructor)PyDTraceSession_dealloc,
	.tp_methods = PyDTraceSession_methods,
};

/* ------------------------------------------------------------------------- */
/* Module definition                                                         */
/* ------------------------------------------------------------------------- */

static struct PyModuleDef pydtrace_module = {
	PyModuleDef_HEAD_INIT,
	.m_name = "dtrace",
	.m_doc = "Python bindings for libdtrace.",
	.m_size = -1,
};

PyMODINIT_FUNC
PyInit_dtrace(void)
{
	PyObject *m;

	if (PyType_Ready(&PyDTraceSessionType) < 0)
		return NULL;
	if (PyType_Ready(&PyDTraceProgramType) < 0)
		return NULL;
	if (PyType_Ready(&PyDTraceProcType) < 0)
		return NULL;

	m = PyModule_Create(&pydtrace_module);
	if (m == NULL)
		return NULL;

	PyExc_DTraceError = PyErr_NewException("dtrace.DTraceError",
					       PyExc_RuntimeError, NULL);
	if (PyExc_DTraceError == NULL) {
		Py_DECREF(m);
		return NULL;
	}

	Py_INCREF(&PyDTraceSessionType);
	if (PyModule_AddObject(m, "DTraceSession",
			       (PyObject *)&PyDTraceSessionType) < 0) {
		Py_DECREF(&PyDTraceSessionType);
		Py_DECREF(m);
		return NULL;
	}

	Py_INCREF(&PyDTraceProgramType);
	if (PyModule_AddObject(m, "DTraceProgram",
			       (PyObject *)&PyDTraceProgramType) < 0) {
		Py_DECREF(&PyDTraceProgramType);
		Py_DECREF(m);
		return NULL;
	}

	Py_INCREF(&PyDTraceProcType);
	if (PyModule_AddObject(m, "DTraceProc", (PyObject *)&PyDTraceProcType) <
	    0) {
		Py_DECREF(&PyDTraceProcType);
		Py_DECREF(m);
		return NULL;
	}

	Py_INCREF(PyExc_DTraceError);
	if (PyModule_AddObject(m, "DTraceError", PyExc_DTraceError) < 0) {
		Py_DECREF(PyExc_DTraceError);
		Py_DECREF(m);
		return NULL;
	}

	if (PyModule_AddIntConstant(m, "DTRACE_VERSION", DTRACE_VERSION) < 0) {
		Py_DECREF(m);
		return NULL;
	}

	if (PyModule_AddIntConstant(m, "DTRACE_C_CPP", DTRACE_C_CPP) < 0 ||
	    PyModule_AddIntConstant(m, "DTRACE_C_ZDEFS", DTRACE_C_ZDEFS) < 0) {
		Py_DECREF(m);
		return NULL;
	}

	if (PyModule_AddIntConstant(m, "DTRACE_STATUS_NONE",
				    DTRACE_STATUS_NONE) < 0) {
		Py_DECREF(m);
		return NULL;
	}
	if (PyModule_AddIntConstant(m, "DTRACE_STATUS_OKAY",
				    DTRACE_STATUS_OKAY) < 0) {
		Py_DECREF(m);
		return NULL;
	}
	if (PyModule_AddIntConstant(m, "DTRACE_STATUS_EXITED",
				    DTRACE_STATUS_EXITED) < 0) {
		Py_DECREF(m);
		return NULL;
	}
	if (PyModule_AddIntConstant(m, "DTRACE_STATUS_FILLED",
				    DTRACE_STATUS_FILLED) < 0) {
		Py_DECREF(m);
		return NULL;
	}
	if (PyModule_AddIntConstant(m, "DTRACE_STATUS_STOPPED",
				    DTRACE_STATUS_STOPPED) < 0) {
		Py_DECREF(m);
		return NULL;
	}
	if (PyModule_AddIntConstant(m, "DTRACE_WORKSTATUS_DONE",
				    DTRACE_WORKSTATUS_DONE) < 0) {
		Py_DECREF(m);
		return NULL;
	}
	if (PyModule_AddIntConstant(m, "DTRACE_WORKSTATUS_OKAY",
				    DTRACE_WORKSTATUS_OKAY) < 0) {
		Py_DECREF(m);
		return NULL;
	}

	return m;
}
