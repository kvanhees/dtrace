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
#include <math.h>
#include <sys/param.h>
#include <sys/types.h>
#include <pthread.h>

#include <dtrace.h>
#include "dt_aggregate.h"
#include "dt_math.h"

#ifndef UNUSED
#define UNUSED(x) ((void)(x))
#endif

typedef struct {
	PyObject_HEAD
	dtrace_hdl_t *dtp;
	FILE *fp;
	int pids;      /* pid()s _create()ed or grab()bed */
	int pids_live; /* _continue()d active processes */
	int status;    /* EXITed or STOPPED */
	int exit_status;
	int closed;
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
	switch (size) {
	case 1:
		return *((const uint8_t *)addr);
	case 2:
		return *((const uint16_t *)addr);
	case 4:
		return *((const uint32_t *)addr);
	case 8:
		return *((const uint64_t *)addr);
	default:
		return 0;
	}
}

static inline int64_t
read_sint(const void *addr, size_t size)
{
	switch (size) {
	case 1:
		return *((const int8_t *)addr);
	case 2:
		return *((const int16_t *)addr);
	case 4:
		return *((const int32_t *)addr);
	case 8:
		return *((const int64_t *)addr);
	default:
		return 0;
	}
}

static PyObject *
bytes_or_string_from_buffer(const char *addr, size_t size)
{
	if (size == 0)
		return PyBytes_FromStringAndSize("", 0);

	if (addr[size - 1] == '\0') {
		size_t n = strnlen(addr, size);
		return PyUnicode_DecodeUTF8(addr, (Py_ssize_t)n, "replace");
	}

	return PyBytes_FromStringAndSize(addr, (Py_ssize_t)size);
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
quant_dict_add(PyObject *dict, long long bucket, long long count)
{
	PyObject *key = PyLong_FromLongLong(bucket);
	PyObject *val;

	if (key == NULL)
		return NULL;

	val = PyLong_FromLongLong(count);
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
convert_quantize(const int64_t *data, size_t nbins, uint64_t normal)
{
	PyObject *dict = PyDict_New();

	if (dict == NULL)
		return NULL;

	if (normal == 0)
		normal = 1;

	for (size_t i = 0; i < nbins; i++) {
		int64_t count = data[i];

		if (count == 0)
			continue;

		count /= (int64_t)normal;
		if (count == 0)
			continue;

		if (quant_dict_add(dict, DTRACE_QUANTIZE_BUCKETVAL((uint64_t)i),
				   count) == NULL) {
			Py_DECREF(dict);
			return NULL;
		}
	}

	return dict;
}

static PyObject *
convert_lquantize(const int64_t *data, uint64_t sig, size_t size,
		  uint64_t normal)
{
	uint16_t levels = DTRACE_LQUANTIZE_LEVELS(sig);
	uint16_t step = DTRACE_LQUANTIZE_STEP(sig);
	int32_t base = DTRACE_LQUANTIZE_BASE(sig);
	size_t expected;
	PyObject *dict;

	if (normal == 0)
		normal = 1;

	expected = (size_t)(levels + 2) * sizeof(uint64_t);
	if (size != expected)
		return PyBytes_FromStringAndSize((const char *)data,
						 (Py_ssize_t)size);

	dict = PyDict_New();
	if (dict == NULL)
		return NULL;

	for (uint16_t i = 0; i < levels + 2; i++) {
		int64_t count = data[i];
		long long bucket;

		if (count == 0)
			continue;

		count /= (int64_t)normal;
		if (count == 0)
			continue;

		if (i == 0)
			bucket = base - 1;
		else if (i == levels + 1)
			bucket = base + (long long)levels * step;
		else
			bucket = base + (long long)(i - 1) * step;

		if (quant_dict_add(dict, bucket, count) == NULL) {
			Py_DECREF(dict);
			return NULL;
		}
	}

	return dict;
}

static PyObject *
convert_llquantize(const int64_t *data, uint64_t sig, size_t size,
		   uint64_t normal)
{
	int factor = DTRACE_LLQUANTIZE_FACTOR(sig);
	int lmag = DTRACE_LLQUANTIZE_LMAG(sig);
	int hmag = DTRACE_LLQUANTIZE_HMAG(sig);
	int steps = DTRACE_LLQUANTIZE_STEPS(sig);
	int steps_factor = steps / factor;
	int bin0;
	size_t nbins;
	PyObject *dict;

	if (normal == 0)
		normal = 1;

	bin0 = 1 + (hmag - lmag + 1) * (steps - steps_factor);
	nbins = (size_t)(hmag - lmag + 1) * (steps - steps_factor) * 2 + 3;

	if (size != nbins * sizeof(uint64_t))
		return PyBytes_FromStringAndSize((const char *)data,
						 (Py_ssize_t)size);

	dict = PyDict_New();
	if (dict == NULL)
		return NULL;

	for (size_t i = 0; i < nbins; i++) {
		int64_t count = data[i];
		long long bucket;

		if (count == 0)
			continue;

		count /= (int64_t)normal;
		if (count == 0)
			continue;

		if (i == 0)
			bucket = -(long long)powl((double)factor,
						  (double)(hmag + 1));
		else if (i == nbins - 1)
			bucket = (long long)powl((double)factor,
						 (double)(hmag + 1));
		else if (i == (size_t)bin0) {
			bucket = 0;
		} else {
			int left = (int)i - bin0;
			int is_neg = left < 0;
			int steps_rem = is_neg ? bin0 - (int)i : left;
			long long scale;
			int mag = lmag;

			if (steps_rem == 0) {
				bucket = 0;
				goto have_bucket;
			}

			if (lmag == 0 && steps > factor) {
				for (int val = 2;
				     val <= factor && steps_rem > 0; val++) {
					steps_rem -= steps_factor;
					if (steps_rem == 0) {
						bucket = is_neg ? -val : val;
						goto have_bucket;
					}
				}
				mag++;
			}

			scale = (long long)(powl((double)factor,
						 (double)(mag + 1)) /
					    (double)steps);

			while (mag <= hmag) {
				for (int step = steps_factor + 1; step <= steps;
				     step++) {
					steps_rem--;
					if (steps_rem == 0) {
						bucket = step * scale;
						if (is_neg)
							bucket = -bucket;
						goto have_bucket;
					}
				}
				scale *= factor;
				mag++;
			}

			bucket = is_neg ? -(long long)powl((double)factor,
							   (double)(hmag + 1))
					: (long long)powl((double)factor,
							  (double)(hmag + 1));
		}

	have_bucket:
		if (quant_dict_add(dict, bucket, count) == NULL) {
			Py_DECREF(dict);
			return NULL;
		}
	}

	return dict;
}

static PyObject *
convert_quantized(const dtrace_recdesc_t *rec, caddr_t base, uint64_t normal,
		  const dtrace_aggdata_t *aggdata)
{
	caddr_t addr = base + rec->dtrd_offset;
	size_t size = rec->dtrd_size;
	const int64_t *data = (const int64_t *)addr;
	const dtrace_aggdesc_t *agg = aggdata ? aggdata->dtada_desc : NULL;
	uint64_t sig = agg ? agg->dtagd_sig : 0;

	switch (rec->dtrd_action) {
	case DT_AGG_QUANTIZE:
		if (size % sizeof(uint64_t) != 0)
			return PyBytes_FromStringAndSize((const char *)addr,
							 (Py_ssize_t)size);
		return convert_quantize(data, size / sizeof(uint64_t), normal);
	case DT_AGG_LQUANTIZE:
		if (sig == 0)
			return PyBytes_FromStringAndSize((const char *)addr,
							 (Py_ssize_t)size);
		return convert_lquantize(data, sig, size, normal);
	case DT_AGG_LLQUANTIZE:
		if (sig == 0)
			return PyBytes_FromStringAndSize((const char *)addr,
							 (Py_ssize_t)size);
		return convert_llquantize(data, sig, size, normal);
	default:
		break;
	}

	return PyBytes_FromStringAndSize((const char *)addr, (Py_ssize_t)size);
}

static PyObject *
convert_record_value(PyDTraceSession *session, const dtrace_recdesc_t *rec,
		     caddr_t base, uint64_t normal,
		     const dtrace_aggdata_t *aggdata)
{
	caddr_t addr = base + rec->dtrd_offset;
	size_t size = rec->dtrd_size;
	const uint64_t *words = (const uint64_t *)addr;
	uint32_t depth = 0, tgid = 0;
	char buf[PATH_MAX * 2];
	PyObject *sym;
	uint64_t pc;
	int len;

	switch (rec->dtrd_action) {
	case DT_AGG_AVG: {
		if (size < sizeof(int64_t) * 2)
			return PyFloat_FromDouble(0.0);

		const int64_t *data = (const int64_t *)addr;
		if (data[0] == 0)
			return PyFloat_FromDouble(0.0);

		long double avg = (long double)data[1] / (long double)normal /
				  (long double)data[0];
		return PyFloat_FromDouble((double)avg);
	}

	case DT_AGG_SUM:
	case DT_AGG_MIN:
	case DT_AGG_MAX:
	case DT_AGG_COUNT: {
		int64_t value = read_sint(addr, size);
		value /= (int64_t)normal;
		return PyLong_FromLongLong(value);
	}

	case DT_AGG_STDDEV: {
		uint64_t stddev = dt_stddev((uint64_t *)addr, normal);

		return PyLong_FromUnsignedLongLong(stddev);
	}
	case DT_AGG_QUANTIZE:
	case DT_AGG_LQUANTIZE:
	case DT_AGG_LLQUANTIZE:
		return convert_quantized(rec, base, normal, aggdata);

	case DTRACEACT_JSTACK:
	case DTRACEACT_USTACK:
	case DTRACEACT_STACK: {
		depth = *(uint32_t *)words;
		uint32_t frames =
			depth < rec->dtrd_size / sizeof(uint64_t)
				? depth
				: (uint32_t)(rec->dtrd_size / sizeof(uint64_t));
		PyObject *list = PyList_New((Py_ssize_t)0);
		if (list == NULL)
			return NULL;

		if (rec->dtrd_action != DTRACEACT_STACK)
			tgid = ((uint32_t *)words)[3];
		for (uint32_t i = 0; i < frames; i++) {
			pc = words[i + 2];

			if (pc == 0)
				break;
			len = rec->dtrd_action != DTRACEACT_STACK
				      ? dtrace_uaddr2str(session->dtp, tgid, pc,
							 buf, sizeof(buf))
				      : dtrace_addr2str(session->dtp, pc, buf,
							sizeof(buf));
			if (len < 0) {
				Py_DECREF(list);
				return raise_dtrace_error(session,
							  "dtrace_addr2str");
			}
			PyObject *frame = PyUnicode_FromString(buf);
			if (frame == NULL) {
				Py_DECREF(list);
				return NULL;
			}
			if (PyList_Insert(list, 0, frame) < 0) {
				Py_DECREF(frame);
				Py_DECREF(list);
				return NULL;
			}
			Py_DECREF(frame);
		}
		return list;
	}
	case DTRACEACT_SYM:
	case DTRACEACT_MOD: {
		pc = words[0];
		dtrace_syminfo_t dts;

		if (dtrace_lookup_by_addr(session->dtp, pc, NULL, &dts) == 0) {
			if (rec->dtrd_action == DTRACEACT_SYM)
				snprintf(buf, sizeof(buf), "%s`%s", dts.object,
					 dts.name);
			else
				snprintf(buf, sizeof(buf), "%s", dts.object);
		} else {
			snprintf(buf, sizeof(buf), "0x%llx",
				 (unsigned long long)pc);
		}
		sym = PyUnicode_FromString(buf);
		if (sym == NULL)
			return NULL;
		return sym;
	}
	case DTRACEACT_UADDR: {
		tgid = ((uint32_t *)words)[0];
		pc = words[1];
		len = dtrace_uaddr2str(session->dtp, tgid, pc, buf,
				       sizeof(buf));
		if (len < 0)
			return raise_dtrace_error(session, "dtrace_addr2str");
		sym = PyUnicode_FromString(buf);
		if (sym == NULL)
			return NULL;
		return sym;
	}
	/*
	 * These two functions require grabbing pid lock etc, no interfaces yet
	 * in libdtrace for this.
	 */
	case DTRACEACT_USYM:
	case DTRACEACT_UMOD:
	default:
		break;
	}

	switch (size) {
	case 1:
	case 2:
	case 4:
	case 8: {
		int64_t value = read_sint(addr, size);
		value /= (int64_t)normal;
		return PyLong_FromLongLong(value);
	}
	default:
		return bytes_or_string_from_buffer((const char *)addr, size);
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

	for (uint_t i = 1; i < agg->dtagd_nkrecs; i++) {
		const dtrace_recdesc_t *rec = &agg->dtagd_krecs[i];
		PyObject *item = convert_record_value(
			session, rec, aggdata->dtada_key, 0, aggdata);

		if (item == NULL) {
			Py_DECREF(keys);
			goto error;
		}

		if (PyList_Append(keys, item) < 0) {
			Py_DECREF(item);
			Py_DECREF(keys);
			goto error;
		}
		Py_DECREF(item);
	}

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

	PyObject *value = convert_record_value(
		session, value_rec, aggdata->dtada_data, normal, aggdata);
	if (value == NULL)
		goto error;
	if (PyDict_SetItemString(entry, "value", value) < 0) {
		Py_DECREF(value);
		goto error;
	}
	Py_DECREF(value);

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
	if (self->dtp != NULL && !self->closed) {
		Py_BEGIN_ALLOW_THREADS dtrace_close(self->dtp);
		Py_END_ALLOW_THREADS
	}
	self->dtp = NULL;
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

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|Ii", kwlist, &version,
					 &flags))
		return -1;

	self->dtp = dtrace_open(version, flags, &err);
	if (self->dtp == NULL)
		return raise_dtrace_error_with_code(NULL, err, "dtrace_open") ==
				       NULL
			       ? -1
			       : -1;

	self->fp = fopen("/dev/null", "a");
	if (dtrace_init(self->dtp) != 0) {
		raise_dtrace_error(self, "dtrace_init");
		dtrace_close(self->dtp);
		fclose(self->fp);
		self->dtp = NULL;
		self->fp = NULL;
		return -1;
	}
	if (dtrace_handle_proc(self->dtp, &prochandler, self) != 0 ||
	    dtrace_setopt(self->dtp, "aggsize", "4m") != 0 ||
	    dtrace_setopt(self->dtp, "bufsize", "4m") != 0) {
		raise_dtrace_error(self, "dtrace_setopt");
		dtrace_close(self->dtp);
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
	if (!self->closed && self->dtp != NULL) {
		Py_BEGIN_ALLOW_THREADS dtrace_close(self->dtp);
		Py_END_ALLOW_THREADS fclose(self->fp);
		self->dtp = NULL;
		self->fp = NULL;
		self->closed = 1;
	}

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

	if (!self->closed && self->dtp != NULL) {
		Py_BEGIN_ALLOW_THREADS dtrace_close(self->dtp);
		Py_END_ALLOW_THREADS if (self->fp) fclose(self->fp);
		self->dtp = NULL;
		self->fp = NULL;
		self->closed = 1;
	}

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

	if (dtrace_setopt(self->dtp, opt, cvalue) != 0) {
		Py_XDECREF(value_str);
		return raise_dtrace_error(self, "dtrace_setopt");
	}

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
	static char *kwlist[] = {"program", "cflags", "argv", "spec", NULL};
	const char *source = NULL;
	unsigned int cflags = 0;
	PyObject *argv_obj = NULL;
	int spec = DTRACE_PROBESPEC_NAME;
	PyObject *argv_seq = NULL;
	char **argv = NULL;
	PyObject **encoded = NULL;
	Py_ssize_t argc = 0;
	dtrace_prog_t *prog = NULL;
	PyDTraceProgram *wrapper = NULL;

	if (ensure_open(self) < 0)
		return NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|IOi", kwlist, &source,
					 &cflags, &argv_obj, &spec))
		return NULL;

	if (argv_obj != NULL && argv_obj != Py_None) {
		argv_seq = PySequence_Fast(
			argv_obj, "argv must be a sequence of strings");
		if (argv_seq == NULL)
			return NULL;

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

	pthread_mutex_lock(&compile_lock);
	prog = dtrace_program_strcompile(self->dtp, source,
					 (dtrace_probespec_t)spec, cflags,
					 (int)argc, argv);
	pthread_mutex_unlock(&compile_lock);

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

	if (dtrace_program_exec(self->dtp, program->prog, &info) != 0)
		return raise_dtrace_error(self, "dtrace_program_exec");

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

	Py_BEGIN_ALLOW_THREADS rc = dtrace_go(self->dtp, cflags);
	Py_END_ALLOW_THREADS

		if (rc != 0) return raise_dtrace_error(self, "dtrace_go");

	Py_RETURN_NONE;
}

static PyObject *
PyDTraceSession_stop(PyDTraceSession *self, PyObject *Py_UNUSED(args))
{
	if (ensure_open(self) < 0)
		return NULL;

	if (dtrace_stop(self->dtp) != 0)
		return raise_dtrace_error(self, "dtrace_stop");

	Py_RETURN_NONE;
}

static PyObject *
PyDTraceSession_update(PyDTraceSession *self, PyObject *Py_UNUSED(args))
{
	if (ensure_open(self) < 0)
		return NULL;

	if (dtrace_update(self->dtp) != 0)
		return raise_dtrace_error(self, "dtrace_update");

	Py_RETURN_NONE;
}

static PyObject *
PyDTraceSession_status(PyDTraceSession *self, PyObject *Py_UNUSED(args))
{
	if (ensure_open(self) < 0)
		return NULL;

	int status = dtrace_status(self->dtp);
	if (status == DTRACE_STATUS_ERROR)
		return raise_dtrace_error(self, "dtrace_status");
	/*
	 * We maintain some local status too for forced exit (see consume_rec()
	 * below)
	 */
	if (status == DTRACE_STATUS_OKAY && self->status)
		status = self->status;
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
		self->exit_status = *(uint32_t *)addr;
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
		PyObject *raw = PyBytes_FromStringAndSize(
			(const char *)(data->dtpda_data + rec->dtrd_offset),
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

	status = dtrace_work(self->dtp, self->fp, consume_probe, consume_rec,
			     &ctx);

	if (status == DTRACE_WORKSTATUS_ERROR || (ctx.capture && ctx.aborted)) {
		Py_XDECREF(ctx.probes);
		return raise_dtrace_error(self, "dtrace_work");
	}

	if (status == DTRACE_STATUS_OKAY && self->pids > 0 &&
	    self->pids_live == 0)
		status = DTRACE_STATUS_EXITED;

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
	if (ensure_open(self) < 0)
		return NULL;

	if (dtrace_aggregate_snap(self->dtp) != 0)
		return raise_dtrace_error(self, "dtrace_aggregate_snap");

	Py_RETURN_NONE;
}

static PyObject *
PyDTraceSession_agg_clear(PyDTraceSession *self, PyObject *Py_UNUSED(args))
{
	if (ensure_open(self) < 0)
		return NULL;

	dtrace_aggregate_clear(self->dtp);
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

	rc = walker(self->dtp, agg_walk_callback, &ctx);
	if (rc != 0) {
		Py_DECREF(ctx.list);
		return raise_dtrace_error(self, "dtrace_aggregate_walk");
	}

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
		if (self->proc && self->session->dtp)
			dtrace_proc_release(self->session->dtp, self->proc);

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

	pid = dtrace_proc_getpid(self->session->dtp, self->proc);

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
	proc = dtrace_proc_create(self->dtp, argvlist[0], argvlist, 0);
	if (proc == NULL)
		goto error_raise;

	ret = PyDTraceProcType.tp_alloc(&PyDTraceProcType, 0);
	if (ret == NULL) {
		dtrace_proc_release(self->dtp, proc);
		goto error;
	}
	self->pids++;
	retproc = (PyDTraceProc *)ret;
	retproc->session = self;
	Py_INCREF(self);
	retproc->proc = proc;
	for (i = 0; i < size; i++)
		Py_DECREF(encoded[i]);

	return ret;

error_raise:
	ret = raise_dtrace_error(self, "dtrace_proc_create");
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

	proc = dtrace_proc_grab_pid(self->dtp, pid, 0);
	if (!proc)
		return raise_dtrace_error(self, "dtrace_proc_grab_pid");
	ret = PyDTraceProcType.tp_alloc(&PyDTraceProcType, 0);
	if (ret == NULL) {
		dtrace_proc_release(self->dtp, proc);
		return ret;
	}
	self->pids++;
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

	dtrace_proc_continue(self->dtp, proc->proc);
	self->pids_live++;

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

	dtrace_proc_release(self->dtp, proc->proc);
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
