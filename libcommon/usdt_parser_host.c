/*
 * Oracle Linux DTrace; Host-parser communication implementation.
 * Copyright (c) 2022, 2025, Oracle and/or its affiliates. All rights reserved.
 * Licensed under the Universal Permissive License v 1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 */

#include <errno.h>
#include <poll.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <libelf.h>
#include "usdt_parser.h"

static int
payload_has_n_cstrings(const char *str, size_t len, size_t nstr)
{
	const char *end = str + len;

	while (nstr-- > 0) {
		const char *nul;

		if (str >= end)
			return 0;

		nul = memchr(str, '\0', end - str);
		if (nul == NULL)
			return 0;

		str = nul + 1;
	}

	return 1;
}

const char *
usdt_parsed_invalid(const dof_parsed_t *msg)
{
	size_t payload_len;
	const char *payload;

	if (msg == NULL)
		return "null parsed message";

	if (msg->size < offsetof(dof_parsed_t, type))
		return "parsed message smaller than header";

	switch (msg->type) {
	case DIT_PROVIDER:
		if (msg->size < DIT_PROVIDER_HEADSZ + 1)
			return "provider record too small";
		if (!payload_has_n_cstrings(msg->provider.name,
					    msg->size - DIT_PROVIDER_HEADSZ, 1))
			return "unterminated provider name";
		break;
	case DIT_PROBE:
		if (msg->size < DIT_PROBE_HEADSZ + 3)
			return "probe record too small";
		if (!payload_has_n_cstrings(msg->probe.name,
					    msg->size - DIT_PROBE_HEADSZ, 3))
			return "unterminated probe name";
		break;
	case DIT_TRACEPOINT:
		if (msg->size < DIT_TRACEPOINT_HEADSZ + 1)
			return "tracepoint record too small";
		if (!payload_has_n_cstrings(msg->tracepoint.args,
					    msg->size - DIT_TRACEPOINT_HEADSZ, 1))
			return "unterminated tracepoint args";
		break;
	case DIT_ERR:
		if (msg->size < DIT_ERR_HEADSZ + 1)
			return "error record too small";
		if (!payload_has_n_cstrings(msg->err.err,
					    msg->size - DIT_ERR_HEADSZ, 1))
			return "unterminated parser error";
		break;
	case DIT_ARGS_NATIVE:
		if (msg->size < DIT_ARGS_NATIVE_HEADSZ)
			return "native-args record too small";
		payload = msg->nargs.args;
		payload_len = msg->size - DIT_ARGS_NATIVE_HEADSZ;
		if (payload_len > 0 && payload[payload_len - 1] != '\0')
			return "unterminated native arg string";
		break;
	case DIT_ARGS_XLAT:
		if (msg->size < DIT_ARGS_XLAT_HEADSZ)
			return "translated-args record too small";
		payload = msg->xargs.args;
		payload_len = msg->size - DIT_ARGS_XLAT_HEADSZ;
		if (payload_len > 0 && payload[payload_len - 1] != '\0')
			return "unterminated translated arg string";
		break;
	case DIT_ARGS_MAP:
		if (msg->size < DIT_ARGS_MAP_HEADSZ)
			return "arg-map record too small";
		break;
	case DIT_EOF:
		if (msg->size != offsetof(dof_parsed_t, provider.nprobes))
			return "bad EOF record size";
		break;
	default:
		return "unknown parsed record type";
	}

	return NULL;
}

/*
 * Write BUF to the parser pipe OUT.
 *
 * Returns 0 on success or a positive errno value on error.
 */
int
usdt_parser_write_one(int out, const void *buf_, size_t size)
{
	size_t i;
	char *buf = (char *) buf_;

	for (i = 0; i < size; ) {
		ssize_t ret;

		ret = write(out, buf + i, size - i);
		if (ret < 0) {
			switch (errno) {
			case EINTR:
				continue;
			default:
				return errno;
			}
		}

		i += ret;
	}

	return 0;
}

/*
 * Write the DOF to the parser pipe OUT.
 *
 * Returns 0 on success or a positive errno value on error.
 */
int
usdt_parser_host_write(int out, const dof_helper_t *dh, const usdt_data_t *data)
{
	int err;
	size_t cnt = 0;
	const usdt_data_t *blk;

	/* Write dof_helper_ structure. */
	if ((err = usdt_parser_write_one(out, (const char *)dh,
					 sizeof(*dh))) != 0)
		return err;

	/* Count and write nunmber of blocks that follow. */
	for (blk = data; blk != NULL; blk = blk->next)
		cnt++;

	if ((err = usdt_parser_write_one(out, (const char *)&cnt,
					 sizeof(cnt))) != 0)
		return err;

	/* Write the blocks (for each, offset, size, and data). */
	for (blk = data; blk != NULL; blk = blk->next) {
		if ((err = usdt_parser_write_one(out, (const char *)&blk->base,
						 sizeof(blk->base))) != 0)
			return err;
		if ((err = usdt_parser_write_one(out, (const char *)&blk->size,
						 sizeof(blk->size))) != 0)
			return err;
		if ((err = usdt_parser_write_one(out, (const char *)blk->buf,
						 blk->size)) != 0)
			return err;
	}

	return 0;
}

/*
 * Read a single dof_parsed_t structure from a parser pipe.  Wait at most
 * TIMEOUT seconds to do so.
 *
 * Returns NULL and sets errno on error.
 */
dof_parsed_t *
usdt_parser_host_read(int in, int timeout)
{
	size_t i, sz;
	dof_parsed_t *reply;
	struct pollfd fd;

	fd.fd = in;
	fd.events = POLLIN;

	reply = malloc(sizeof(dof_parsed_t));
	if (!reply)
		goto err;
	memset(reply, 0, sizeof(dof_parsed_t));

	/*
	 * On the first read, only read in the size.  Decide how much to read
	 * only after that, both to make sure we don't underread and to make
	 * sure we don't *overread* and concatenate part of another message
	 * onto this one.
	 *
	 * Adjust the timeout whenever we are interrupted.  If we can't figure
	 * out the time, don't bother adjusting, but still read: a read taking
	 * longer than expected is better than no read at all.
	 */
	for (i = 0, sz = offsetof(dof_parsed_t, type); i < sz;) {
		ssize_t ret;
		struct timespec start, end;
		int no_adjustment = 0;
		long timeout_msec = timeout * MILLISEC;

		if (clock_gettime(CLOCK_REALTIME, &start) < 0)
			no_adjustment = 1;

		while ((ret = poll(&fd, 1, timeout_msec)) <= 0 && errno == EINTR) {

			if (no_adjustment || clock_gettime(CLOCK_REALTIME, &end) < 0)
				continue; /* Abandon timeout adjustment */

			timeout_msec -= ((((unsigned long long) end.tv_sec * NANOSEC) + end.tv_nsec) -
					 (((unsigned long long) start.tv_sec * NANOSEC) + start.tv_nsec)) /
					MICROSEC;

			if (timeout_msec < 0)
				timeout_msec = 0;
		}

		if (ret < 0)
			goto err;

		while ((ret = read(in, ((char *) reply) + i, sz - i)) < 0 &&
		       errno == EINTR);

		if (ret <= 0)
			goto err;

		/*
		 * Fix up the size once it's received.  Might be large enough
		 * that we've done the initial size read...
		 */
		if (i < offsetof(dof_parsed_t, type) &&
		    i + (size_t)ret >= offsetof(dof_parsed_t, type)) {
			sz = reply->size;
			if (sz < offsetof(dof_parsed_t, type) || sz > DOF_MAXSZ) {
				errno = EPROTO;
				goto err;
			}
		}

		/* Allocate more room if needed for the reply.  */
		if (sz > sizeof(dof_parsed_t)) {
			dof_parsed_t *new_reply;

			new_reply = realloc(reply, reply->size);
			if (!new_reply)
				goto err;

			memset(((char *) new_reply) + i + ret, 0,
			       new_reply->size - (i + ret));
			reply = new_reply;
		}

		i += ret;
	}

	return reply;

err:
	free(reply);
	return NULL;
}
