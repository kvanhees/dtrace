/*
 * Copyright (c) 2026, Oracle and/or its affiliates. All rights reserved.
 * Licensed under the Universal Permissive License v 1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 */

#include "libdtrace/dt_btf.c"

static int
check(const dt_btf_t *btf, int argc, int is_void, int traceable)
{
	return dt_btf_func_argc(btf, 1) == argc &&
	       dt_btf_func_is_void(btf, 1) == is_void &&
	       dt_btf_func_is_traceable(btf, 1) == traceable;
}

int
main(void)
{
	btf_type_t	func = { .info = BTF_KIND_FUNC << 24, .type = 1 };
	btf_type_t	qualifier = { .info = BTF_KIND_CONST << 24, .type = 1 };
	btf_type_t	proto = { .info = BTF_KIND_FUNC_PROTO << 24 };
	btf_type_t	*types[] = { NULL, &func, &qualifier, &proto };
	dt_btf_t	btf = { .type_cnt = 4, .types = types };

	/* A function that refers directly to itself. */
	if (!check(&btf, -1, 0, 0))
		return 1;

	/* A function and qualifier that refer to each other. */
	func.type = 2;
	if (!check(&btf, -1, 0, 0))
		return 2;

	/* The same chain must resolve when it ends at a prototype. */
	qualifier.type = 3;
	if (!check(&btf, 0, 1, 1))
		return 3;

	/* A cyclic return type makes an otherwise valid prototype untraceable. */
	func.type = 3;
	proto.type = 2;
	qualifier.type = 2;
	if (!check(&btf, 0, 0, 0))
		return 4;

	/* Follow references through a parent and child BTF, then close a loop. */
	{
		btf_type_t *parent_types[] = { NULL, &func, &proto };
		btf_type_t *child_types[] = { NULL, &qualifier };
		dt_btf_t parent = { .type_cnt = 3, .types = parent_types };
		dt_btf_t child = { .parent = &parent, .type_cnt = 2,
				   .types = child_types };

		func.type = 3;
		proto.type = 0;
		qualifier.type = 2;
		if (!check(&child, 0, 1, 1))
			return 5;

		qualifier.type = 1;
		if (!check(&child, -1, 0, 0))
			return 6;
	}

	return 0;
}
