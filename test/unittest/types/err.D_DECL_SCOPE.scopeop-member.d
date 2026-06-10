/*
 * Oracle Linux DTrace.
 * Copyright (c) 2026, Oracle and/or its affiliates. All rights reserved.
 * Licensed under the Universal Permissive License v 1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 */

/*
 * ASSERTION: D scoping operators are not permitted in struct member names.
 */

#pragma D option quiet

struct scopeop_struct {
	int foo`bar;
};
