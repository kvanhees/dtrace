/*
 * Oracle Linux DTrace.
 * Copyright (c) 2026, Oracle and/or its affiliates. All rights reserved.
 * Licensed under the Universal Permissive License v 1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 */

/* @@trigger: testprobe */
/* @@runtest-opts: -e */

/*
 * ASSERTION: Explicit userspace module scoping resolves as a userspace
 * external symbol reference.
 */

#pragma D option quiet

BEGIN
{
	trace(&testprobe``main);
	exit(0);
}
