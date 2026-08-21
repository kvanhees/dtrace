#!/bin/bash
#
# Oracle Linux DTrace.
# Copyright (c) 2026, Oracle and/or its affiliates. All rights reserved.
# Licensed under the Universal Permissive License v 1.0 as shown at
# http://oss.oracle.com/licenses/upl.
#
# Ensure we see exit() from script with dt.status().

if [ $# -ne 1 ]; then
    echo "usage: $0 <dtrace>" >&2
    exit 2
fi

dtrace=$1

tmpdir=$(mktemp -d)
cleanup() {
    rm -rf "$tmpdir"
}
trap cleanup EXIT

cat >"$tmpdir"/script.d <<EOF
#!/usr/bin/env python3
from pathlib import Path
from subprocess import Popen

from dtrace import DTraceSession, DTRACE_STATUS_EXITED, DTRACE_STATUS_STOPPED

prog = r"""
syscall:::entry
{
    c++;
}

syscall:::entry
/ c > 1024 /
{
    exit(0);
}
"""

with DTraceSession() as dt:
    p = dt.compile(prog)
    dt.enable(p)
    dt.go()
    exited = False
    iters = 0
    while iters < 10:
        pid = Popen(["/bin/sleep", "1"]).wait()
        if dt.status() == DTRACE_STATUS_EXITED:
            exited = True
            break
        iters += 1
    if not exited:
        raise SystemExit("missing DTRACE_STATUS_EXIT")
    work_status, _ = dt.work()
    if work_status != DTRACE_STATUS_STOPPED:
        raise SystemExit(f"exit() was not drained by work(): got {work_status}")
    dt.stop()

EOF

chmod +x "$tmpdir/script.d"
PATH="$tmpdir:$PATH"

"$DTRACE_PYTHON" "$tmpdir/script.d"
