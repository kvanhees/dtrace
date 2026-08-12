#!/bin/bash
#
# Oracle Linux DTrace.
# Copyright (c) 2026, Oracle and/or its affiliates. All rights reserved.
# Licensed under the Universal Permissive License v 1.0 as shown at
# http://oss.oracle.com/licenses/upl.
#
# Ensure we see stopped state when traced process goes away.

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

from dtrace import DTraceSession, DTRACE_STATUS_STOPPED

prog = r"""
syscall:::entry
{
    c++;
}
"""

with DTraceSession() as dt:
    p = dt.compile(prog)
    dt.enable(p)
    dt.go()
    proc = dt.proc_create(["/bin/sleep", "5"])
    dt.proc_continue(proc)
    Popen(["/bin/sleep", "10"]).wait()
    dt.work()
    status = dt.status()
    dt.proc_release(proc)
    dt.stop()

if status != DTRACE_STATUS_STOPPED:
    raise SystemExit(f"missing DTRACE_STATUS_STOPPED: got {status}")

EOF

chmod +x "$tmpdir/script.d"
PATH="$tmpdir:$PATH"

$tmpdir/script.d
