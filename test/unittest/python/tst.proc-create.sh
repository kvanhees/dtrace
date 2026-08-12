#!/bin/bash
#
# Oracle Linux DTrace.
# Copyright (c) 2026, Oracle and/or its affiliates. All rights reserved.
# Licensed under the Universal Permissive License v 1.0 as shown at
# http://oss.oracle.com/licenses/upl.
#
# Validate tracing of a spawned command.

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

cat >"$tmpdir"/script.py <<'EOF'
#!/usr/bin/env python3
from subprocess import Popen
from dtrace import DTraceSession

prog = r"""
syscall::read:entry
{
    @calls[execname] = count();
}
"""

with DTraceSession() as dt:
    p = dt.compile(prog)
    dt.enable(p)
    dt.go()
    proc = dt.proc_create(["/bin/echo", "hello"])
    dt.proc_continue(proc)
    dt.proc_release(proc)
    dt.stop()
    dt.agg_snap()
    rows = dt.agg_walk()

if not rows:
    raise SystemExit("no aggregation rows")

names = {tuple(entry["keys"]) for entry in rows}
if not any("echo" in key for key in names):
    raise SystemExit("expected echo entry in aggregation")
EOF

chmod +x "$tmpdir/script.py"

$tmpdir/script.py
