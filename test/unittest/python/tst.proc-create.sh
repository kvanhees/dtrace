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
import time

from dtrace import DTRACE_STATUS_STOPPED, DTraceSession

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
    deadline = time.monotonic() + 5
    try:
        while time.monotonic() < deadline:
            status, _ = dt.work()
            if status == DTRACE_STATUS_STOPPED:
                break
            time.sleep(0.05)
        else:
            raise SystemExit("created process did not complete")
    finally:
        dt.proc_release(proc)
    dt.agg_snap()
    rows = dt.agg_walk()

if not rows:
    raise SystemExit("no aggregation rows")

def flatten(key):
    if isinstance(key, list):
        return [item for child in key for item in flatten(child)]
    return [key]

names = [flatten(entry["keys"]) for entry in rows]
if not any("echo" in key for key in names):
    raise SystemExit("expected echo entry in aggregation")
EOF

chmod +x "$tmpdir/script.py"

"$DTRACE_PYTHON" "$tmpdir/script.py"
