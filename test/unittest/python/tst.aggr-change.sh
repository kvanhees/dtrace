#!/bin/bash
#
# Oracle Linux DTrace.
# Copyright (c) 2026, Oracle and/or its affiliates. All rights reserved.
# Licensed under the Universal Permissive License v 1.0 as shown at
# http://oss.oracle.com/licenses/upl.
#
# Ensure aggregation values are updated across dt.work() calls.

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

from dtrace import DTraceSession

prog = r"""
syscall:::entry
{
    @counts["syscalls"] = count();
}
"""

with DTraceSession() as dt:
    p = dt.compile(prog)
    dt.enable(p)
    dt.go()
    pid = Popen(["/bin/sleep", "1"]).wait()
    dt.work()
    dt.agg_snap()
    rows = dt.agg_walk()
    if not rows:
        raise SystemExit("no rows returned")
    entry = rows[0]
    val1 = int(entry["value"])
    pid = Popen(["/bin/sleep", "1"]).wait()
    dt.work()
    dt.agg_snap()
    rows = dt.agg_walk()
    if not rows:
        raise SystemExit("no rows returned")
    entry = rows[0]
    val2 = int(entry["value"])
    if val2 <= val1:
        raise SystemExit("aggr value unchanged")
    dt.stop()
    
    rows = dt.agg_walk()

if not rows:
    raise SystemExit("no rows returned")

entry = rows[0]
if "keys" not in entry or "value" not in entry:
    raise SystemExit("missing keys or value")

EOF

chmod +x "$tmpdir/script.d"
PATH="$tmpdir:$PATH"

$tmpdir/script.d
