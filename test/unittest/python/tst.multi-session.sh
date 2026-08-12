#!/bin/bash
#
# Oracle Linux DTrace.
# Copyright (c) 2026, Oracle and/or its affiliates. All rights reserved.
# Licensed under the Universal Permissive License v 1.0 as shown at
# http://oss.oracle.com/licenses/upl.
#
# Ensure multiple sessions within same process image work.

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
syscall::read:entry
{
    @counts["syscalls"] = count();
}
"""

dts = {}
max_sessions = 10

try:
    for i in range(max_sessions):
        dts[i] = DTraceSession()
        p = dts[i].compile(prog)
        dts[i].enable(p)
        dts[i].go()
        dts[i].work()
except Exception as exc:
        raise SystemExit(f"got err with {i} multiple sessions: {exc}")
finally:
    for j in range(i):
        dts[i].close()

EOF

chmod +x "$tmpdir/script.d"
PATH="$tmpdir:$PATH"

$tmpdir/script.d
