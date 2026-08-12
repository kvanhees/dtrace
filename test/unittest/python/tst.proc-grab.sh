#!/bin/bash
#
# Oracle Linux DTrace.
# Copyright (c) 2026, Oracle and/or its affiliates. All rights reserved.
# Licensed under the Universal Permissive License v 1.0 as shown at
# http://oss.oracle.com/licenses/upl.
#
# Ensure Python bindings can grab an existing process and trace its syscalls.

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

# Start a long-lived helper shell to grab.
sleep_inf="$tmpdir/sleep.sh"
cat >"$sleep_inf" <<'EOF'
#!/bin/bash
while :; do
    sleep 1
done
EOF
chmod +x "$sleep_inf"
"$sleep_inf" &
helper=$!

cat >"$tmpdir"/script.py <<'EOF'
#!/usr/bin/env python3
import os
import sys
from subprocess import Popen
from dtrace import DTraceSession

prog = r"""
syscall:::entry
/ pid == $target /
{
    @counts[execname, probefunc] = count();
}
"""

pid = int(os.environ["TARGET_PID"])

with DTraceSession() as dt:
    proc = dt.proc_grab_pid(pid)
    if proc.getpid() != pid:
        raise SystemExit("grabbed PID mismatch")
    p = dt.compile(prog)
    dt.enable(p)
    dt.go()
    dt.proc_continue(proc)
    Popen(["/bin/sleep", "5"]).wait()
    dt.stop()
    dt.proc_release(proc)
    dt.agg_snap()
    rows = dt.agg_walk()

if not rows:
    raise SystemExit("no rows returned")

entry = rows[0]
if "keys" not in entry or "value" not in entry:
    raise SystemExit("missing keys or value")
EOF

chmod +x "$tmpdir/script.py"
export TARGET_PID=$helper
$tmpdir/script.py
ret=$?

kill $helper
wait $helper 2>/dev/null || true
exit $ret
