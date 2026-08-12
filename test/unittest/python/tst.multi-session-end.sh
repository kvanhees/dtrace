#!/bin/bash
#
# Oracle Linux DTrace.
# Copyright (c) 2026, Oracle and/or its affiliates. All rights reserved.
# Licensed under the Universal Permissive License v 1.0 as shown at
# http://oss.oracle.com/licenses/upl.
#
# Ensure END probes remain attached when another DTrace session in the same
# process closes.

if [ $# -ne 1 ]; then
    echo "usage: $0 <dtrace>" >&2
    exit 2
fi

tmpdir=$(mktemp -d)
cleanup() {
    rm -rf "$tmpdir"
}
trap cleanup EXIT

cat >"$tmpdir/script.d" <<'EOF'
#!/usr/bin/env python3
from dtrace import DTraceSession


program = r'''
END
{
    @ended = count();
}
'''


def start_session():
    session = DTraceSession()
    program_handle = session.compile(program)
    session.enable(program_handle)
    session.go()
    return session


def assert_end_fired(session, survivor):
    session.stop()
    session.agg_snap()
    rows = session.agg_walk()

    for row in rows:
        if row["name"] == "ended" and int(row["value"]) == 1:
            return

    raise SystemExit(f"END probe did not fire for surviving handle {survivor}")


# Closing A must not remove B's shared END uprobe.
handle_a = start_session()
handle_b = start_session()
try:
    handle_a.close()
    assert_end_fired(handle_b, "B")
finally:
    handle_b.close()

# Closing B must not remove A's shared END uprobe.
handle_a = start_session()
handle_b = start_session()
try:
    handle_b.close()
    assert_end_fired(handle_a, "A")
finally:
    handle_a.close()
EOF

chmod +x "$tmpdir/script.d"
"$tmpdir/script.d"
