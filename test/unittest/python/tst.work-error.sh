#!/bin/bash
#
# Oracle Linux DTrace.
# Copyright (c) 2026, Oracle and/or its affiliates. All rights reserved.
# Licensed under the Universal Permissive License v 1.0 as shown at
# http://oss.oracle.com/licenses/upl.
#
# Ensure libdtrace errors from work() are reported as Python exceptions.

if [ $# -ne 1 ]; then
    echo "usage: $0 <dtrace>" >&2
    exit 2
fi

tmpdir=$(mktemp -d)
cleanup() {
    rm -rf "$tmpdir"
}
trap cleanup EXIT

cat >"$tmpdir/script.py" <<'EOF'
#!/usr/bin/env python3
from dtrace import DTraceError, DTraceSession


with DTraceSession() as session:
    try:
        session.work()
    except DTraceError:
        pass
    else:
        raise SystemExit("work() did not report its libdtrace error")
EOF

chmod +x "$tmpdir/script.py"
"$DTRACE_PYTHON" "$tmpdir/script.py"
