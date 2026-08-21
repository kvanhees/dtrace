#!/bin/bash
#
# Ensure aggregation buffers can be cleared through the Python binding.

if [ $# -ne 1 ]; then
    echo "usage: $0 <dtrace>" >&2
    exit 2
fi

tmpdir=$(mktemp -d)
cleanup() { rm -rf "$tmpdir"; }
trap cleanup EXIT

cat >"$tmpdir/script.py" <<'EOF'
#!/usr/bin/env python3
from dtrace import DTraceSession

program = r'''
BEGIN
{
    @counts = count();
}
'''

with DTraceSession() as session:
    compiled = session.compile(program)
    session.enable(compiled)
    session.go()
    session.stop()
    session.agg_snap()
    if not session.agg_walk():
        raise SystemExit("aggregation was not populated")
    session.agg_clear()
    session.agg_snap()
    rows = session.agg_walk()
    if not rows:
        raise SystemExit("aggregation descriptor disappeared after agg_clear()")
    for row in rows:
        if row["name"] == "counts" and int(row["value"]) != 0:
            raise SystemExit(f"aggregation was not cleared: {row}")
EOF

chmod +x "$tmpdir/script.py"
"$DTRACE_PYTHON" "$tmpdir/script.py"
