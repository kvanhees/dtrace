#!/bin/bash
#
# Ensure compile flags and preprocessor macro arguments are accepted.

if [ $# -ne 1 ]; then
    echo "usage: $0 <dtrace>" >&2
    exit 2
fi

tmpdir=$(mktemp -d)
cleanup() { rm -rf "$tmpdir"; }
trap cleanup EXIT

cat >"$tmpdir/script.py" <<'EOF'
#!/usr/bin/env python3
from dtrace import DTRACE_C_ZDEFS, DTraceSession

program = r'''
missing-provider:::missing-probe
{
    @missing = count();
}

BEGIN
{
    @value = sum(TEST_VALUE);
}
'''

with DTraceSession() as session:
    compiled = session.compile(
        program,
        cflags=DTRACE_C_ZDEFS,
        defines=["TEST_VALUE=42"],
    )
    session.enable(compiled)
    session.go()
    session.stop()
    session.agg_snap()
    rows = session.agg_walk()

values = {row["name"]: row["value"] for row in rows}
if int(values.get("value", -1)) != 42:
    raise SystemExit(f"macro definition was not applied: {values}")
if "missing" in values:
    raise SystemExit("missing probe unexpectedly generated an aggregation")
EOF

chmod +x "$tmpdir/script.py"
"$DTRACE_PYTHON" "$tmpdir/script.py"
