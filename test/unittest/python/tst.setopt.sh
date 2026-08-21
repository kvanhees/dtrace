#!/bin/bash
#
# Ensure valid and invalid options are handled through the Python binding.

if [ $# -ne 1 ]; then
    echo "usage: $0 <dtrace>" >&2
    exit 2
fi

tmpdir=$(mktemp -d)
cleanup() { rm -rf "$tmpdir"; }
trap cleanup EXIT

cat >"$tmpdir/script.py" <<'EOF'
#!/usr/bin/env python3
from dtrace import DTraceError, DTraceSession

with DTraceSession() as session:
    session.setopt("bufsize", "4m")
    session.setopt("quiet", None)
    try:
        session.setopt("not-a-dtrace-option", "1")
    except DTraceError:
        pass
    else:
        raise SystemExit("invalid option was accepted")
EOF

chmod +x "$tmpdir/script.py"
"$DTRACE_PYTHON" "$tmpdir/script.py"
