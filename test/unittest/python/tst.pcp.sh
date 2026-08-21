#!/bin/bash
#
# Oracle Linux DTrace.
# Copyright (c) 2026, Oracle and/or its affiliates. All rights reserved.
# Licensed under the Universal Permissive License v 1.0 as shown at
# http://oss.oracle.com/licenses/upl.
#
# Test the PCP ManagedDTraceScript with a real DTrace session.
# @@timeout: 60

if [ $# -ne 1 ]; then
    echo "usage: $0 <dtrace>" >&2
    exit 2
fi

if ! "$DTRACE_PYTHON" -c 'import dtrace, cpmapi, cpmda, pcp.pmapi, pcp.pmda' \
    >/dev/null 2>&1; then
    echo "DTrace or PCP Python bindings are unavailable"
    exit 2
fi

tmpdir=$(mktemp -d)
cleanup() { rm -rf "$tmpdir"; }
trap cleanup EXIT

cat >"$tmpdir/test.py" <<'EOF'
#!/usr/bin/env python3
import importlib.machinery
import importlib.util
import time

loader = importlib.machinery.SourceFileLoader("pmdadtrace", "pcp/pmdadtrace.python")
spec = importlib.util.spec_from_loader("pmdadtrace", loader)
pmdadtrace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pmdadtrace)

created = []
script = pmdadtrace.ManagedDTraceScript(
    "tick_test", "profile:::tick-1s /$1 == 1/ { @ticks = count(); }", False,
    {"quiet": True}, ".", None, None, [], ["1"], 0,
    print,
)
script._data_callbacks = {
    "create_metric": lambda entry: created.append(("metric", entry.metric)),
    "create_instance": lambda entry: created.append(
        ("instance", entry.metric, entry.instance)
    ),
    "update_instance": lambda entry: None,
    "remove_instance": lambda entry: None,
    "refresh_metrics": lambda: None,
}

ok, error = script.start()
if not ok:
    raise SystemExit(f"unable to start ManagedDTraceScript: {error}")
time.sleep(15)
script.stop()

entries = script.latest_aggregations()
if script.state() == "error":
    raise SystemExit(f"ManagedDTraceScript failed: {script.last_error()}")
if not any(entry.metric.endswith(".ticks") for entry in entries.values()):
    raise SystemExit(f"tick aggregation was not published: {entries}")
if not any(item[0] == "instance" for item in created):
    raise SystemExit(f"tick metric instance was not created: {created}")
EOF

chmod +x "$tmpdir/test.py"
timeout 60 "$DTRACE_PYTHON" "$tmpdir/test.py"
