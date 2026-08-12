#!/bin/bash
#
# Oracle Linux DTrace.
# Copyright (c) 2026, Oracle and/or its affiliates. All rights reserved.
# Licensed under the Universal Permissive License v 1.0 as shown at
# http://oss.oracle.com/licenses/upl.
#
# Ensure aggregation actions return expected values.

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
BEGIN
{
    @counts = count();
    @counts = count();
    @counts = count();
    @sums = sum(100);
    @sums = sum(50);
    @sums = sum(32);
    @avgs = avg(4);
    @avgs = avg(5);
    @mins = min(100);
    @mins = min(99);
    @mins = min(101);
    @maxs = max(12);
    @maxs = max(19);
    @maxs = max(-4);
    @stddevs = stddev(5000000000);
    @stddevs = stddev(5000000100);
    @stddevs = stddev(5000000200);
    @stddevs = stddev(5000000300);
    @stddevs = stddev(5000000400);
    @stddevs = stddev(5000000500);
    @stddevs = stddev(5000000600);
    @stddevs = stddev(5000000700);
    @stddevs = stddev(5000000800);
    @stddevs = stddev(5000000900);
    @quants = quantize(1);
    @quants = quantize(2);
    @quants = quantize(1);
    @quants = quantize(3);
    @quants = quantize(128);
    @lquants = lquantize(1, 1, 10, 2);
    @lquants = lquantize(3, 1, 10, 2);
    @lquants = lquantize(1, 1, 10, 2);
    @lquants = lquantize(9, 1, 10, 2);
    @lquants = lquantize(9, 1, 10, 2);
    @lquants = lquantize(1, 1, 10, 2);
    @llquants = llquantize(1, 3, 1, 4, 3);
    @llquants = llquantize(26, 3, 1, 4, 3);
    @llquants = llquantize(2, 3, 1, 4, 3);
    @llquants = llquantize(13, 3, 1, 4, 3);
    @llquants = llquantize(6, 3, 1, 4, 3);
    @llquants = llquantize(81, 3, 1, 4, 3);
    exit(0);
}
"""

with DTraceSession() as dt:
    p = dt.compile(prog)
    dt.enable(p)
    dt.go()
    pid = Popen(["/bin/sleep", "1"]).wait()
    dt.stop()
    dt.agg_snap()
    rows = dt.agg_walk()

if not rows:
    raise SystemExit("no rows returned")

for row in rows:
    if row["name"] == "counts":
       v = int(row["value"])
       if v != 3:
           raise SystemExit(f"unexpected count value {v}")
    if row["name"] == "avgs":
       v = float(row["value"])
       if v != 4.5:
           raise SystemExit(f"unexpected avg value {v}")
    if row["name"] == "sums":
       v = int(row["value"])
       if v != 182:
           raise SystemExit(f"unexpected sum value {v}")
    if row["name"] == "mins":
       v = int(row["value"])
       if v != 99:
           raise SystemExit(f"unexpected min value {v}")
    if row["name"] == "maxs":
       v = int(row["value"])
       if v != 19:
           raise SystemExit(f"unexpected max value {v}")
    if row["name"] == "stddevs":
       v = int(row["value"])
       if v != 287:
           raise SystemExit(f"unexecpted stddev value {v}")
    if row["name"] == "quants":
       v = row["value"]
       if v != {1:2, 2:2, 128:1}:
           raise SystemExit(f"unexecpted quantize value {v}")
    if row["name"] == "lquants":
       v = row["value"]
       if v != {1:3, 3:1, 9:2}:
           raise SystemExit(f"unexecpted lquantize value {v}")
    if row["name"] == "llquants":
       v = row["value"]
       if v != {0:2, 9:1, 18:1, 27:1, 162:1}:
           raise SystemExit(f"unexecpted llquantize value {v}")

EOF

chmod +x "$tmpdir/script.d"
PATH="$tmpdir:$PATH"

$tmpdir/script.d
