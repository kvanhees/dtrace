#!/bin/bash
#
# Verify Python aggregation-key decoding for zero, string, numeric, and
# mixed key tuples.
#

if [ $# -ne 1 ]; then
	echo "usage: $0 <dtrace>" >&2
	exit 2
fi

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

cat >"$tmpdir/script.py" <<'EOF'
#!/usr/bin/env python3
from dtrace import DTraceSession

program = r'''
BEGIN
{
	@zero = count();
	@string["alpha"] = count();
	@numeric[17] = count();
	@mixed["irq", 17] = count();
}

fbt::schedule:entry
{
	@symkey[sym(caller)] = count();
	@modkey[mod(caller)] = count();
	@stackkey[stack()] = count();
}

pid$target::getopt*:entry
{
	@usymkey[usym(ucaller)] = count();
	@umodkey[umod(ucaller)] = count();
}

profile:::tick-5s
{
	exit(0);
}
'''

with DTraceSession() as session:
    from dtrace import DTRACE_C_ZDEFS
    target = session.proc_create(["/bin/sleep", "2"])
    program_obj = session.compile(program, cflags=DTRACE_C_ZDEFS)
    session.enable(program_obj)
    session.go()
    session.proc_continue(target)
    import time
    time.sleep(2)
    session.proc_release(target)
    session.stop()
    session.agg_snap()
    rows = session.agg_walk()

def hashable_key(key):
    return tuple(hashable_key(item) for item in key) if isinstance(key, list) else key

seen = {
    (row["name"], tuple(hashable_key(key) for key in row["keys"]))
    for row in rows
}
expected = {
    ("zero", ()),
    ("string", (("alpha",),)),
    ("numeric", ((17,),)),
    ("mixed", (("irq",), (17,))),
}
missing = expected - seen
if missing:
    raise SystemExit(f"missing aggregation keys: {missing}; rows={rows}")
print(f"rows={rows}")

for name in ("symkey", "modkey", "usymkey", "umodkey"):
    matching = [row for row in rows if row["name"] == name]
    if not matching or not isinstance(matching[0]["keys"][0], list):
        raise SystemExit(f"symbolic key was not formatted: {name}: {matching}")
stack_rows = [row for row in rows if row["name"] == "stackkey"]
if not stack_rows or not isinstance(stack_rows[0]["keys"][0], list):
    raise SystemExit(f"stack key was not formatted: {stack_rows}")
EOF

chmod +x "$tmpdir/script.py"
"$DTRACE_PYTHON" "$tmpdir/script.py"
