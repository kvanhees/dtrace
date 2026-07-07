#!/bin/bash
#
# Oracle Linux DTrace.
# Copyright (c) 2026, Oracle and/or its affiliates. All rights reserved.
# Licensed under the Universal Permissive License v 1.0 as shown at
# http://oss.oracle.com/licenses/upl.
#
# ASSERTION: D library search paths remain independent from userspace module
# search paths used by system-wide uprobes.
#

if [ $# != 1 ]; then
	echo expected one argument: '<'dtrace-path'>'
	exit 2
fi

dtrace=$1
DIRNAME="$tmpdir/uprobe-dlib-path.$$.$RANDOM"
mkdir -p "$DIRNAME/dlib" "$DIRNAME/userlib"
cd "$DIRNAME" || exit 1

mod="libswpathsplit_$$.so"

cat > dlib/uprobe_dlib_path.d <<'EOF'
inline int UPROBE_DLIB_PATH_MAGIC = 31337;
EOF

cat > probe.c <<'EOF'
__attribute__((noinline, visibility("default")))
void
pathsplit_probe(void)
{
}
EOF

${CC:-cc} $test_cppflags -fPIC -shared -o "userlib/$mod" probe.c || exit 1

if ! "$dtrace" $dt_flags -L"$PWD/dlib" -e -n \
    'BEGIN { trace(UPROBE_DLIB_PATH_MAGIC); exit(0); }' \
    > dtrace.out 2> dtrace.err; then
	echo "ERROR: -L no longer loads D libraries"
	cat dtrace.err
	exit 1
fi

if ! LD_LIBRARY_PATH="$PWD/userlib" "$dtrace" $dt_flags -L"$PWD/dlib" \
    -e -n "uprobe:$mod:pathsplit_probe:entry" \
    > dtrace.out 2> dtrace.err; then
	echo "ERROR: LD_LIBRARY_PATH userspace module lookup failed with -L present"
	cat dtrace.err
	exit 1
fi

sys_path=${PATH:-/usr/bin:/bin}
if LD_LIBRARY_PATH= PATH="$sys_path" "$dtrace" $dt_flags -L"$PWD/userlib" \
    -e -n "uprobe:$mod:pathsplit_probe:entry" \
    > dtrace.out 2> dtrace.err; then
	echo "ERROR: -L was incorrectly used as a userspace module search path"
	exit 1
fi

echo success
exit 0
