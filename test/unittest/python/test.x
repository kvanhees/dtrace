#!/bin/bash
#
#
# Oracle Linux DTrace.
# Copyright (c) 2026, Oracle and/or its affiliates. All rights reserved.
# Licensed under the Universal Permissive License v 1.0 as shown at
# http://oss.oracle.com/licenses/upl.
#
# Skip the Python binding tests when the bindings were not built or installed.
#

if ! "$DTRACE_PYTHON" -c 'import dtrace' >/dev/null 2>&1; then
	echo "Python bindings are unavailable"
	exit 2
fi

exit 0
