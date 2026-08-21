# SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
#
# Copyright (c) 2026, Oracle and/or its affiliates.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public
# License v2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this program.  If not, see <https://www.gnu.org/licenses/>.
#


# dtrace PMDA

This PMDA provides support to collect PCP metrics from DTrace scripts via the
libdtrace Python bindings. Scripts can be registered dynamically via
`pmstore(1)` calls and optionally autostarted from an on-disk directory when
the PMDA is launched.

# Dynamic-script authorization

Dynamic script registration is enabled only for `root` by default. To change
the policy, edit the root-owned `$PCP_PMDAS_DIR/dtrace/dtrace.conf` file:

```
[dynamic_scripts]
enabled = true
auth_enabled = true
allowed_users = root,mydtraceuser
```

When authentication is enabled, every write to `dtrace.control.*` must come
from an authenticated PCP user named in `allowed_users`. Local `pmstore`
clients are identified using their Unix UID; remote clients require PCP
authentication. Leave `auth_enabled` set to `true`: disabling it allows every
client with `pmcd` store permission to run DTrace programs with the PMDA's
privileges.

# Metrics

- `dtrace.control.*` metrics are writable strings consumed by the PMDA to
  register, unregister, start, stop, or reload scripts.  Payloads for
  `dtrace.control.register` must be JSON objects containing at least the
  `name` and `program` fields and optional `options` (libdtrace `setopt`
  key/value pairs), `autostart`, `exitonly`, `top`, `bottom`, `pid`, `command`,
  `args`, and `defines` fields. `pid` attaches
  to an existing process, while `command` is the JSON equivalent of
  `dtrace -c`: it starts a whitespace- and quote-split command under DTrace
  control. The two target fields are mutually exclusive and initialize
  `$target` before the program is compiled. `args` is an array of string operands
  supplied to the D program as positional macro arguments `$1`, `$2`, and so on.
  `defines` may be an object mapping
  macro names to values (use `null` for an unvalued macro), or an array of
  `NAME`/`NAME=VALUE` strings; it enables preprocessing and passes definitions
  to cpp.
- `dtrace.scripts.*` metrics form an instance domain over the registered
  scripts and report each script's current state, autostart flag, last error
  message, and runtime in seconds.

For example, to create a script which counts system calls that automatically
starts and collects metrics:

```
$ pmstore dtrace.control.register '{"name":"syscalls","program":"syscall:::entry { @c[probefunc] = count(); }", "autostart":true}'
dtrace.control.register old value="" new value="{"name":"syscalls","program":"syscall:::entry { @c[probefunc] = count(); }", "autostart":true}"
$ pminfo -f dtrace

dtrace.scripts.data.syscalls.c
    inst [0 or "bpf"] value 5360
    inst [1 or "access"] value 278
    inst [2 or "poll"] value 7949
    inst [3 or "close"] value 7693
    inst [4 or "mmap"] value 525
    inst [5 or "rename"] value 26
...
```

Each instance of the metric 'dtrace.scripts.data.syscalls.c' represents
the aggregation keys/values associated with aggregation '@c'.

## Quantized aggregations

`quantize()`, `lquantize()`, and `llquantize()` aggregations are exported as
histograms.  Each PCP instance is one inclusive bucket range and its value is
the DTrace count for that range.  This layout is suitable for Grafana's
pre-bucketed heatmap input.

For a quantized aggregation with keys, the key is included in the metric name,
so buckets for separate keys remain distinct.  For example:

```d
@iowait["device_mapper"] = quantize(args[0]);
```

produces `dtrace.scripts.data.<script>.iowait.device_mapper`, with instances
such as `512-1023` and `8388608-16777215`.  A quantized aggregation with no
keys instead uses `dtrace.scripts.data.<script>.<aggregation>` and the same
range instances.

The range scheme follows the DTrace aggregation action:

- `quantize()` uses power-of-two ranges: `0-0`, `1-1`, `2-3`, `4-7`, and so
  on. Negative buckets are represented by their inclusive negative ranges.
- `lquantize()` uses the program's declared base and step; for example a
  bucket beginning at `20` with a step of `10` is named `20-29`. Its underflow
  and overflow buckets are named with `-inf` and `inf` endpoints.
- `llquantize()` uses the factor, magnitude range, and steps declared by the
  program to generate its log-linear ranges, such as `1000-1999` and
  `2000-3999`.

Only buckets with non-zero DTrace counts are exported.  A bucket can therefore
disappear from the PCP instance domain when its count is zero on a later
snapshot.

Script names must map uniquely to PCP metric prefixes.  The PMDA rejects a
registration, or skips an autostart script, when its sanitized name collides
with an existing script name.  Sanitization retains ASCII letters, digits,
`_`, `+`, `.`, `;`, `:`, and backticks; each run of other characters is replaced
with `_`, leading and trailing underscores are removed, and an empty result is
named `value`.

Integer scalar aggregations use 64-bit PCP metric types, preserving exact
values.  `count` and `stddev` use unsigned `PM_TYPE_U64`; `sum`, `min`, and
`max` use signed `PM_TYPE_64`.  Floating aggregations such as `avg` use
`PM_TYPE_DOUBLE`.

Aggregation names beginning with `__` are reserved for internal DTrace use.
They are still available to the script, but the PMDA does not publish them as
PCP metrics.  For example, `@__scratch = count();` is intentionally hidden,
while `@scratch = count();` is exported.

To target a running process, supply its PID and use `$target` in the program:

```
$ pmstore dtrace.control.register '{"name":"target_reads","pid":1234,"program":"pid$target::read:entry { @reads = count(); }","autostart":true}'
```

To create a target process, use `command` (the JSON equivalent of `dtrace -c`):

```
$ pmstore dtrace.control.register '{"name":"sleep","command":"/bin/sleep 30","program":"pid$target::sleep:entry { @calls = count(); }","autostart":true}'
```

The register payload supports the following keys.  `name` and `program` are
required; the other keys are optional:

```json
{
  "name": "example",
  "program": "syscall:::entry { @calls[PROBEFUNC] = count(); }",
  "autostart": true,
  "exitonly": true,
  "top": 10,
  "separator": ";",
  "options": {
    "bufsize": "4m",
    "aggrate": "1s",
    "quiet": true
  },
  "compile": {
    "zdefs": true
  },
  "args": ["1234", "read"],
  "defines": {
    "SAMPLE_RATE": 97,
    "BUILD_LABEL": "production",
    "FEATURE_ENABLED": null
  }
}
```

For example, a program containing `/pid == $1/` can be registered with
`"args": ["1234"]`. For a string value, use `$$1` in the D program to force
string-token interpretation. `args` is unrelated to `command`, whose operands
are passed to the target process created by DTrace.

`exitonly` defaults to `false`.  When enabled, the PMDA does not
snapshot or walk aggregations while the script is running; it publishes the
final aggregation view only after the DTrace session terminates or is stopped.
This is useful with, for example, `END { trunc(@stacks, 10); }`, so that only
the final top ten stacks are exported.  It does not limit DTrace aggregation
memory while the script runs; use the DTrace `aggsize` option for that.

`top` and `bottom` are mutually exclusive optional non-negative limits applied
independently to each aggregation on every PMDA update. They publish the
highest- or lowest-valued aggregation entries respectively. Entries outside the
selected limit are removed from PCP. The limits apply to aggregation entries,
not individual quantization buckets, and do not limit DTrace aggregation
memory.

The `compile` object controls compile-time flags.  `zdefs` is equivalent to
the `dtrace -Z` option and allows probe descriptions that match no probes.

`defines` enables the C preprocessor and accepts either an object, as above,
or an array of `NAME`/`NAME=VALUE` strings:

```json
{
  "name": "conditional",
  "program": "BEGIN { trace(SAMPLE_RATE); }",
  "defines": ["SAMPLE_RATE=10", "FEATURE_ENABLED"]
}
```

For target selection, specify exactly one of `pid` or `command`:

```json
{
  "name": "existing-process",
  "pid": 1234,
  "program": "pid$target:::entry { @calls = count(); }"
}
```

```json
{
  "name": "new-process",
  "command": "/usr/bin/sleep 30",
  "program": "pid$target:::entry { @calls = count(); }"
}
```

To stop and unregister the script

```
$ pmstore dtrace.control.unregister syscalls
```

or to simply stop (while retaining metrics):

```
$ pmstore dtrace.control.stop syscalls
```

Stopping is asynchronous: the store request acknowledges once shutdown has
been requested.  Check `dtrace.scripts.state` until it reports `stopped` if
you need to wait for DTrace cleanup to finish.

# Profiling

It is possible to profile using stack keys, and the instance names
that represent the call stacks can be made to be compatible with
the PCP Flame Graph panel's expected comma-delimited stack format of
`function1,function2`. To do this,
the default "." key separator that is used to concatenate key values
must be overridden with a `,`, i.e.

```
"separator":";"
```

Stack frames are normalized to `module:function` form and their DTrace
`+0x...` offsets are removed before the instance name is generated.

For example:

```
$ pmstore dtrace.control.register '{"name":"profile","program":"profile:::profile-97 { @profile[stack()] = count(); }", "autostart":true, "separator":","}'
dtrace.control.register old value="" new value="{"name":"profile","program":"profile:::profile-97 { @profile[stack()] = count(); }", "autostart":true}"

$ pminfo -f dtrace

dtrace.scripts.data.profile.profile
    inst [0 or "vmlinux:entry_SYSCALL_64_after_hwframe,vmlinux:do_syscall_64,vmlinux:x64_sys_call,vmlinux:__x64_sys_read,vmlinux:ksys_read,vmlinux:vfs_read,vmlinux:seq_read,vmlinux:seq_read_iter,vmlinux:show_smap,vmlinux:__show_smap,vmlinux:seq_put_decimal_ull_width,vmlinux:strlen"] value 1
    inst [1 or "vmlinux:entry_SYSCALL_64_after_hwframe,vmlinux:__audit_syscall_exit"] value 1
...
```

# Autostart

Scripts placed under `$PCP_PMDAS_DIR/dtrace/autostart/` with a `.d`
extension are started automatically when the PMDA becomes ready. Optional
metadata can be provided by placing a matching `.json` file alongside the `.d`
file; its contents should mirror the register payload structure (for example,
to define libdtrace options).

Examples are provided:

- `examples/irq_times.*` - measure min, max, and average IRQ/softirq
  handler execution time
- `examples/syscall_counts.*` - count syscalls by name
- `examples/packet_drop_reasons.*` - count packets dropped by drop reason
  string

To run, copy .d and .json files under autostart prior to install.
Metrics then appear under dtrace.scripts.data.syscall_counts.counts`,
  with one instance per aggregation key (in this case syscall name):

```
# pminfo -f dtrace.scripts.data.syscall_counts.counts

dtrace.scripts.data.syscall_counts.counts
    inst [0 or "mmap"] value 7959
    inst [1 or "futex"] value 574830
    inst [2 or "exit"] value 202
    inst [3 or "dup2"] value 168
    inst [4 or "times"] value 575
...
```

# Installation

First ensure that dtrace and its associated python bindings are installed
and running.

```
# cd $PCP_PMDAS_DIR/dtrace
```

Check there is no clash in the Performance Metrics domain defined in
as `domain=` in `Install`. If there is a clash, edit the file.

Then run

```
   # sudo ./Install
```

Verify PMDA Is running

```
   # pminfo -f dtrace
```

# De-installation

```
# cd $PCP_PMDAS_DIR/dtrace
# sudo ./Remove
```

# Troubleshooting

 + Ensure the DTrace Python bindings are installed (`python3 -c 'import dtrace'`).
 + Confirm the PMDA log (`$PCP_LOG_DIR/pmcd/dtrace.log`) for script errors.
 + When debugging autostart scripts, temporarily move files out of
   `autostart/` to disable them.
