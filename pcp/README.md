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
  key/value pairs), `autostart`, `pid`, `command`, and `defines` fields. `pid` attaches
  to an existing process, while `command` is the JSON equivalent of
  `dtrace -c`: it starts a whitespace- and quote-split command under DTrace
  control. The two target fields are mutually exclusive and initialize
  `$target` before the program is compiled. `defines` may be an object mapping
  macro names to values (use `null` for an unvalued macro), or an array of
  `NAME`/`NAME=VALUE` strings; it enables preprocessing and passes definitions
  to cpp.
- `dtrace.scripts.*` metrics form an instance domain over the registered
  scripts and report each script's current state, autostart flag, last error
  message, and runtime in seconds.

For example, to create a script which counts system calls that automatically
starts and collects metrics:

```
$ pmstore dtrace.control.register '{"name":"syscalls","program":"syscall:::entry { @c[probefunc] = count(); }", "autostart":"true"}'
dtrace.control.register old value="" new value="{"name":"syscalls","program":"syscall:::entry { @c[probefunc] = count(); }", "autostart":"true"}"
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
  "separator": ";",
  "options": {
    "bufsize": "4m",
    "aggrate": "1s",
    "quiet": true
  },
  "compile": {
    "zdefs": true
  },
  "defines": {
    "SAMPLE_RATE": 97,
    "BUILD_LABEL": "production",
    "FEATURE_ENABLED": null
  }
}
```

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

# Profiling

It is possible to profile using stack keys, and the instance names
that represent the call stacks can be made to be compatible with
the expected flamegraph format of `function1;function2`.  To do this,
the default "." key separator that is used to concatenate key values
must be overridden with a ";" , i.e.

```
"separator":";"
```

For example:

```
$ pmstore dtrace.control.register '{"name":"profile","program":"profile:::profile-97 { @profile[stack()] = count(); }", "autostart":"true", "separator":";"}'
dtrace.control.register old value="" new value="{"name":"profile","program":"profile:::profile-97 { @profile[stack()] = count(); }", "autostart":"true"}"

$ pminfo -f dtrace

dtrace.scripts.data.profile.profile
    inst [0 or "vmlinux`entry_SYSCALL_64_after_hwframe+0x76;vmlinux`do_syscall_64+0xb1;vmlinux`x64_sys_call+0x1cc6;vmlinux`__x64_sys_read+0x1d;vmlinux`ksys_read+0x6d;vmlinux`vfs_read+0xbf;vmlinux`seq_read+0xf9;vmlinux`seq_read_iter+0x2c6;vmlinux`show_smap+0xe7;vmlinux`__show_smap+0x1d1;vmlinux`seq_put_decimal_ull_width+0xae;vmlinux`strlen+0xc"] value 1
    inst [1 or "vmlinux`entry_SYSCALL_64_after_hwframe+0x76;vmlinux`__audit_syscall_exit+0xa"] value 1
...
```

# Autostart

Scripts placed under `$PCP_PMDAS_DIR/dtrace/autostart.d/` with a `.d`
extension are started automatically when the PMDA becomes ready. Optional
metadata can be provided by placing a matching `.json` file alongside the `.d`
file; its contents should mirror the register payload structure (for example,
to define libdtrace options).

An example pair is provided:

- `examples/syscall_counts.d` – counts system call entries by name.
- `examples/syscall_counts.json` – marks the script for autostart and
  enlarges the libdtrace buffers to reduce drops under load.
- metrics then appear under dtrace.scripts.data.syscall_counts.counts`,
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
   `autostart.d/` to disable them.
