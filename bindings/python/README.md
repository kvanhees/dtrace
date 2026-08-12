# Python bindings for libdtrace

This directory contains Python bindings for the `libdtrace` consumer API. The
extension allows Python applications to compile D programs, enable and control
tracing, and inspect aggregation results (including associative arrays) without
shelling out to the `dtrace` CLI.

## Requirements

- Python 3.6 or newer
- libdtrace
- A working C compiler toolchain and Python development headers

## Building and installing

```bash
# Build dtrace first (from repository root)
$ make
$ sudo make install
```

Alternatively you can install using pip:

```
# Install the bindings into your current Python environment
$ cd bindings/python
$ python3 -m pip install --upgrade build
$ python3 -m pip install -e .
```

## Quick start

```python
from dtrace import DTraceSession

program = """
#pragma D option quiet
syscall::open*:entry
{
    @counts[execname] = count();
}
"""

with DTraceSession() as dt:
    compiled = dt.compile(program)
    dt.enable(compiled)
    dt.go()
    # ... run workload here ...
    dt.work()
    dt.agg_snap()
    for entry in dt.agg_walk():
        print(entry["keys"], entry["samples"], entry["value"])
```

## API Guide

### Sessions and lifecycle

`dtrace.DTraceSession` is the entry point. Sessions implement the context
manager protocol so the recommended pattern is:

```python
from dtrace import DTraceSession

with DTraceSession() as dt:
    ...
```

Upon construction the binding calls `dtrace_open()`/`dtrace_init()` and installs
its default buffer sizing (`aggsize`/`bufsize`). The session must remain open
for the lifetime of any compiled programs or grabbed processes. If you create a
session without a context manager, remember to call `close()` when finished.

Use `setopt(option, value=None)` to tune libdtrace options before enabling a
program. Any value is converted to a string; passing `None` clears an option.

### Compiling and enabling programs

`compile(program, cflags=0, argv=None, spec=DTRACE_PROBESPEC_NAME)` wraps
`dtrace_program_strcompile()` and returns a `DTraceProgram` object bound to the
session. The optional `argv` sequence is encoded to UTF-8 and supplied as the
compiler argument vector. Each compiled program must be passed into
`enable(program)` which returns a dictionary summarising the probe attributes
(`aggregations`, `recgens`, `matches`, `speculations`, `descattr`, `stmtattr`).

### Running the tracing loop

Invoke `go(cflags=0)` to transition the session into a running state. Typical
loops alternate between driving the consumer and handling results:

```python
dt.go()
while dt.status() == dtrace.DTRACE_STATUS_OKAY:
    status, probes = dt.work(return_records=True)
    # inspect `probes`, drive workload, or break once done

dt.stop()
```

`status()` wraps `dtrace_status()` but also reports synthetic values tracked by
the binding when the traced processes exit or when an `exit()` action fires.
`go()` may be followed by `update()` to re-scan loaded kernel modules if probes
are added dynamically, and `stop()` can be called manually to halt collection.

`work(return_records=False)` executes `dtrace_work()`. Its return value is a
`(status, probes)` tuple where `status` is one of the exported
`DTRACE_STATUS_*` constants and `probes` is a list of dictionaries describing
each consumed probe firing. By default only the status is returned; passing
`return_records=True` captures full probe metadata plus a list of record
descriptors (size, action, alignment, raw bytes, and any libdtrace metadata).
If you are just dealing with aggregations, there is no need to return records;
aggregation snapshot walk is all you will need.

### Aggregations and snapshots

`agg_snap()` issues `dtrace_aggregate_snap()` to freeze the aggregation buffer;
`agg_walk(mode="values")` walks that snapshot using the selected ordering mode
(`"default"`, `"values"`, `"valrev"`, `"keys"`, etc.) and returns a list of
entries. Each entry is a dictionary with:

- `keys`: ordered list of aggregation keys.
- `samples`: raw sample count collected for the entry.
- `normal`: the normalisation factor applied to the aggregate (1 if unused).
- `value`: the converted aggregate value.
- `raw`: the raw byte payload backing `value`.

Stacks produced by `stack()`, `ustack()`, or `jstack()` actions are converted to
Python lists ordered from root to leaf (the binding inserts the deepest frame at
the end of the list). Quantization actions (`quantize`, `lquantize`,
`llquantize`) are represented as dictionaries mapping bucket identifiers to
counts, already divided by any aggregation normaliser. Buckets use the same
numeric semantics as libdtrace (e.g., powers-of-two for `quantize` or explicit
boundaries for `lquantize`).

The raw data remains available in `entry["raw"]` when you need the original
binary layout, for example to re-run libdtrace helpers.

### Process control helpers

The binding exposes libdtrace process control for coordinated tracing:

- `proc_create(args)` forks a new traced process, using the provided argument
  list. It returns a `DTraceProc` wrapper that keeps the underlying handle.
- `proc_grab_pid(pid)` attaches to an existing process by pid.
- `proc_continue(proc)` resumes a previously created or grabbed process and
  marks it as live so the session can detect when all traced processes exit.
- `proc_release(proc)` releases libdtrace’s hold on the process once finished.

`DTraceProc` currently exposes `getpid()` to query the grabbed pid. The session
tracks how many processes are created or grabbed so that when the last one
exits the consumer loop observes `DTRACE_STATUS_EXITED` and stops automatically.

### Detecting completion or stop conditions

The binding raises `DTraceError` when libdtrace reports failures. To detect a
graceful stop, inspect either `status()` or the first element of the tuple
returned by `work()`. When libdtrace reports `DTRACE_STATUS_STOPPED` or
`DTRACE_STATUS_FILLED`, you can drain remaining data, call `agg_snap()`/
`agg_walk()` if needed, and then `close()` the session. A session observing a
`DTRACEACT_EXIT` record records the exit status internally, and a stopped state
is reported even if `dtrace_status()` still returns `DTRACE_STATUS_OKAY`, so
applications can rely on `status()` reflecting exits from traced processes.

When running under a context manager, exiting the `with` block closes the
session automatically, regardless of whether tracing finished normally or due
to `stop()`.

