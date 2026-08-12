import os
import subprocess
from pathlib import Path
from typing import List

from setuptools import Extension, setup

ROOT = Path(__file__).resolve().parents[2]
OBJDIR = Path(os.environ.get("DTRACE_OBJDIR", ROOT / "build"))

def project_version() -> str:
    """Return the DTrace version used by the top-level build."""
    version = os.environ.get("DTRACE_VERSION")
    if version:
        return version

    return subprocess.check_output(
        [str(ROOT / "libdtrace" / "mkvers"), "-vcurrent=t",
         str(ROOT / "libdtrace" / "versions.list")],
        universal_newlines=True,
    ).strip()

# Default include directories assume an in-tree build of libdtrace.
default_include_dirs = [
    str(ROOT / "include"),
    str(ROOT / "libdtrace"),
    str(ROOT / "uts" / "common"),
    str(ROOT / "include" / "dtrace"),
    str(OBJDIR),
]

default_library_dirs: List[str] = []
if OBJDIR.exists():
    default_library_dirs.append(str(OBJDIR))

extra_include = os.environ.get("DTRACE_INCLUDE_DIRS")
if extra_include:
    default_include_dirs.extend(p for p in extra_include.split(os.pathsep) if p)

extra_library = os.environ.get("DTRACE_LIBRARY_DIRS")
if extra_library:
    default_library_dirs.extend(p for p in extra_library.split(os.pathsep) if p)

extra_link_args = os.environ.get("DTRACE_EXTRA_LINK_ARGS", "").split()
extra_compile_args = os.environ.get("DTRACE_EXTRA_COMPILE_ARGS", "").split()

ext_modules = [
    Extension(
        "dtrace",
        sources=["src/pydtrace_module.c"],
        include_dirs=default_include_dirs,
        libraries=["dtrace"],
        library_dirs=default_library_dirs,
        extra_compile_args=extra_compile_args,
        extra_link_args=extra_link_args,
    )
]

setup(
    name="dtrace",
    version=project_version(),
    description="Python bindings for libdtrace",
    author="Oracle Linux DTrace maintainers",
    license="UPL",
    python_requires=">=3.6",
    ext_modules=ext_modules,
)
