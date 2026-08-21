#!/usr/sbin/dtrace -s

/* Count system call invocations per syscall name */

syscall:::entry
{
    @counts[probefunc] = count();
}
