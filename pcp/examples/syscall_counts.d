/* Count system call invocations per syscall name */

syscall:::entry
{
    @counts[probefunc] = count();
}

END
{
    printf("Tracing stopped for syscall_counts (see PCP metrics for live data)\n");
}
