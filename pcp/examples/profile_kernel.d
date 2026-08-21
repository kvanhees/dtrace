#!/usr/sbin/dtrace -Cqs

/* Profile kernel stacks for RUNTIME_MAX sec (default 1 min) */

#ifndef RUNTIME_MAX
#define RUNTIME_MAX		60
#endif

#ifndef STACKS_MAX
#define STACKS_MAX		512
#endif

BEGIN
{
	runtime = 0;
}

profile:::profile-97
{
	@kstacks[stack()] = count();
}

profile:::tick-10s
{
	runtime += 10;
}

profile:::tick-10s
/ runtime > RUNTIME_MAX /
{
	trunc(@kstacks, STACKS_MAX);
	exit(0);
}
