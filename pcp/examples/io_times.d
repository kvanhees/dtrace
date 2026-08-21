#!/usr/sbin/dtrace -Cqs

/* Provide histogram of io times, wait completion times by device. */

io:::start
{
	iostart[curthread] = timestamp;
}

io:::wait-start
{
	iowstart[curthread] = timestamp;
}

io:::done
/ iostart[curthread] /
{
	@iotime[args[1]->dev_name] = quantize((timestamp - iostart[curthread])/1000);
	iostart[curthread] = 0;
}


io:::wait-done
/ iowstart[curthread] /
{
	@iowait[args[1]->dev_name] = quantize((timestamp - iowstart[curthread])/1000);
	iowstart[curthread] = 0;
}
