#!/usr/sbin/dtrace -s

/* Count avg/max/min irq/softirq times */

BEGIN
{
	softirq_names[0] = "hi";
	softirq_names[1] = "timer";
	softirq_names[2] = "net_tx";
	softirq_names[3] = "net_rx";
	softirq_names[4] = "block";
	softirq_names[5] = "irq_poll";
	softirq_names[6] = "tasklet";
	softirq_names[7] = "sched";
	softirq_names[8] = "hrtimer";
	softirq_names[9] = "rcu";
	softirq_max = 9;
}

sdt:::irq_handler_entry,
sdt:::softirq_entry
{
	self->start = timestamp;
}

rawtp:irq::irq_handler_entry
{
	self->start = timestamp;
	self->name = ((struct irqaction *)arg1)->name;
}

sdt:::irq_handler_exit
/self->start/
{
	this->t = timestamp;
	@irq_avg_time_ns[stringof(self->name)] = avg(this->t - self->start);
	@irq_max_time_ns[stringof(self->name)] = max(this->t - self->start);
	@irq_min_time_ns[stringof(self->name)] = min(this->t - self->start);
	self->start = 0;
	self->name = 0;
}

sdt:::softirq_exit
/self->start && arg0 <= softirq_max /
{
        this->t = timestamp;
        @softirq_avg_time_ns[softirq_names[arg0]] = avg(this->t - self->start);
        @softirq_max_time_ns[softirq_names[arg0]] = max(this->t - self->start);
        @softirq_min_time_ns[softirq_names[arg0]] = min(this->t - self->start);
        self->start = 0;
}
