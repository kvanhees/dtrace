#!/usr/bin/gawk -f

NR == 1 {
	val = $1;
}

NF > 0 {
	if ($1 != val) {
		print "Output line " NR ": Expected " val ", got " $1;
		fail++;
	}
}

END {
	if (fail) {
		print fail " failures";
		exit(1);
	} else {
		print "All pointers are identical (as expected).";
		exit(0);
	}
}
