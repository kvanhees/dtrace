#!/usr/bin/gawk -f

NR == 1 {
	expected = int($1);
	print "Expect " expected " bytes";
	next;
}

$1 ~ /^[0-9][0-9]*:$/ {
	sub(/  .{16}$/, "");
	got += NF - 1;

	for (i = 2; i <= NF; i++)
		not0 += ($i != "00");
}

END {
	print "Got " got " bytes";
	if (not0 == 0)
		print "All zeros - read failure?";
	else if (expected != got)
		print "Data size mismatch";
	else if (not0 < got / 4)
		print "Too many zeros - check data?";
}
