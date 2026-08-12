/* Count packet drops by reason (SOCKET_CLOSE) etc */

BEGIN
{
	drop_reasons = (char **)`drop_reasons_core;
	num_core_reasons = *(size_t *)(`drop_reasons_core+sizeof(char *));
}

sdt:::kfree_skb
/arg4 < num_core_reasons /
{
	reason = stringof(drop_reasons[arg4]);
	@drops[reason] = count();
}
