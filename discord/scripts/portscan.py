# xploit: title=aportscan
# description: ACTIVE port scan an internal ip via kernel sockets. this may be risky.
# args: ip,ports

def main(sess, ip, ports):
	if "-" in ports:
		lo, hi = ports.split("-")
	else:
		lo = hi = ports
	for p in range(int(lo), int(hi)+1):
		out = sess.send(f"@probe {ip} {p}")
		if "open" in out:
			print(f"OPEN: {ip}:{p}")
