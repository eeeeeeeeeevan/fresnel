# xploit: title=banner
# description=grab banner from internal ip:port via kernel socket
# args=ip,port

def main(sess, ip, port):
	out = sess.send(f"@send {ip} {port} 00")
	if out.strip():
		print(f"{ip}:{port}: {out[:200]}")
	else:
		print(f"{ip}:{port} no response")
