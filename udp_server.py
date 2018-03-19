import sys
from socket import *

s = socket(AF_INET, SOCK_DGRAM)
s.bind(("0.0.0.0", int(sys.argv[1])))

print("Listening...")
while 1:
	msg, addr = s.recvfrom(65536)
	print("Received %d bytes from %s" % (len(msg) + 20 + 8, str(addr)))
	s.sendto(msg, addr)
