#!/usr/bin/python

import socket, sys, struct

shellcode = "";

if len(sys.argv) != 3:
	print "supply IP PORT"
	sys.exit(-1)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect( (sys.argv[1], int(sys.argv[2])) )

###send
message = ""
sock.sendall(message)

###recieve
data = sock.recv(10000)
print data
