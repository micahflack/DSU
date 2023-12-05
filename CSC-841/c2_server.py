import socket

HOST = "172.18.3.58"
PORT = 8080

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
	s.bind((HOST, PORT))
	s.listen()
	conn, addr = s.accept()
	with conn:
		print(f"Connected by {addr}")
		while True:
			data = conn.recv(1024)
			if not data:
				break
			print(data.decode('utf-8'))
#			conn.sendall(b"Msg received: " + data)
