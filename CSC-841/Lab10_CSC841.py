from scapy.all import *
import random, time, sqlite3
from datetime import datetime

# if connection older than 60secs, remove it

def init_databse():

	db = sqlite3.connect(':memory:')
	cur = db.cursor()
	sql_cmd = "CREATE TABLE nat_connections (source_ip text, dest_ip text, source_port int, nat_port int, protocol text, time int)"
	cur.execute(sql_cmd)
	db.commit()
	return db

def stale_connections():

	db = sqlite3.connect(':memory:')
	cur = db.cursor()
	cur.execute('SELECT * FROM nat_connections ORDER BY time DESC')
	nat_connections = cur.fetchall()

	timestamp = time.mktime(datetime.now().timetuple())

	for nat_connection in nat_connections:
		if timestamp - nat_connection[5] > 60:
			sql = 'DELETE FROM nat_connections WHERE time ?'
			cur.execute(sql, (nat_connection[5],))
			conn.commit

	return

def nat_internal(packet):

#	print(packet.getlayer(Ether).src)

	if packet.haslayer(IP):

		timestamp = time.mktime(datetime.now().timetuple())

		# prevent NATing of host traffic, local addrs, etc...

		for ip in IGNORED:
#			if ip in packet.getlayer(IP).src or packet.getlayer(IP).dst:
#				return
			if packet.getlayer(IP).src == packet.getlayer(IP).dst:
				return

		# get layer type... TCP, UDP, ICMP...

		layer = packet.payload.layers()[1]
		layer = str(layer).split('.')[-1][:-2]

		if layer in SUPPORTED_LAYERS:

			source_ip = packet.getlayer(IP).src
			dest_ip = packet.getlayer(IP).dst

			packet.getlayer(IP).src = EXTERNAL_IP

			if layer == "TCP":

				source_port = packet.getlayer(layer).sport
				dest_port = packet.getlayer(layer).dport
				nat_port = random.randint(MIN_PORT, MAX_PORT)
				protocol = layer

				# nat_connections (source_ip text, dest_ip text, source_port int, nat_port int, protocol text, time int)

				cur = db.cursor()
				sql = 'SELECT * FROM nat_connections WHERE protocol ? AND dest_ip ? AND source_port = ? ORDER BY time DESC'
				cur.execute(sql, (protocol, dest_ip, source_port,))

				nat_connection = cur.fetchone()

				if nat_connection:
					if timestamp - nat_connection[5] < 60:
						nat_port = nat_entry[3]
					else:
						nat_port = random.randint(MIN_PORT, MAX_PORT)
					if packet.getlayer(IP).src == nat_connection[1]:
						if packet.getlayer(IP).dst == nat_connection[0]:
							return

				packet.getlayer(layer).sport = nat_port
				del packet.getlayer(layer).chksum

				print("TCP")

			elif layer == "UDP":

				source_port = packet.getlayer(layer).sport
				dest_port = packet.getlayer(layer).dport
				nat_port = random.randint(MIN_PORT, MAX_PORT)
				protocol = layer

				packet.getlayer(layer).sport = nat_port
				del packet.getlayer(layer).chksum

				print("UDP")

			elif layer == "ICMP":

				source_port = packet.getlayer(layer).type
				dest_port = packet.getlayer(layer).seq
				nat_port = packet.getlayer(layer).seq
				protocol = layer

				print("ICMP")

			else:

				pass

			send(packet.getlayer(IP), iface=EXTERNAL_IF, verbose=0)

			# tried using lists, but global inheritance didn't work... switched to dbs
			# connection = (nat_port, protocol, source_ip, source_port, dest_ip, dest_port, timestamp)
			# CONNECTIONS = CONNECTIONS.append(connection)

			cur = db.cursor()
			sql = 'INSERT INTO nat_connections VALUES (?, ?, ?, ?, ?, ?)'
			cur.execute(sql, (source_ip, dest_ip, source_port, nat_port, protocol, timestamp))
			db.commit()

			print("{} Rule Added! src {}:{}, dst {}:{}, nat {}:{}".format(protocol, source_ip, source_port, dest_ip, dest_port, EXTERNAL_IP, nat_port))

		else:

			print("Unsupported layer!")
			return

	return

def nat_external(packet):


#	print(packet.getlayer(Ether).src)

	if packet.haslayer(IP):

		# get current time as of pkt processing

		timestamp = time.mktime(datetime.now().timetuple())

		# get layer type... TCP, UDP, ICMP...

		layer = packet.payload.layers()[1]
		layer = str(layer).split('.')[-1][:-2]

		if layer in SUPPORTED_LAYERS:

			source_ip = packet.getlayer(IP).src
			dest_ip = packet.getlayer(IP).dst

			# grab info for NAT entry checking

			if "TCP" in layer:

				protocol = layer
				source_port = packet.getlayer(TCP).sport
				dest_port = packet.getlayer(TCP).dport
				del packet.getlayer(TCP).chksum

			elif "UDP" in layer:

				protocol = layer
				source_port = packet.getlayer(UDP).sport
				dest_port = packet.getlayer(UDP).dport
				del packet.getlayer(UDP).chksum

			elif "ICMP" in layer:

				protocol = layer
				source_port = packet.getlayer(ICMP).type
				dest_port = packet.getlayer(ICMP).seq

			else:

				return

			# check all NAT connections for existing entry, kill if not

			cur = db.cursor()
			sql = 'SELECT * FROM nat_connections WHERE protocol = ? AND nat_port = ? ORDER BY time DESC'
			cur.execute(sql, (protocol, dest_port))
			nat_connection = cur.fetchone()

			if nat_connection:

				internal_src = nat_connection[0]
				internal_src_prt = nat_connection[2]

				packet.getlayer(IP).dst = internal_src

				if layer in ("TCP", "UDP"):
					packet.getlayer(layer).dport = internal_src_prt
				
				del packet.getlayer(IP).chksum

				send(packet.getlayer(IP), iface=INTERNAL_IF, verbose=0)

				print("{} Rule Existing! src {}:{}, dst {}:{}, nat {}:{}".format(protocol, source_ip, source_port, dest_ip, dest_port, EXTERNAL_IP, nat_port))

			else:

				pass

	return

def nat_process(packet):

	db = sqlite3.connect(':memory:')

	# remove old nat connections

	#stale_connections()

	if packet.sniffed_on == EXTERNAL_IF:

		# if pkt external, process w/ nat_external()

		nat_external(packet)

	else:

		# else, process w/ nat_internal()

		nat_internal(packet)

if __name__ =='__main__':

	global GW
	global INTERNAL_IF
	global EXTERNAL_IF
	global INTERNAL_IP
	global EXTERNAL_IP
	global IGNORED
	global MIN_PORT
	global MAX_PORT
	global SUPPORTED_LAYERS

	# ['lo', 'ens160', 'ens192']

	INTERNAL_IF = 'ens192'
	EXTERNAL_IF = 'ens160'

	# grab gateway, internal, and external addrs

	GW = conf.route.route("0.0.0.0")[2]
	INTERNAL_IP = get_if_addr(INTERNAL_IF)
	EXTERNAL_IP = get_if_addr(EXTERNAL_IF)

	# IPs that should be ignored when routing

	IGNORED = (EXTERNAL_IP, INTERNAL_IP, "127.0.0.1", "0.0.0.0")

	# grab available port range for host
	with open('/proc/sys/net/ipv4/ip_local_port_range') as f:
		ports = f.read().split('\t')
		ports[1] = ports[1][:-1]

	MIN_PORT = ports[0]
	MAX_PORT = ports[1]

	SUPPORTED_LAYERS = [ "TCP", "UDP", "ICMP"]

	db = init_databse()

	# sniff internal/external interfaces, redirect using nat_process()

	print("Starting packet redirection...")
	sniff(iface=[INTERNAL_IF, EXTERNAL_IF], prn=nat_process, store=0)