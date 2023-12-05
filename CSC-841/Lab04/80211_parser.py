# CSC-841 Cyber Operations II - Lab 04 802.11 Parsing; Micah Flack

import warnings
warnings.filterwarnings("ignore")

# ^ ignore deprecation warnigns from importing scapy library

import sys
import time
from scapy.all import *

IFACE = "wlan0"

devices = set()

def PacketHandler(pkt):
        if pkt.haslayer(Dot11):
            dot11_layer = pkt.getlayer(Dot11)
            if dot11_layer.haslayer(Dot11Beacon):
                if dot11_layer.addr2 and (dot11_layer.addr not in devices):
                    devices.add(dot11_layer.addr2)
                    elt = dot11_layer.getlayer(Dot11Elt)
                    beacon = dot11_layer.getlayer(Dot11Beacon)
                    country = elt.getlayer(Dot11EltCountry)
                    auth = dot11_layer.getlayer(Dot11Auth)

                    if elt:
                        ESSID = str(elt.info.replace(b"\x00", b""), 'utf-8')
                        if ESSID == "":
                            ESSID = 'empty'

                    else:
                        ESSID = "empty"

                    if auth:
                        auth_algo = str(auth.algo, 'utf-8')
                    else:
                        auth_algo = "none"


                    timestamp = time.strftime('%H:%M:%S', time.localtime(beacon.timestamp))
                    interval = str(beacon.beacon_interval, 'utf-8')
                    country = str(country.country_string, 'utf-8')

                    print(
                    'ESSID: {:<12s}'        \
                    'BSSID: {:<20s}'        \
                    'Timestamp: {:<12s}'    \
                    'Interval: {:<12s}'     \
                    'Country: {:<12s}'      \
                    'AuthAlgo: {:<12s} \n'  \
                    ).format(
                        ESSID,
                        dot11_layer.addr2,
                        timestamp,
                        interval,
                        country,
                        auth_algo
                    )

print("~~ 802.11 Sniffer ~~")
print("PRESS CTRL+C to QUIT...")

sniff(iface=IFACE, count=0, prn=PacketHandler, monitor=True)