from scapy.all import *
from datetime import datetime
import sys

## This script only works on Linux systems with Scapy installed
## The script will automatically listen for unencrypted Identity Response 
## packets and save the MAC Address + User identity in a file

# Interfaces to use for scanning, they should already be in monitor mode
# (Use airmon-ng to enable monitor mode). Followed by the channel they
# should scan in.
# example: [('wlan0mon', '1'), ('wlan1mon', '6'), ('wlan2mon', '11')] 
iface = [('wlan0mon', '1'), ('wlan1mon', '6'), ('wlan2mon', '11')] 

# Filename to store mac addresses + identities, if file doesn't exist items
# will be created. If the file already exists new mac addresses that don't
# already exist in the file will be appended.
filename = "id.txt"

# Create file if not already exists
open(filename, 'a+').close()

# Set channels using iwconfig in Linux
for i in range(len(iface)):
	ret = "Error"		
	while "Error" in ret:
		ret = os.popen('iwconfig %s channel %s' % (iface[i][0], iface[i][1])).read()
		print(ret)
	iface[i] = iface[i][0]

# Function that will be called for every package to check for Request ID(Eap type 1, code 2)
def checkID(p):
	if p.haslayer(EAP) and p.getlayer(EAP).code == 2 and p.getlayer(EAP).type == 1:
		mac = p.getlayer(Dot11).addr2
		id = datetime.now().strftime("%Y-%m-%d, %H:%M:%S") + ":\t" + mac + ": " + str(p.getlayer(EAP).identity)
		
		print("\t\tFound " + id + " \t adding to " + filename)
		
		f = open(filename, 'a+')
		r = f.readlines()
		if mac not in "".join(r):
			f.write(id + '\n')
		f.close()

print("Starting sniffing")
# Start sniffing
sniff(iface = iface, prn = checkID)

