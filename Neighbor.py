#!/usr/bin/python
from subprocess import check_output
from scapy.all import *
import MySQLdb
import os, sys, time


db = MySQLdb.connect("localhost","sfcuser","sfc123","SFC")
cursor = db.cursor()
GWs = []

output = check_output(['ip','neighbor'])
output = output.rstrip("\n")
lines = output.split('\n')
for line in lines:
	GWs.append(line.split(' ')[0])

print GWs

i = 1
while(i <= len(GWs)):
	table = "ip route add table %d default via %s" % (i, GWs[i-1])
	rule = "ip rule add fwmark %d table %d" %(i, i)
	os.system(table)
	os.system(rule)
	i += 1 

def Gateway(IP):
	#Getting the Gateway of an IP address 
	netmask = "255.255.255.0"
	net = ""
	mask = netmask.split(".")
	ip = IP.split(".")

	i=0
	while i < 4:
		x = int(mask[i]) & int(ip[i])
		net = net + str(x) + "."
		i +=1
	net = net.rstrip('.')

	for line in scapy.config.conf.route.routes:
		network = scapy.utils.ltoa(line[0])
		GW = line[2]
		if(network==net):
			break

	return GW

while(True):
	try:
		try:
			sql = "SELECT SF_MAP_INDEX, NextSFHop FROM SFCRoutingTable WHERE Encap IS NULL"
		   	cursor.execute(sql)
			results = cursor.fetchall()

		except:
			print "Error Reading IP address of Next SF Hop"

		if(results):
			for result in results:
				index = result[0]
				IPx = result[1]
				if IPx is not None:
					try:
						pdest = IP(dst=IPx, ttl=1)
						ans = sr1(pdest, verbose=0)
						nextHop = ans[IP].src
						print nextHop

					except:
						print "Destination unreachable"

					if(IPx==nextHop):
						sql = "UPDATE SFCRoutingTable SET Encap = 0 WHERE NextSFHop='%s'" % IPx
					else:
						sql = "UPDATE SFCRoutingTable SET Encap = 1 WHERE NextSFHop='%s'" % IPx 

					#Force routing in case destination gateway is different from next SF hop gateway
					GW = Gateway(IPx)
					if GW == "0.0.0.0":
						m = GWs.index(IPx) + 1
					else:
						m = GWs.index(GW) + 1
					rule = 'iptables -t mangle -A PREROUTING -m tos --tos %d -j MARK --set-mark %d' % (index, m)
					print rule
					os.system(rule)

				else:
					sql = "UPDATE SFCRoutingTable SET Encap = 0 WHERE SF_MAP_INDEX=%d" % index

				try:
				   	cursor.execute(sql)
				   	db.commit()
				except:   
				   	db.rollback()
				   	print "Error"

		else:
			print "No entry with Encap = NULL"
	
		time.sleep(10)

	except KeyboardInterrupt, e:
		break

db.close()

