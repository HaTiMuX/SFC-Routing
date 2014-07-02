#!/usr/bin/python
from subprocess import check_output
from scapy.all import *
import MySQLdb
import os, sys, time

GWs = []

output = check_output(['ip','neighbor'])
output = output.rstrip("\n")
lines = output.split('\n')
for line in lines:
	GWs.append(line.split(' ')[0])

print "Local gateways: " +  str(GWs)

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
		db = MySQLdb.connect("localhost","sfcuser","sfc123","SFC")
		cursor = db.cursor()

		try:
			sql = "SELECT SF_MAP_INDEX, NextSF FROM SFCRoutingTable WHERE Encap IS NULL"
		   	cursor.execute(sql)
			results = cursor.fetchall()

		except:
			print "Error Reading next SF in the Map"

		if(results):
			for result in results:
				index = result[0]
				SF = result[1]
				if SF is not None:
					try:
						sql = "SELECT Locator FROM LocalLocators WHERE SF='%s'" % SF
					   	cursor.execute(sql)
						res = cursor.fetchone()
					except:
						print "Error Reading IP address of the next SF"

				
					IPx = res[0]
					try:
						pdest = IP(dst=IPx, ttl=1)
						ans = sr1(pdest, verbose=0)
						nextHop = ans[IP].src
					except:
						print "Destination unreachable"

					if(IPx==nextHop):
						sql = "UPDATE SFCRoutingTable SET Encap = 0 WHERE NextSF='%s'" % SF
					else:
						sql = "UPDATE SFCRoutingTable SET Encap = 1 WHERE NextSF='%s'" % SF 

					#Force routing in case destination gateway is different from next SF hop gateway
					GW = Gateway(IPx)
					if GW == "0.0.0.0":
						m = GWs.index(IPx) + 1
					else:
						m = GWs.index(GW) + 1
					rule = 'iptables -t mangle -A PREROUTING -m tos --tos %d -j MARK --set-mark %d' % (index, m)
					print "Forcing Rule to add: " + rule + "\n"
					os.system(rule)
					print "Updating Encap Done!!"

				else:
					sql = "UPDATE SFCRoutingTable SET Encap = 0 WHERE SF_MAP_INDEX=%d" % index
					print "Updating Encap Done!!"

				try:
				   	cursor.execute(sql)
				   	db.commit()
				except:   
				   	db.rollback()
				   	print "Error"

		else:
			print "No entry with Encap = NULL"

		db.close()
		time.sleep(10)

	except KeyboardInterrupt, e:
		break


