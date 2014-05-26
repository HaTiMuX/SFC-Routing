#!/usr/bin/python
import MySQLdb
from scapy.all import *

db = MySQLdb.connect("localhost","sfcuser","sfc123","SFC")
cursor = db.cursor()

sql = "SELECT NextSFHop FROM SFCRoutingTable WHERE Encap IS NULL"

try:
   	cursor.execute(sql)
	results = cursor.fetchall()

except:
	print "Error Reading IP address of Next SF Hop"

for result in results:
	IPx = result[0]

	if IPx is not None:
		pdest = IP(dst=IPx, ttl=1)
		ans = sr1(pdest, verbose=0)
		nextHop = ans[IP].src

		#t = WhichTable(nextHop)
		#rule = 'iptables -t nat -A PREROUTING -m tos --tos %d  -j MARK --set-mark %d' % (p.tos, t)
		#os.system(rule)

		if(IPx==nextHop):
			sql = "UPDATE SFCRoutingTable SET Encap = 0 WHERE NextSFHop='%s'" % IPx
		else:
			sql = "UPDATE SFCRoutingTable SET Encap = 1 WHERE NextSFHop='%s'" % IPx

	else:
		sql = "UPDATE SFCRoutingTable SET Encap = 0 WHERE NextSFHop='%s'" % IPx

try:
   	cursor.execute(sql)
   	db.commit()
except:   
   	db.rollback()
   	print "Error"

db.close()

