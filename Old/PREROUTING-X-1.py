#@Author=HaTiM#
#@Title=POSTROUTING-1#
#@Function=DECAPSULATE PACKETS IF THERE IS ENCAPSULATION & ADD ROUTING RULES IN CASE OF FORCING#

import nfqueue, socket
from scapy.all import *
import os, MySQLdb
os.system('iptables -t mangle -A PREROUTING -j NFQUEUE --queue-num 0')

count = 0

db = MySQLdb.connect("localhost","sfcuser","sfc123","SFC")
cursor = db.cursor()

def ForcingRuleTest(p):
	try:
		sql = "SELECT * FROM SFCRoutingTable WHERE SF_MAP_INDEX=%d" % (p.tos)
		cursor.execute(sql)
		result = cursor.fetchone()
		if result is not None:
			IPx = result[2]
			if IPx is not None: 
				pdest = IP(dst=p.dst, ttl=1)
				ans = sr1(pdest, verbose=0)
				GWdst = ans[IP].src
				pdest = IP(dst=IPx, ttl=1)
				ans = sr1(pdest, verbose=0)
				GWSF = ans[IP].src
				
			if(GWdst!=GWSF):
				print "Forcing"
				rule = "ip rule add tos " + hex(p.tos) + " table 10"
				os.system(rule)
	except:
	   	print "Error: unable to fecth data"


def cb(payload):
	global count
	count +=1
	data = payload.get_data()
	p = IP(data)        #Reading packet data

	if(p.tos==192 or p.tos==222):
		payload.set_verdict(nfqueue.NF_DROP)

	elif(p.dst=="10.1.0.2" or p.dst=="10.2.0.2"):
		if(p.tos != 0): #If the packet is marked and the SF node is last the Destination
			ForcingRuleTest(p)
			print(str(count) + ": " + p.src + "=>" + p.dst + "--TOS==" + str(p.tos))

		else:
			print(str(count) + ": Outer Header " + p.src + "=>" + p.dst + "--TOS==" + str(p.tos))
			#Getting the original packet if it exists
			p = p.payload 
			del p.chksum
			if IP in p:
				ForcingRuleTest(p)
				print(" : Inner Header " + p.src + "=>" + p.dst + "--TOS==" + str(p.tos))
				payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(p), len(p))

			else:
				print(" : Packet Accepted. No encapsulation")
				print(" : " + p.src + "=>" + p.dst + "--TOS==" + str(p.tos))
				payload.set_verdict(nfqueue.NF_ACCEPT)

	else:
		print(str(count) + ": Packet accepted. No encapsulation!!!")
		print(" : " + p.src + "=>" + p.dst + "--TOS==" + str(p.tos))
		payload.set_verdict(nfqueue.NF_ACCEPT)

q = nfqueue.queue()
q.open()
q.unbind(socket.AF_INET)
q.bind(socket.AF_INET)
q.set_callback(cb)
q.create_queue(0) #Same queue number of the rule

try:
	q.try_run()

except KeyboardInterrupt, e:
	os.system('iptables -t mangle -F')
	print "interruption"
	q.unbind(socket.AF_INET)
	q.close()