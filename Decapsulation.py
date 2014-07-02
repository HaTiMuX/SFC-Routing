#@Author=HaTiM#
#@Title=POSTROUTING#
#@Function=DECAPSULATE PACKETS IF THERE IS ENCAPSULATION#

import nfqueue, socket
from scapy.all import *
import os, MySQLdb


os.system('iptables -t mangle -A PREROUTING -j NFQUEUE --queue-num 0')

db = MySQLdb.connect("localhost","sfcuser","sfc123","SFC")
cursor = db.cursor()

count = 0

def cb(payload):
	global count
	count +=1
	data = payload.get_data()
	p = IP(data) 

	if(p.dst=="10.1.0.1" or p.dst=="10.2.0.1"):
		if(p.tos == 0): #If the packet is not marked
			#Getting the original packet if it exists
			p1 = p.payload 
			if IP in p1:
				print(str(count) + ": Outer Header " + p.src + "=>" + p.dst + "--TOS==" + str(p.tos))
				p = p.payload 
				del p.chksum
				print(" : Inner Header " + p.src + "=>" + p.dst + "--TOS==" + str(p.tos))
				payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(p), len(p))

			else:
				print(str(count) + ": Packet accepted. No encapsulation!!!")
				print(" : " + p.src + "=>" + p.dst + "--TOS==" + str(p.tos))
				payload.set_verdict(nfqueue.NF_ACCEPT)

		else:
			print(str(count) + ": Packet accepted. No encapsulation!!!")
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