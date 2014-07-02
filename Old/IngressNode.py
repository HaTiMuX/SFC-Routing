#@Author=HaTiM#
#@Title=FORWARD-1#
#@Function=ROUTING PACKETS TO THE FIRST SF NODE IN THE CORRESPONDING SF MAP#
import nfqueue, socket
from scapy.all import *
import os, MySQLdb

count = 0

#Adding iptables rule
os.system('iptables -t mangle -A POSTROUTING -j NFQUEUE --queue-num 1')

# Open database connection
db = MySQLdb.connect("localhost","sfcuser","sfc123","SFC")
# prepare a cursor object using cursor() method
cursor = db.cursor()

def Encapsulation(p,IPx):
	p = IP(dst=IPx)/p
	del p[IP].chksum
	print(" : New Outer Header " + p.src + "=>" + p.dst + "--TOS=" + str(p.tos))
	return p

def cb(payload):
	global count
	count +=1
	data = payload.get_data()
	p = IP(data)

	try:
		sql = "SELECT * FROM SFCRoutingTable WHERE SF_MAP_INDEX=%d" % (p.tos)
		cursor.execute(sql)
		result = cursor.fetchone()

		if result is not None:
			Encap = result[3]
			#reading First SF Node IP address
			IPx = result[2]

			if Encap is 1:
				print(str(count) + ": Forwarding to First SF Node: %s (Encapsulation)" % IPx)
				p = Encapsulation(p,IPx)	
				payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(p), len(p))
			
			else:
				print(str(count) + ": Forwarding to First SF Node: %s" % IPx)
				payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(p), len(p))

		else:
			#print(str(count) + ": Packet Accepted. Logical routing |||| " + p.src + "=>" + p.dst + "--TOS=" + str(p.tos))
			payload.set_verdict(nfqueue.NF_ACCEPT)

		#else: 
			#print(str(count) + ": Packet Droped |||| " + p.src + "=>" + p.dst + "--TOS=" + str(p.tos))
			#payload.set_verdict(nfqueue.NF_DROP)
			
	except:
   		print "Error: unable to fecth data"


q = nfqueue.queue()
q.set_callback(cb)
q.open()
q.create_queue(1) #Same queue number of the rule
q.set_queue_maxlen(50000)
try:
	q.try_run()
except KeyboardInterrupt, e:
	print "interruption"
	os.system('iptables -t mangle -F')
	q.unbind(socket.AF_INET)
	q.close()



