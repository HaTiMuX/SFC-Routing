#@Author=HaTiM#
#@Title=SFCRouting-X#
#@Function=ROUTE PACKETS ACCORDING TO SFC SOLUTION#
import nfqueue, socket
from scapy.all import *
import os, MySQLdb

count = 0

#Adding iptables rule
os.system('iptables -t mangle -A FORWARD -j NFQUEUE --queue-num 1')

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
		sql = "SELECT NextSF, Encap FROM SFCRoutingTable WHERE SF_MAP_INDEX=%d" % (p.tos)
		cursor.execute(sql)
		result = cursor.fetchone()
		if result is not None:
			#Reading Next SF Function
			nextSF = result[0]
			#Reading Encap field
			Encap = result[1]

			#No next SF in the table means the node is the last in the SF Map
			if nextSF is None: 
				print(str(count) + ": I'm the last SF Node!!")
				NAT(p,True)
				payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(p), len(p))

			#The Node is not the Last in the SF Map
			else:
				try:
					sql = "SELECT * FROM LocalLocators WHERE SF='%s'" % (nextSF)
					cursor.execute(sql)
					result2 = cursor.fetchone()
					if result2 is not None:
						nextHop = result2
						#Checking the Encap field to know if the next SF Node is a next hop or not
						if Encap is 1:
							print(str(count) + ": SF_MAP_INDEX=%d" % p.tos)
							print(" : Forwarding to Next SF Hop: %s (Encapsulation)" % nextHop)
							p = Encapsulation(p,nextHop)	
							payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(p), len(p))
			
						else:
							print(str(count) + ": SF_MAP_INDEX=%d" % p.tos)
							print(" : Forwarding to Next SF Hop: %s" % nextHop)
							payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(p), len(p))
				except:
			   		print "Error: unable to fecth data (Next SF Hop Locator)"
		else: 
			payload.set_verdict(nfqueue.NF_ACCEPT)
			
	except:
   		print "Error: unable to fecth data (Next SF Function)"


q = nfqueue.queue()
q.set_callback(cb)
q.open()
q.create_queue(1)
q.set_queue_maxlen(50000)

try:
	q.try_run()

except KeyboardInterrupt, e:
	print "interruption"
	os.system('iptables -t mangle -F')
	q.unbind(socket.AF_INET)
	q.close()