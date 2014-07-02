#@Author=HaTiM#
#@Title=FORWARD-X#
#@Function=ROUTE PACKETS, APPLY NAT FUNCTION AND MAKE ENCAPSULATION DEPENDING ON THE MARK#
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

def NAT(p, last):
	print(" : Before " + p.src + "=>" + p.dst + "--TOS=" + str(p.tos))
	p[IP].src = "10.2.0.2" #NAT Source SF1
	if(last==True):
		p.tos = 0 #Taking mark off 
	print(" : After  " + p.src + "=>" + p.dst + "--TOS=" + str(p.tos))
	del p[IP].chksum

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
		"""This attribute will be None for operations that do not return rows 
		or if the cursor has not had an operation invoked via the execute*() methods yet."""
		if result is not None:
			Encap = result[3]
			#reading Next SF Hop IP address
			IPx = result[2]
			#No IP address in the table means the node is the last in the SF Map
			if IPx is None: 
				print(str(count) + ": I'm the last SF Node!!")
				NAT(p,True)
				payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(p), len(p))

			#The Node is not the Last in the SF Map
			#Checking the Encap field to know if the next SF Node is a next hop
			else:
				if Encap is 1:
					print(str(count) + ": Applying NAT and Forwarding to Next SF Hop: %s (Encapsulation)" % IPx)
					NAT(p,False)
					p = Encapsulation(p,IPx)	
					payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(p), len(p))
			
				else:
					print(str(count) + ": Applying NAT and Forwarding to Next SF Hop: %s" % IPx)
					NAT(p,False)
					payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(p), len(p))

		elif(p.tos==0):
			#print(str(count) + ": Packet Accepted. Logical routing |||| " + p.src + "=>" + p.dst + "--TOS=" + str(p.tos))
			payload.set_verdict(nfqueue.NF_ACCEPT)


		#else: 
		#print(str(count) + ": Packet Droped |||| " + p.src + "=>" + p.dst + "--TOS=" + str(p.tos))
		#payload.set_verdict(nfqueue.NF_DROP)
			
	except:
   		print "Error: unable to fecth data (Next SF Hop IP address)"


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