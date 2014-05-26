#@Author=HaTiM#
#@Title=FORWARD-1#
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

def NAT(p):
	print(" : Before " + p.src + "=>" + p.dst + "--TOS=" + str(p.tos))
	p[IP].src = "10.1.0.1" #NAT Source SF1
	print(" : After  " + p.src + "=>" + p.dst + "--TOS=" + str(p.tos))
	del p[IP].chksum

def Encapsulation(p,IPx):
	p = IP(src="10.1.0.1", dst=IPx)/p
	del p[IP].chksum
	print(" : New Outer Header " + p.src + "=>" + p.dst + "--TOS=" + str(p.tos))

def cb(payload):
	global count
	count +=1
	data = payload.get_data()
	p = IP(data)
	# Prepare SQL query to INSERT a record into the database.
	sql = "SELECT * FROM SFCRoutingTable WHERE SF_MAP_INDEX=%d" % (p.tos)
	print sql

	try:
		# Execute the SQL commands
		cursor.execute(sql)
		# Fetch all the rows in a list of lists.
		result = cursor.fetchone()
		print result
		"""This attribute will be None for operations that do not return rows 
		or if the cursor has not had an operation invoked via the execute*() methods yet."""
		if result is not None:
			Encap = result[3]
			#reading Next SF Hop IP address
			IPx = result[2]
			print IPx
			#No IP address in the table means the node is the last in the SF Map
			if IPx is None: 
				print(str(count) + ": I'm the last SF Node!!")
				NAT(p)
				p.tos = 0 #Taking mark off
				del p[IP].chksum
				payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(p), len(p))

			#The Node is not the Last in the SF Map
			#Checking the Encap field to know if the next SF Node is a next hop
			else:
				pdest = IP(dst=p.dst, ttl=1)
				ans = sr1(pdest, verbose=0)
				GWdst = ans[IP].src
				pdest = IP(dst=IPx, ttl=1)
				ans = sr1(pdest, verbose=0)
				GWSF = ans[IP].src

				if(GWdst!=GWSF):
					conf.route.add(host=IPx,gw=GWSF)

				if Encap is None:
					#Verifing Neighberhood
					if(GWSF==IPx):
						sqlupd = "UPDATE SFCRoutingTable SET ENCAP = 0 WHERE SF_MAP_INDEX=%d" % (p.tos)
						print(str(count) + ": Applying NAT and Forwarding to Next SF Hop: %s e" % IPx)
						NAT(p)
						payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(p), len(p))

					else:
						sqlupd = "UPDATE SFCRoutingTable SET ENCAP = 1 WHERE SF_MAP_INDEX=%d" % (p.tos)
						print(str(count) + ": Applying NAT and Forwarding to Next SF Hop: %s (Encapsulation)" % IPx)
						NAT(p)
						Encapsulation(p,IPx)
						payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(p), len(p))

				elif Encap is 1:
					sqlupd = None
					print(str(count) + ": Applying NAT and Forwarding to Next SF Hop: %s (Encapsulation)" % IPx)
					NAT(p)
					Encapsulation(p,IPx)	
					payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(p), len(p))
			
				else:
					sqlupd = None
					print(str(count) + ": Applying NAT and Forwarding to Next SF Hop: %s" % IPx)
					NAT(p)
					payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(p), len(p))


				if sqlupd is not None:
					try:
						cursor.execute(sqlupd)
						db.commit()
					except:
						print "Error: Update Fail!!"
						db.rollback()

				conf.route.resync()

		elif(p.tos==0):
			print(str(count) + ": Packet Accepted. Logical routing |||| " + p.src + "=>" + p.dst + "--TOS=" + str(p.tos))
			payload.set_verdict(nfqueue.NF_ACCEPT)

		else: 
			print(str(count) + ": Packet Droped |||| " + p.src + "=>" + p.dst + "--TOS=" + str(p.tos))
			payload.set_verdict(nfqueue.NF_DROP)
			
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



