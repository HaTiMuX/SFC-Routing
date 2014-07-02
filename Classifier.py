#@Author=HaTiM#
#@Title=Classifier#
#@Function=MARK PACKETS DEPENDING ON SPECIFIC RULES#
import nfqueue, socket
from scapy.all import *
import os
<<<<<<< HEAD
os.system('iptables -A PREROUTING -j NFQUEUE --queue-num 0')


def conversion(N):
	b = []
	div = [10000, 1000, 100, 10, 1]

	i=0
	for d in div:
		if N/d==1:
			b[i]=1
		else:
			b[i]=1
		i+=1

	return b

=======
os.system('iptables -A OUTPUT -j NFQUEUE --queue-num 0')
>>>>>>> 85dd5e78a042515bef00c2b20e8f220e18e52afb

def cb(payload):
	data = payload.get_data()
	p = IP(data)
<<<<<<< HEAD
	proto = p[IP].proto
	src = p[IP].src
	dst = p[IP].dst

		try:
			sql = "SELECT * FROM ClassRules WHERE ParNum<=3"
			cursor.execute(sql)
			results = cursor.fetchall()

			for result in results:
				if result[]==5:
					if src==result[2] and dst==result[3] and proto==result[4] and sport==result[5] and dport==result[6]:
						p.tos= result[1]
						break

				if result[]==4:
					
					if src==result[2] and dst==result[3] and proto==result[4] and sport==result[5] and dport==result[6]:
						p.tos= result[1]
						break


					
				if result[7]>3:
					if src==result[1] and dst==result[2] and proto==result[2]:
						p.tos= result[0]
						break

				elif result[]==2:
					if((src==result[1] and dst==result[2]) or (src==result[1] and proto==result[3]) or (dst==result[2] and proto==result[3])):
						p.tos= result[0]
						break

				elif result[]==1:
					if(src==result[1] or dst==result[2] or proto==result[3]):
						p.tos= result[0]
						break
			del p[IP].chksum
			payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(p), len(p))
			
			print "Matching rule: "

		except:
			print "Error reading rules"


	elif (TCP in IP) or (UDP in IP):
		dport = p[1].dport
		sport = p[1].sport
		try:
			sql = "SELECT * FROM ClassRules"
			cursor.execute(sql)
			results = cursor.fetchall()

			cond1 = (src==result[1] and dst==result[2] and proto==result[3] and sport==result[4]) or 
			cond2 = (src==result[1] and dst==result[2] and proto==result[3] and dport==result[5])

			for result in results:
				if result[]==5:


				elif result[]==4:
					if((src==result[1] and dst==result[2]) or (src==result[1] and proto==result[3]) or (dst==result[2] and proto==result[3])):
						p.tos= result[0]
						break

				elif result[]==1:
					if(src==result[1] or dst==result[2] or proto==result[3]):
						p.tos= result[0]
						break
=======
	src = p[IP].src

	try: 
		port = p[1].dport
		try:
			sql = "SELECT SF_MAP_INDEX FROM Rules WHERE IP='%s' and port='%d'" % (src, port)
			cursor.execute(sql)
			result = cursor.fetchone()
			if result is not None:
				p.tos = result[0]
				del p[IP].chksum
				payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(p), len(p))

			else:
				try:
					sql = "SELECT SF_MAP_INDEX FROM Rules WHERE IP is NULL and port='%d'" % (port)
					cursor.execute(sql)
					result = cursor.fetchone()

					if result is not None:
						p.tos = result[0]
						del p[IP].chksum
						payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(p), len(p))

					else:
						try:
							sql = "SELECT SF_MAP_INDEX FROM Rules WHERE IP='%s' and port is NULL" % (src)
							cursor.execute(sql)
							result = cursor.fetchone()

							if result is not None:
								p.tos = result[0]
								del p[IP].chksum
							payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(p), len(p))

							else:
								print("Packet Accepted: logical routing")
								payload.set_verdict(nfqueue.NF_ACCEPT)

						except:
							print "Error looking for mark (by IP)"

				except:
					print "Error looking for mark (by port)"

		except:
			print "Error looking for mark (by IP and port)"

	except:
		print "Protocol does not support destination port field"
		sql = "SELECT SF_MAP_INDEX FROM Rules WHERE IP='%s' and port is NULL" % (src)

		try: 
			cursor.execute(sql)
			result = cursor.fetchone()

			if result is not None:
				p.tos = result[0]
				del p[IP].chksum
				payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(p), len(p))

			else: 
				print("Packet Accepted: logical routing")
				payload.set_verdict(nfqueue.NF_ACCEPT)

		except:
			print "Error looking for mark (by IP)"
>>>>>>> 85dd5e78a042515bef00c2b20e8f220e18e52afb

q = nfqueue.queue()
q.open()
q.unbind(socket.AF_INET)
q.bind(socket.AF_INET)
q.set_callback(cb)
q.create_queue(0) #Same queue number of the rule
#q.set_queue_maxlen(50000)

try:
	q.try_run()
except KeyboardInterrupt, e:
	os.system('iptables -F')
	print "interruption"
	q.unbind(socket.AF_INET)
	q.close()

