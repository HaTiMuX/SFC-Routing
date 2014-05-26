#@Author=HaTiM#
#@Title=Classifier#
#@Function=MARK PACKETS DEPENDING ON SPECIFIC RULES#
import nfqueue, socket
from scapy.all import *
import os
os.system('iptables -A OUTPUT -j NFQUEUE --queue-num 0')

def cb(payload):
	data = payload.get_data()
	p = IP(data)
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

