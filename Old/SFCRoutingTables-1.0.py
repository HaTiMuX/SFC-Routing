import MySQLdb
import sys

# Open database localhost connection
db = MySQLdb.connect("localhost","sfcuser","sfc123","SFC")
cursor = db.cursor()
'''
db.append(MySQLdb.connect("localhost","sfcuser","sfc123","SFC"))
db.append(MySQLdb.connect("10.1.0.1","sfcuser","sfc123","SFC"))
db.append(MySQLdb.connect("10.2.0.2","sfcuser","sfc123","SFC"))
db.append(MySQLdb.connect("10.3.0.3","sfcuser","sfc123","SFC"))
'''

# prepare cursor objects using cursor() method
cursor = db.cursor()
'''
cursor.append(db[0].cursor())
cursor.append(db[1].cursor())
cursor.append(db[2].cursor())
cursor.append(db[3].cursor())
'''

#Entries
SFs = ['SF1','SF2','SF3','SF4']
Index = 5
SF_Maps = []
SF_Maps.append((1,['SF1','SF2']))
SF_Maps.append((2,['SF1','SF3']))
SF_Maps.append((3,['SF2','SF1']))
SF_Maps.append((4,['SF2','SF3']))
SF_Maps.append((5,['SF3','SF1']))
SF_Maps.append((6,['SF3','SF2']))

#Functions
def getPosition(SF_MAP, SF):
	try:
		return SF_MAP.index(SF)

	except ValueError:
		return -1

'''
def Whichdb(SF):
	if(SF=="SF1"):
		return 1
	elif(SF=="SF2"):
		return 2
	elif(SF=="SF3"):
		return 3
	else: 
		return -1
'''
'''
sql = "SELECT SFMap FROM SFMaps"
try:
	cursor.execute(sql)
	results = cursor.fetchall()
	
	for SFMap in results:
		SFMap = SFMap.lstrip('{')
		SFMap = SFMap.rstrip('}')
		SF_Map = SFMap.split(', ')

		#Checking each SF function if it is involved or not
		for SF in SFs:

'''





#Body
l1 = len(SF_Maps)
l2 = len(SFs)
i=0
j=0
IP = ""

while(i<l1):
	print "************************************"
	print "Adding configuration of SF_Map N: %d" % (i+1)
	print "************************************"
	while(j<l2):
		#Checking each SF function if it is involved or not
		p = getPosition(SF_Maps[i][1], SFs[j])
		Index = SF_Maps[i][0] #Index of the current Map
		if(p!=-1): 
			print(SFs[j] + " is involved and its position in the SF Map is " + str(p+1))

			#Looking for the Locator of the next SF
			try:
				if(p!=len(SF_Maps[i])-1):
					sql1 = "SELECT ip FROM SFIP WHERE sf = '%s'" % (SFs[j])
					sql2 = "SELECT ip FROM SFIP WHERE sf = '%s'" % (SF_Maps[i][1][p+1]) #Tferoui7
					cursor.execute(sql1)
			   		result = cursor.fetchone()
					IP = result[0] #Converting from tuple to normal string: SF node IP
					cursor.execute(sql2)
			   		result = cursor.fetchone()
					IPx = result[0] #Next SF Node IP
					print "Node IP = " + IP
			  		print "Next SF Hop @IP = " + IPx
					sql = "INSERT INTO SFCRoutingTable (SF_MAP_INDEX, NextSFHop, Encap) VALUES ('%d','%s', NULL)" % (Index,IPx)
				else:
					sql1 = "SELECT ip FROM SFIP WHERE sf = '%s'" % (SF_Maps[p][1])
					cursor.execute(sql1)
			   		result = cursor.fetchone()
					IP = result[0] #SF node IP
					print "The Node is the last Node in the SF Map"
					sql = "INSERT INTO SFCRoutingTable (SF_MAP_INDEX, NextSFHop, Encap) VALUES ('%d', NULL, NULL)" % Index
			except:
				print "Error: unable to fecth data (IP addresses)"

			#Adding row to the remote table 'SFCRoutingTable' of the SF Node 
			remoteDB = MySQLdb.connect(IP,"sfcuser","sfc123","SFC")
			remoteCursor = remoteDB.cursor()
			try:
				remoteCursor.execute(sql)
				remoteDB.commit()
				print "Adding data to remote Node %s: Success!" % IP
			except:
				remoteDB.rollback()
				print "Error: unable to add data!"

			remoteDB.close()
			print ""

		else:
			print(SFs[j] + " is not involved\n")

		j+=1

	print ""
	j=0
	i+=1


# disconnect from DB local server
db.close()

#db[2].close()
#db[3].close()


'''j = Whichdb(SF_MAP[p])
			if(j!=-1):
				try:
					cursor[j].execute(sql)
				db[j].commit()
				print "Adding data to DB%d: Success!" % j
			except:
				db[j].rollback()
				print "Error: unable to add data!"
			else: 
				print "Error: DB not found!"
'''
