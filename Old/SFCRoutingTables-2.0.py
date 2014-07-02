import MySQLdb
import sys

# Open database localhost connection
db = MySQLdb.connect("localhost","sfcuser","sfc123","SFC")
cursor = db.cursor()

#Entries
SFs = ['SF1','SF2','SF3','SF4']

#Functions
def getPosition(SF_MAP, SF):
	try:
		return SF_MAP.index(SF)

	except ValueError:
		return -1

#Body
i=0
sql = "SELECT SF_Map_Index, SFMap FROM SFMaps"
try:
	cursor.execute(sql)
	results = cursor.fetchall()

	for row in results:
		print "************************************"
		print "Adding configuration of SF_Map N: %d" % (i+1)
		print "************************************"
		Index = row[0] #Index of the current Map
		SFMap = row[1] # Reading The current Map
		#Changing SFMap Format
		SFMap = SFMap.lstrip('{')
		SFMap = SFMap.rstrip('}')
		SF_Map = SFMap.split(', ')
		print SF_Map

		#Checking each SF function if it is involved or not
		for SF in SFs:
			p = getPosition(SF_Map, SF)
			if(p!=-1): 
				print(SF + " is involved and its position in the SF Map is " + str(p+1))
				#Looking for the Locator of the next SF
				try:
					if(p!=len(SF_Map)-1):
						sql1 = "SELECT ip FROM SFIP WHERE sf = '%s'" % (SF)
						sql2 = "SELECT ip FROM SFIP WHERE sf = '%s'" % (SF_Map[p+1]) 
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
						sql1 = "SELECT ip FROM SFIP WHERE sf = '%s'" % (SF)
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
					print "Error: unable to add data to remote server!"

				remoteDB.close()
				print ""

			else:
				print(SF + " is not involved\n")

		print ""
		i+=1

except:
	print "Error: unable to fecth data in the local database!!"

# disconnect from DB local server
db.close()
