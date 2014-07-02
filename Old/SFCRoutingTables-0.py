import MySQLdb
import sys

# Open database connections
db = []
db.append(MySQLdb.connect("localhost","sfcuser","sfc123","SFC"))
db.append(MySQLdb.connect("10.1.0.1","sfcuser","sfc123","SFC"))
db.append(MySQLdb.connect("10.2.0.2","sfcuser","sfc123","SFC"))
db.append(MySQLdb.connect("10.3.0.3","sfcuser","sfc123","SFC"))

# prepare cursor objects using cursor() method
cursor = []
cursor.append(db[0].cursor())
cursor.append(db[1].cursor())
cursor.append(db[2].cursor())
cursor.append(db[3].cursor())

#Entries
SFs = ['SF1','SF2','SF4']
Index = 5
SF_MAP = ['SF1','SF2','SF3']

#Functions
def getPosition(SF_MAP, SF):
	try:
		return SF_MAP.index(SF)

	except ValueError:
		return -1

def Whichdb(IPx):
	if(IPx=="localhost"):
		return 0
	elif(IPx=="10.1.0.1"):
		return 1
	elif(IPx=="10.2.0.2"):
		return 2
	elif(IPx=="10.3.0.3"):
		return 3
	else: 
		return -1

#Body
print "************************************************"
print "Checking the involved SFs in the Chain"
print "************************************************"
l = len(SFs)
i=0

while(i<l):
	p = getPosition(SF_MAP, SFs[i])
	if(p!=-1):
		print(SFs[i] + " is involved and its position in the SF Map is " + str(p+1))

		#Looking for the Locator of the next SF
		try:
			if(p!=len(SF_MAP)-1):
				sql1 = "SELECT ip FROM SFIP WHERE sf = '%s'" % (SF_MAP[p])
				sql2 = "SELECT ip FROM SFIP WHERE sf = '%s'" % (SF_MAP[p+1])
				cursor[0].execute(sql1)
			   	result = cursor[0].fetchone()
				IP = result[0] #Converting from tuple to normal string
				cursor[0].execute(sql2)
			   	result = cursor[0].fetchone()
				IPx = result[0] 
				print "Node IP= " + IP
			  	print "Next SF Hop @IP= " + IPx
				sql = "INSERT INTO SFCRoutingTable (SF_MAP_INDEX, NextSFHop, Encap) VALUES ('%d','%s', NULL)" % (Index,IPx)
			else:
				print "The Node is the last Node in the SF Map"
				sql = "INSERT INTO SFCRoutingTable (SF_MAP_INDEX, NextSFHop, Encap) VALUES ('%d', NULL, NULL)" % Index

		except:
			print "Error: unable to fecth data"

		#Adding row to the SFCRoutingTable
		j = Whichdb(IP)
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

		print ""
	else:
		print(SFs[i] + " is not involved\n")

	i+=1


# disconnect from servers
db[0].close()
db[1].close()
db[2].close()
db[3].close()


