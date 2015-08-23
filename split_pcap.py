#!-*- coding:utf-8 -*-
import sys
import urlparse
import dpkt,socket,datetime

def search():
	global pcap_file
	global sum
	no = 1
	global index
	global max

	with open(pcap_file, 'rb') as f:
		pcr = dpkt.pcap.Reader(f)
	
		for t, buf in pcr:
			if index >= len(lines):
				break
			eth = dpkt.ethernet.Ethernet(buf)
			ip = eth.data
			tcp = ip.data

			netloc = urlparse.urlparse(lines[index]).netloc
			dst = socket.inet_ntoa(ip.dst)

			if tcp.dport == 80 and dst == netloc:
					print index+1, ":", lines[index].rstrip()
					print "  No.", no
					index += 1
					sum +=1
			elif tcp.dport == 53 and len(tcp.data) > 0:
				dns = dpkt.dns.DNS(tcp.data)
				name = dns.qd[0].name
				if netloc == name:
					print index+1, ":", lines[index].rstrip()
					print "  No.", no
					index += 1
					sum +=1
			no += 1
		
		if index != max:
			print index+1, ":", lines[index].rstrip()
			print "  !!! Failure !!!"

argvs = sys.argv
if len(argvs) != 3:
	print 'Usage: # python %s pcap_file urllist_file' % argvs[0]
	quit()

pcap_file = sys.argv[1]
urllist_file = sys.argv[2]

urllist = open(urllist_file)
lines = urllist.readlines()
urllist.close()

sum = 0
index = 0
max = len(lines)

search()
while index != max:
	index += 1
	search()

print ""
print "Success:", sum, "/", max
print ""
