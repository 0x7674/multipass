#!/usr/bin/python

# vt 2k14
# TODO
# urllib2 timeout

import urllib2
import sys
import signal
import socket
import re
import getopt
import argparse
from threading import Thread
from Queue import Queue, Empty

queue = Queue()
headers = {'User-Agent': 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'}
threadcount = 10
results = {}
ports = [80, 443]

parser = argparse.ArgumentParser(prog='multipass.py')
mutually_exclusive_parms = parser.add_mutually_exclusive_group(required=True)
mutually_exclusive_parms.add_argument('-d', '--domain', help='domain to check (single)')
mutually_exclusive_parms.add_argument('-l', '--listdomains', help='file containing domains to check')
parser.add_argument('-r', '--reqfile', help='file containing wordlist of requests (default=pages)', default='pages')
parser.add_argument('-o', '--outfile', help='output file', required=True)
parser.add_argument('-t', '--threadcount', help='number of threads (default=10)', default=10)
parser.add_argument('-v', '--verbose', help='verbose output', default=False)

myargs = parser.parse_args()

logfile = open(myargs.outfile, 'w')
wordlist_f = open(myargs.reqfile, 'r')
wordlist = wordlist_f.readlines()
wordlist_f.close()

if myargs.domain:
	domainlist = [myargs.domain]
elif myargs.listdomains:
	domlist_f = open(myargs.listdomains, 'r')
	domainlist = domlist_f.readlines()
	domlist_f.close()
else:
	print "+++ Divide By Cucumber Error. Please Reinstall Universe And Reboot +++"

def signal_handler(signal, frame):
	print "\nCtrl-C pressed, exiting.."
	sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def test_domain(domain):
	try:
		this_ip = socket.gethostbyname(domain)
		return this_ip
	except socket.error:
		return 'nxdomain'

def test_ports(ip, ports):
	open_ports = []
	for port in ports:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock_result = sock.connect_ex((ip,port))
		if sock_result == 0:
			open_ports.append(port)
		sock.close()

	return open_ports

def verify_requests(url):
	req = urllib2.Request(url, None, headers)
	res1 = urllib2.urlopen(req)
	res2 = urllib2.urlopen(req)
	res3 = urllib2.urlopen(req)
	res4 = urllib2.urlopen(req)
	res5 = urllib2.urlopen(req)
	len1 = len(res1.read())
	len2 = len(res2.read())
	len3 = len(res3.read())
	len4 = len(res4.read())
	len5 = len(res5.read())
	if (len1 == len2 == len3 == len4 == len5):
		#print "equal: " + `len1`
		return len1
	else:
		#print "not equal"
		return "ne:"+url
	



def get_404_control(scheme, domain, port):
	print "Checking 404 for " + scheme + domain + ':' + `port`
	control = {}
	try:
		req1 = urllib2.Request(scheme + domain + ':' + `port` + "/" + "Neg-Existorz", None, headers)
		len_404_1 = verify_requests(scheme + domain + ':' + `port` + "/" + "Neg-Existorz")
		req2 = urllib2.Request(scheme + domain + ':' + `port` + "/" + "Neg-ExistorzNeg-Existorz", None, headers)
		len_404_2 = verify_requests(scheme + domain + ':' + `port` + "/" + "Neg-ExistorzNeg-Existorz")
		if (len_404_1 != len_404_2) and ( ( (len_404_2 % 12) != 0) and ( (len_404_1 % 12) != 0) ): # FIXME stoopz
			#print "weird length responses"
			control['type404'] = 'error'
			control['error'] = 'Server returns inconsistent response lengths.'
		else:
			if (len_404_2-len_404_1) == 0:
				control['type404'] = 'static200'
				control['staticlen'] = len_404_1
				control['multiplier'] = 1
			else:
				difference = (len_404_2-len_404_1)/12
				control['type404'] = 'variable200'
				control['staticlen'] = (len_404_1-(difference * 12))
				control['multiplier'] = difference
	except urllib2.HTTPError as errorDetail:
		cleaned = errorClean(errorDetail)
		if cleaned == 404:
			control['type404'] = 'standard'
			control['staticlen'] = 0
			control['multiplier'] = 1
		else:
			#print "some httperror"
			control['type404'] = 'error'
			control['error'] = 'An unknown HTTPError occurred: ' + errorDetail

	except urllib2.URLError as urlError:
		#print "some urlerror"
		control['type404'] = 'error'
		control['error'] = 'An unknown URLError occurred: ' + urlError
	except:
		#print "some timeout, probably. catchall"
		# probably a timeout of some description
		control['type404'] = 'error'
		control['error'] = 'An unknown error occurred - probably a timeout.'

	return control

def cp_thread(**kwargs):
	try:
		while True:
			url = queue.get_nowait()
			try:
				req = urllib2.Request(url, None, headers)
				http_response = urllib2.urlopen(url)
				response_parsed = parse_response(http_response, url, **kwargs) 
				res_code = response_parsed['code']
				res_length = response_parsed['len']
				res_mark = response_parsed['mark']
				sys.stdout.write(res_mark),
				sys.stdout.flush()
			except urllib2.HTTPError as errorDetail:
				sys.stdout.write("."),
				res_code = errorClean(errorDetail)
				res_length = 0
				sys.stdout.flush()
			except urllib2.URLError as urlError:
				sys.stdout.write("x"),
				res_code = 1 # timeout
				res_length = 0
				sys.stdout.flush()
			except:
				sys.stdout.write("X"),
				res_code = 1
				res_length = 0
				sys.stdout.flush()

			results[url] = {}
			results[url]['code'] = res_code
			results[url]['length'] = res_length

	except Empty:
		pass


def errorClean(errorRaw):
	errorMsg = str(errorRaw)
	if errorMsg == "HTTP Error 404: Not Found":
		return 404
	elif errorMsg == "HTTP Error 403: Forbidden":
		return 403
	elif errorMsg == "HTTP Error 401: Unauthorized":
		return 401
	else:
		return errorRaw

def parse_response(response_object, url, type404, staticlen, multiplier):
	request_len = re.sub('http.+:\d+\/','',url)
	parsed_results = {}
	response_len = len(response_object.read())
	if type404 == 'standard':
		parsed_results['code'] = 200
		parsed_results['len'] = response_len
		parsed_results['mark'] = '!'
		# If it was a 400 error it wouldn't have made it this far anyway		
	
	elif type404 == 'static200':
		if staticlen == response_len:
			parsed_results['code'] = 404
			parsed_results['len'] = 0
			parsed_results['mark'] = '.'
		else:
			parsed_results['code'] = 200
			parsed_results['len'] = response_len
			parsed_results['mark'] = '!'

	elif type404 == 'variable200':
		if len(response_object.read()) == (staticlen + (multiplier * request_len)):
			parsed_results['code'] = 404
			parsed_results['len'] = 0
			parsed_results['mark'] = '.'
		else:
			parsed_results['code'] = 200
			parsed_results['len'] = response_len
			parsed_results['mark'] = '!'

	return parsed_results


##################
##################
##### MAIN #######
##################
##################


for domain in domainlist:
	dom = domain.rstrip()
	portscan_results = []
	domain_ip = test_domain(dom)
	if domain_ip == 'nxdomain':
		print dom + ' does not resolve, skipping..'
		continue

	portscan_results = test_ports(domain_ip, ports)
	if len(portscan_results) < 1:
		print dom + ' has no open ports, skipping..'
		next

	for port in portscan_results:
		if port == 443 or port == 8443:
			scheme = 'https://'
		else:
			scheme = 'http://'

		control_404 = {}
		control_404 = get_404_control(scheme, dom, port)
		if control_404['type404'] == 'error':
			print "Port " + `port` + ' needs to be assessed manually, skipping..'
			logfile.write(dom + ':' + `port` + ' needs to be assessed manually. Details: ' + `control_404['error']` + '\n')
			continue
		"""
		elif control_404['type404'] == 'static200':
			print "Static 404 response size of " + `control_404['staticlen']` + "."
		elif control_404['type404'] == 'variable200':
			print "Variable 404 response size. "
		elif control_404['type404'] == 'standard':
			print "normal 404."
		"""
		print "Bruting " + scheme + dom + ':' + `port` + '..'

		for testcase in wordlist:
			page = testcase.rstrip()
			queue.put(scheme + dom + ':' + `port` + '/' + page)
		workers = []
		for i in range(threadcount):
			worker = Thread(group=None, target=cp_thread, name=None, args=(), kwargs=control_404)
			worker.start()
			workers.append(worker)
		for worker in workers:
			worker.join()
			
		for res in results:
			if results[res]['code'] == 1:
				rcode = 'Timeout'
			else:
				rcode = `results[res]['code']`

			logfile.write(res + ' : ' + rcode + ' (' + `results[res]['length']` + ' bytes)\n')

		results = {}
		sys.stdout.write("\n")
		sys.stdout.flush()		

logfile.close()
print "Done!"
