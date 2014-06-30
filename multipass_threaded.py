#!/usr/bin/python

# TODO
# urllib2 timeout

import urllib2
import sys
import signal
import socket
import re
from threading import Thread
from Queue import Queue, Empty

queue = Queue()
headers = {'X-Forwarded-For': '127.0.0.1', 'User-Agent': 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'}
threadcount = 10
results = {}
ports = [80, 443]
domain_list_f = open(sys.argv[1], 'r')
bf_wordlist_f = open(sys.argv[2], 'r')
logfile = open(sys.argv[3], 'w')

domain_list = domain_list_f.readlines()
bf_wordlist = bf_wordlist_f.readlines()

domain_list_f.close()
bf_wordlist_f.close()

def signal_handler(signal, frame):
	print "\nCtrl-C pressed, exiting.."
	sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def test_domain(domain):
	# check domain resolves
	try:
		this_ip = socket.gethostbyname(domain)
		return this_ip
	except socket.error:
		return 'nxdomain'

def test_ports(ip, ports):
	open_ports = []
	# check ports
	for port in ports:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock_result = sock.connect_ex((ip,port))
		if sock_result == 0:
			open_ports.append(port)
		sock.close()

	return open_ports

def get_404_control(scheme, domain, port):
	print "Checking 404 for " + scheme + domain + ':' + `port`
	control = {}
	try:
		req1 = urllib2.Request(scheme + domain + ':' + `port` + "/" + "Neg-Existorz", None, headers)
		response_404_1 = urllib2.urlopen(req1)
		req2 = urllib2.Request(scheme + domain + ':' + `port` + "/" + "Neg-ExistorzNeg-Existorz", None, headers)
		response_404_2 = urllib2.urlopen(req2)
		len_404_1 = len(response_404_1.read())
		len_404_2 = len(response_404_2.read())
		if (len_404_1 != len_404_2) and ( ( (len_404_2 % 12) != 0) and ( (len_404_1 % 12) != 0) ):
			print "weird length responses"
			control['type404'] = 'wtf'
			control['staticlen'] = 'wtf'
			control['multiplier'] = 'wtf'
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
			print "some httperror"
			control['type404'] = 'wtf'

	except urllib2.URLError as urlError:
		print "some urlerror"
		control['type404'] = 'wtf'
	except:
		print "some timeout, probably. catchall"
		# probably a timeout of some description
		control['type404'] = 'wtf'

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

for domain in domain_list:
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
		if control_404['type404'] == 'not-https':
			print "Port " + `port` + ' is not running HTTPS as expected. Skipping..'
			continue
		elif control_404['type404'] == 'wtf':
			print "Port " + `port` + ' needs to be assessed manually, skipping..'
			continue
		elif control_404['type404'] == 'static200':
			print "Static 404 response size of " + `control_404['staticlen']` + "."
		elif control_404['type404'] == 'variable200':
			print "Variable 404 response size. "
		elif control_404['type404'] == 'standard':
			print "normal 404."
		print "Bruting " + scheme + dom + ':' + `port` + '..'

		for testcase in bf_wordlist:
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
