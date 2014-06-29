#!/usr/bin/python

# TODO
# urllib2 timeout
# smart 'fake 404' handling

import urllib2
import sys
import socket
import re
from threading import Thread
from Queue import Queue, Empty

queue = Queue()
headers = {'X-Forwarded-For': '127.0.0.1'}
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
		response_404_1 = urllib2.urlopen(scheme + domain + ':' + `port` + "/" + "Neg-Existorz")
		response_404_2 = urllib2.urlopen(scheme + domain + ':' + `port` + "/" + "Neg-ExistorzNeg-Existorz")
		len_404_1 = len(response_404_1.read())
		len_404_2 = len(response_404_2.read())
		if (len_404_1 != len_404_2) and ( ( (len_404_2 % 12) != 0) and ( (len_404_1 % 12) != 0) ):
			print "Something funky is going on here. Review manually - Skipping.."
			control['type'] = 'wtf'
			control['staticlen'] = 'wtf'
			control['multiplier'] = 'wtf'
		else:
			if (len_404_2-len_404_1) == 0:
				print "A 404 response is a static size of " + `len_404_1`
				control['type'] = 'static200'
				control['staticlen'] = len_404_1
				control['multiplier'] = 1
			else:
				difference = (len_404_2-len_404_1)/12
				print "A 404 response is " + `difference` + " * request length + " + `(len_404_1-(difference * 12))`
				control['type'] = 'variable200'
				control['staticlen'] = (len_404_1-(difference * 12))
				control['multiplier'] = difference
			#logfile.write(scheme + domain + ':' + `port` + ' forges 404 responses. Skipping..\n')
	except urllib2.HTTPError as errorDetail:
		cleaned = errorClean(errorDetail)
		if cleaned == 404:
			control['type'] = 'standard'
	except urllib2.URLError as urlError:
		control['type'] = 'not-https'

	print "control:"
	print control
	return control

"""
def check_page(scheme, domain, port, page, ex404):
	res_code = ''
	try:
		req = urllib2.Request(scheme+domain+':'+`port`+'/'+page, None, headers)
		#check_response = urllib2.urlopen(scheme + domain + ':' + `port` + '/' + page)
		get_response = urllib2.urlopen(req)
		#res_code = get_response.getcode()
		#return res_code, len(get_response.read())
		return parse_response(get_response, len(page), ex404)
	except urllib2.HTTPError as errorDetail:
		# 40x error
		return errorClean(errorDetail), 0
	except urllib2.URLError as urlError:
		return 'Timeout', 0
"""

def cp_thread(my404={}):
	print "my404:"
	print my404
	try:
		while True:
			url = queue.get_nowait()
			try:
				req = urllib2.Request(url, None, headers)
				http_response = urllib2.urlopen(url)
				response_parsed = parse_response(http_response, url, my404)  #XXX hmmmmmm
				res_code = response_parsed['code']
				res_length = response_parsed['len']
				sys.stdout.write("!"),
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

def parse_response(response_object, url, handler404={}):
	print "handler404:"
	print handler404
	request_len = re.sub('http.+:\d+\/','',url)
	parsed_results = {}
	response_len = len(response_object.read())
	if handler404['type'] == 'standard':
		parsed_results['code'] = 200
		parsed_results['len'] = response_len
		# If it was a 400 error it wouldn't have made it this far anyway		
	
	elif handler404['type'] == 'static200':
		if handler404['staticlen'] == response_len:
			parsed_results['code'] = 404
			parsed_results['len'] = 0
		else:
			parsed_results['code'] = 200
			parsed_results['len'] = response_len

	elif handler404['type'] == 'variable200':
		if len(response_object.read()) == (handler404['staticlen'] + (handler404['multiplier'] * request_len)):
			parsed_results['code'] = 404
			parsed_results['len'] = 0
		else:
			parsed_results['code'] = 200
			parsed_results['len'] = response_len

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
		if control_404['type'] == 'not-https':
			print "Port " + `port` + ' is not running HTTPS as expected. Skipping..'
			continue
		elif control_404['type'] == 'wtf':
			print "Port " + `port` + ' needs to be assessed manually, skipping..'
			continue
		elif control_404['type'] == 'static200':
			print "Static 404 response size of " + `control_404['staticlen']` + "."
		elif control_404['type'] == 'variable200':
			print "Variable 404 response size. "
			# TODO set up the control 404 handlre
		elif control_404['type'] == 'standard':
			print "normal 404."

		print "Bruting " + scheme + dom + ':' + `port` + '..'

		for testcase in bf_wordlist:
			page = testcase.rstrip()
			queue.put(scheme + dom + ':' + `port` + '/' + page)
		workers = []
		for i in range(threadcount):
			worker = Thread(group=None, target=cp_thread, name=None, args=(control_404), kwargs={})
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

		sys.stdout.write("\n")
		sys.stdout.flush()		

logfile.close()

