#!/usr/bin/python

# vt 2k14
# TODO
# best runthru - 504mins.
# ascii art
# ports option
# sqlite out
# stdout out
# randomly generate 404 check value - no more NegExist0rz
# accept netblock / range as target input

import requests
import sys
import signal
import socket
import re
import argparse
from threading import Thread
from Queue import Queue, Empty

queue = Queue()
outqueue = Queue()
headers = {'User-Agent': 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'}
#results = {}
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
		sock.settimeout(3.0)
		try:
			sock_result = sock.connect((ip,port)) # broken
			open_ports.append(port)
		except socket.timeout:
			pass
		except:
			pass

		sock.close()

	return open_ports

def verify_requests(url):
	results_404 = {}

	for i in range(5):
		queue.put(url)
	workers = []
	for i in range(5):
		worker = Thread(group=None, target=cp_thread, name=None, args=(), kwargs={'type404':'check404'})
		worker.start()
		workers.append(worker)
	for worker in workers:
		worker.join()

	resultstmp = {}
	rescount = 1
	while True:
		try:
			result = {}
			result = outqueue.get_nowait()
			resultstmp[rescount] = result
			rescount = (rescount + 1)

		except Empty:
			break

	if (resultstmp[1][url]['code'] == 404) and (resultstmp[2][url]['code'] == 404) and (resultstmp[5][url]['code'] == 404):
		results_404['code'] = 404
		results_404['len'] = 0
	elif (resultstmp[1][url]['length'] == resultstmp[2][url]['length'] == resultstmp[3][url]['length'] == resultstmp[4][url]['length'] == resultstmp[5][url]['length']):
		results_404['code'] = resultstmp[2][url]['code']
		results_404['len'] =resultstmp[1][url]['length']
	else:
		results_404['code'] = resultstmp[2][url]['code']
		results_404['len'] = "ne:" + url

	return results_404

def get_404_control(scheme, domain, port):
	control = {}
	try:
		results_404_1 = verify_requests(scheme + domain + ':' + `port` + "/" + "Neg-Existorz")
	except:
		control['type404'] = 'error'
		control['error'] = '404 check failed.'
		return control

	# 404 checks seem to work. lets do the second.
	results_404_2 = verify_requests(scheme + domain + ':' + `port` + "/" + "Neg-ExistorzNegExist.php")

	if (results_404_1['code'] == 404 and results_404_2['code'] == 404):
		control['type404'] = 'standard'

	elif results_404_1['len'] == "ne:"+scheme+domain+":"+`port`+"/"+"Neg-Existorz":
		control['type404'] = 'error'
		control['error'] = 'Variable responses for same HTTP request.'

	elif results_404_1['len'] == results_404_2['len']:
		control['type404'] = 'static200'
		control['staticlen'] = results_404_1['len']
		control['multiplier'] = 1

	elif results_404_2['len'] == "ne:"+scheme+domain+":"+`port`+"/"+"Neg-ExistorzNegExist.php":
		control['type404'] = 'error'
		control['error'] = 'Variable responses for same HTTP request.'

	elif (results_404_1['len'] - results_404_2['len']) % 12 == 0:
		difference = (results_404_2['len'] - results_404_1['len'])	
		control['type404'] = 'variable200'
		control['staticlen'] = (results_404_1['len'] - difference)
		control['multiplier'] = (difference/12)

	else:
		control['type404'] = 'error'
		control['error'] = 'Variable responses for same HTTP request. Maybe in the future, though..'

	return control


def cp_thread(**kwargs):
	try:
		while True:
			url = queue.get_nowait()
			results = {}
			try:
				res = requests.get(url, headers=headers, verify=False, timeout=3.0)
				response_parsed = parse_response(res, url, **kwargs) 

				res_code = response_parsed['code']
				res_length = response_parsed['len']
				res_mark = response_parsed['mark']
			except:
				res_code = 999
				res_length = 0
				res_mark = '?'

			if kwargs['type404']!='check404':
				sys.stdout.write(res_mark),
				sys.stdout.flush()

			results[url] = {}
			results[url]['code'] = res_code
			results[url]['length'] = res_length
			outqueue.put(results)

	except Empty:
		pass


def parse_response(response_object, url, type404, staticlen=0, multiplier=1):
	request_len = len(re.sub('http.+:\d+\/','',url))
	parsed_results = {}
	response_len = len(response_object.text)
	response_code = response_object.status_code

	if response_code != 200:
		parsed_results['code'] = response_code
		parsed_results['len'] = 0
		parsed_results['mark'] = '.'

	else: # response code is 200
		if type404 == 'static200':
			if staticlen == response_len:
				parsed_results['code'] = 404
				parsed_results['len'] = 0
				parsed_results['mark'] = '.'
			else:
				parsed_results['code'] = 200
				parsed_results['len'] = response_len
				parsed_results['mark'] = '!'

		elif type404 == 'variable200':
			if response_len == (staticlen + (multiplier * request_len)):
				parsed_results['code'] = 404
				parsed_results['len'] = 0
				parsed_results['mark'] = '.'
			else:
				parsed_results['code'] = 200
				parsed_results['len'] = response_len
				parsed_results['mark'] = '!'

		elif type404 == 'standard' or type404 == 'check404':
			# a legit, old fashioned 200
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

	print "Analyzing " + dom + ".."
	print "Resolving.."
	domain_ip = test_domain(dom)
	if domain_ip == 'nxdomain':
		print dom + ' does not resolve, skipping..'
		continue

	print "Portscanning.."
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
		print "Checking 404 for port " + `port` + ".."
		control_404 = get_404_control(scheme, dom, port) # XXX here
		if control_404['type404'] == 'error':
			print dom + ":" + `port` + ' needs to be assessed manually, skipping..'
			logfile.write(dom + ':' + `port` + ' needs to be assessed manually. Details: ' + `control_404['error']` + '\n')
			continue

		print "Bruting " + scheme + dom + ':' + `port` + '..'

		for testcase in wordlist:
			page = testcase.rstrip()
			queue.put(scheme + dom + ':' + `port` + '/' + page)
		workers = []

		for i in range(int(myargs.threadcount)):
			worker = Thread(group=None, target=cp_thread, name=None, args=(), kwargs=control_404)
			worker.start()
			workers.append(worker)
		for worker in workers:
			worker.join()
			
		try:
			while True:
				res = outqueue.get_nowait()
				url = dict.keys(res)[0]
				if res[url]['code'] == 1:
					rcode = 'Timeout'
				else:
					rcode = `res[url]['code']`

				logfile.write(url + ' : ' + rcode + ' (' + `res[url]['length']` + ' bytes)\n')
		except Empty:
			pass#continue

		sys.stdout.write("\n")
		sys.stdout.flush()		

		with outqueue.mutex:
			outqueue.queue.clear()

logfile.close()
print "\nDone!"
