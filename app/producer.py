import sys
import time
import requests
import threading
import logging
import click
import os
import signal
import gevent
import binascii
import base64

from gevent.pywsgi import WSGIServer
from gevent.server import _tcp_listener
from multiprocessing import Process, current_process

from flask import Flask, request, Response

from . import cli
from .aes import SIV
from .ticket import Ticket

""" Key distribution is problematic, anyway even not CA valid cerytficate
	provides an TLS encryption and it's worth to use it.
"""
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)

logging.basicConfig(level=0)
logging = logging.getLogger('cli.producer.demo')

http = requests.Session()
ticket = Ticket()

class devnull:
	write = lambda _: None

def crypto(json, host, route):
	if url := 'https://' + host + '/crypto/' + route:
		if response := http.post(url, headers={'Content-Type': 'application/json',
											   'X-Ticket-ID': request.ticket.value,
											   'X-ADDR-ID': request.remote_addr},
									  json=json,
									  verify=False):
			if json := response.json():
				if not json.get('error'):
					return json.get('payload')

def encrypt(json, host):
	return crypto(json, host, 'encrypt')

def decrypt(json, host):
	return crypto(json, host, 'decrypt')

@click.option('--host', is_flag=False, default='0.0.0.0', help=('Host or IP. Default 0.0.0.0'))
@click.option('--port', is_flag=False, default=80, help=('Port number. Default :80'))
@click.option('--multiprocessing', is_flag=True, default=False, help=('Start multiprocessing mode.'))
@cli.command()
def producer(host, port, multiprocessing):
	""" API producer demo - simple server side.
	"""
	app = Flask(__name__)

	@app.before_request
	def validate():
		if not request.is_json:
			return Response({'status': 'Please set your content type "application/json"!'}, status=400, content_type='application/json; charset=utf-8')

		if request.headers.get('X-Ticket-ID'):
			if url := 'https://' + host + '/token':
				if response := http.post(url, headers={'Content-Type': 'application/json',
													   'Connection': 'keep-alive',
													   'X-Ticket-ID': request.headers.get('X-Ticket-ID'), 
													   'X-Token-ID': request.headers.get('X-Token-ID'), 
													   'X-ADDR-ID': request.remote_addr},
											  json={},
											  verify=False):
					if json := response.json():
						if not json.get('error'):
							setattr(request, 'ticket', Ticket(**json))
				else:
					return Response({'status': 'Unauthorized'}, status=401, content_type='application/json; charset=utf-8')

	@app.route("/")
	def index():
		if request.json.get('time'):
			logging.info('Decrypted %s', request.ticket.decrypt(request.json.get('time')))
		return {"time": request.ticket.encrypt(time.time())}

	@app.route("/encrypted", methods=['POST'])
	def encrypted():
		logging.info('Got: %.30s... -> %s', request.json.get('time'), decrypt({'payload': request.json.get('time')}, host))
		if data := encrypt({"payload": time.time()}, host):
			return {"time": data}
		return {"time": time.time()}

	@app.after_request
	def after_request(response):
		if hasattr(request, 'ticket') and not request.ticket.error:
			response.headers.add('X-Ticket-ID', request.ticket.value)
			response.headers.add('X-Token-ID', request.ticket.token)

		_ = (500, 400, 401, 403, 404)
		if response.status_code in _:
			logging.error("[%s/%s] %s %s", request.method, response.status_code, request.remote_addr, request.path)
		else:
			logging.info("[%s/%s] %s %s", request.method, response.status_code, request.remote_addr, request.path)
		return response
		
	# now, we can start the server
	#
	logging.info('Simple producer server at %s:%s starting...', host, port)

	def spawn(listener, app):
		worker = WSGIServer(listener, app, log=devnull)
		gevent.signal_handler(signal.SIGHUP, worker.stop)
		gevent.signal_handler(signal.SIGINT, worker.stop)
		gevent.signal_handler(signal.SIGTERM, worker.stop)
		logging.info('Spawn worker... %s', current_process().name)
		worker.serve_forever()

	listener = _tcp_listener((host, port))
	if multiprocessing:
		for x in range(len(os.sched_getaffinity(0)) - 1):
			Process(target=spawn, args=(listener, app,), name='Producer[%s]' % x).start()
	spawn(listener, app)


