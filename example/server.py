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
from multiprocessing import Process, current_process, cpu_count

from flask import Flask, request, Response

from . import cli

""" Key distribution is problematic, anyway even not CA valid cerytficate
	provides an TLS encryption and it's worth to use it.
"""
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)

logging.basicConfig(level=0)
logging = logging.getLogger('cli.producer.demo')

@click.option('--host', is_flag=False, default='0.0.0.0', help=('Host or IP. Default 0.0.0.0'))
@click.option('--port', is_flag=False, default=80, help=('Port number. Default :80'))
@click.option('--armour', is_flag=False, default='0.0.0.0', help=('Armour IP Default 0.0.0.0'))
@click.option('--aport', is_flag=False, default=8111, help=('Port number. Default :8111'))
@click.option('--private', is_flag=True, default=False, help=('Turn on private mode - require armour ticket\'s.'))
@click.option('--multiprocessing', is_flag=True, default=False, help=('Start multiprocessing mode.'))
@click.option('--cpus', is_flag=False, default=0, help=('Number of cpus'))
@cli.command()
def producer(host, port, armour, aport, private, multiprocessing, cpus):

	if aport == 443:
		from app.client.http import HTTP as Armour
	else:
		from app.client.tcp import TCP as Armour

	""" API producer demo - simple server side.
	"""
	def make(host, port, private):
		
		app = Flask(__name__, instance_relative_config=True)
		armour = Armour(host=host,
						port=port,
						private=True,
						pool=5)

		@app.before_request
		def validate():
			with armour() as arm:
				if not arm.validate(request.path, request.headers, request.remote_addr):
					return Response('Unauthorized', status=401)

		@app.route("/")
		def index():
			with armour() as arm:
				if request.json.get('time') if request.is_json else None:
					logging.info('Decrypted %s', arm.decrypt(request.json.get('time')))
				return {"time": arm.encrypt(time.time())}

		@app.route("/enclave")
		def enclave():
			with armour() as arm:
				if request.json.get('time') if request.is_json else None:
					logging.info('Decrypted %s', arm.decrypt(request.json.get('time'), True))
				return {"time": arm.encrypt(time.time(), True)}

		@armour.allow("/ask")
		@app.route("/ask")
		def ask():
			with armour() as arm:
				if ticket := arm.ask():
					return {'ticket': str(ticket)}

		@app.after_request
		def after_request(response):
			with armour() as arm:
				arm.finalize(response)

			_ = (500, 400, 401, 403, 404)
			if response.status_code in _:
				logging.notify("[{w}%s/{z}{red}%s{z}{gray}]{z} {red}%s{z} {gray}%s{x}", request.method, response.status_code, request.remote_addr, request.path)
			else:
				logging.notify("[{w}%s/{z}{green}%s{z}{gray}]{z} %s {gray}%s{x}", request.method, response.status_code, request.remote_addr, request.path)
			return response

		return app
	# now, we can start the server
	#
	logging.info('Simple producer server at %s:%s starting...', host, port)

	class devnull:
		write = lambda _: None

	def spawn(listener, host, port, armour, aport, private):
		if app := make(armour, aport, private):
			worker = WSGIServer(listener, app, log=devnull)
			gevent.signal_handler(signal.SIGHUP, worker.stop)
			gevent.signal_handler(signal.SIGINT, worker.stop)
			gevent.signal_handler(signal.SIGTERM, worker.stop)
			logging.info('Spawn %s on %s:%s', current_process().name, host, port)
			worker.serve_forever()

	listener = _tcp_listener((host, port), reuse_addr=True)
	if multiprocessing:
		for x in range(int(cpus) or cpu_count()):
			Process(target=spawn, args=(listener, host, port, armour, aport, private), name='App[%s]' % x).start()
	spawn(listener, host, port, armour, aport, private)
