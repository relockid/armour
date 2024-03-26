from gevent import monkey

monkey.patch_all()

import sys
import time
import requests
import logging
import click
import os
import gevent
import signal

from gevent.pywsgi import WSGIServer
from gevent.server import _tcp_listener
from multiprocessing import Process, current_process, cpu_count

from flask import Flask, request, Response

@click.group()
def cli():
	pass

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)

logging.basicConfig(level=0)
logging = logging.getLogger('cli.server.demo')

@click.option('--host', is_flag=False, default='0.0.0.0', help=('Host or IP. Default 0.0.0.0'))
@click.option('--port', is_flag=False, default=80, help=('Port number. Default :80'))
@click.option('--armour', is_flag=False, default='0.0.0.0', help=('Armour IP Default 0.0.0.0'))
@click.option('--aport', is_flag=False, default=8111, help=('Port number. Default :8111'))
@click.option('--private', is_flag=True, default=True, help=('Turn on private mode - require armour ticket\'s.'))
@click.option('--multiprocessing', is_flag=True, default=False, help=('Start multiprocessing mode.'))
@click.option('--cpus', is_flag=False, default=0, help=('Number of cpus'))
@cli.command()
def run(host, port, armour, aport, private, multiprocessing, cpus):
	""" API server demo - simple server side.
	"""

	if int(aport) == 443:
		from relock import HTTP as Armour
	else:
		from relock import TCP as Armour

	def make(host, port, private):

		app = Flask(__name__, instance_relative_config=True)
		armour = Armour(host=host,
						port=port,
						private=private,
						pool=5)

		@app.before_request
		def validate():
			with armour() as arm:
				if not arm.validate(request.path, request.headers, request.remote_addr):
					logging.error('Unauthorized request from %s.', request.remote_addr)
					return Response('Unauthorized', status=401)

		@app.route("/")
		def index():
			with armour() as arm:
				if request.json.get('time') if request.is_json else None:
					logging.info('Decrypted %s', arm.decrypt(request.json.get('time')))
				return {"time": arm.encrypt(time.time())}
			return {"time": None}

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
				response = arm.finalize(response)
			return response

		return app

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

if __name__ == "__main__":
	cli()