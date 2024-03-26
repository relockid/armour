import sys
import signal
import time
import requests
import logging
import click
import os
import binascii
import base64
import click

from typing import Any

logging.basicConfig(level=logging.INFO)
logging = logging.getLogger('cli.consumer.demo')

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

@click.group()
def cli():
	pass

@click.option('--armour', is_flag=False, default=str(), help=('Host or IP of API armour.'))
@click.option('--aport', is_flag=False, default=8111, help=('Armour port number. Default :8111'))
@click.option('--host', is_flag=False, default=str(), help=('Host or IP, host:port API.'))
@click.option('--port', is_flag=False, default=80, help=('API port number. Default :80'))
@click.option('--ticket', is_flag=False, default=str(), help=('Run with dedicated ticket.'))
@click.option('--name', is_flag=False, default=str(), help=('Service/Client process name.'))
@click.option('--sleep', is_flag=False, default=0, help=('Pause between requests in miliseconds.'))
@cli.command()
def run(armour, aport, host, port, ticket, name, sleep):
	""" API consumer demo - simple client example.
	"""
	if int(aport) == 443:
		from relock import HTTP as Armour
	else:
		from relock import TCP as Armour
		

	http   = requests.Session()
	armour = Armour(host=armour,
					port=aport,
					name=name,
					pool=1)

	with armour(ticket, host, port) as arm:

		if not name and not ticket:
			""" automatic key exchange, if ticket is not provided by cli, 
				download the ticket directly from api server

				Demo purpose only, ticket is downloaded directly from producer 
				application. For production env it should be delivered in second 
				channel e.g. identity provider or email.
			"""
			if response := http.get('http://' + host + '/ask',
									headers={'Content-Type': 'application/json'}):
				if ticket := response.json().get('ticket'):
					if armour.save(ticket):
						logging.info('Key exchange success.')

		while not hasattr(cli, 'terminated'):
			""" Request loop,
			"""
			if response := http.get('http://' + host,
									headers={'Content-Type': 'application/json',
											  **arm.headers()},
									json={'time': arm.encrypt(time.time())}):
				if ticket := arm.stamp(response.headers):
					logging.info('Decrypted %s', arm.decrypt(response.json().get('time')))
			else:
				logging.error('Faild.')
			time.sleep(int(sleep)/1000)

if __name__ == "__main__":
	
	def signal_handler(signal, frame):
		logging.info('Terminated.')
		setattr(cli, 'terminated', time.time())
	signal.signal(signal.SIGINT, signal_handler)
	signal.signal(signal.SIGHUP, signal_handler)
	signal.signal(signal.SIGTERM, signal_handler)
	signal.signal(signal.SIGQUIT, signal_handler)

	cli()