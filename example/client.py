import sys
import time
import requests
import logging
import click
import os
import binascii
import base64

from . import cli

from app.plugins.drive import Drive

from typing import Any

logging.basicConfig(level=0)
logging = logging.getLogger('cli.consumer.demo')

""" Key distribution is problematic anyway, even not valid cerytficate
	gives TLS encryption and it's worth to use it.
"""
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

@click.option('--armour', is_flag=False, default=str(), help=('Host or IP of API armour.'))
@click.option('--aport', is_flag=False, default=8111, help=('Armour port number. Default :8111'))
@click.option('--host', is_flag=False, default=str(), help=('Host or IP, host:port API.'))
@click.option('--port', is_flag=False, default=80, help=('API port number. Default :80'))
@click.option('--ticket', is_flag=False, default=str(), help=('Run with dedicated ticket.'))
@click.option('--name', is_flag=False, default=str(), help=('Service name'))
@click.option('--sleep', is_flag=False, default=0, help=('Pause between requests in miliseconds.'))
@cli.command()
def consumer(armour, aport, host, port, ticket, name, sleep):
	""" API consumer demo - simple server with recurrent calls.
	"""
	if aport == 443:
		from app.client.http import HTTP as Armour
	else:
		from app.client.tcp import TCP as Armour
		

	http = requests.Session()

	armour = Armour(host=armour,
					port=aport,
					name=name,
					pool=1)

	# if not name and not ticket:
	# 	""" automatic key exchange, if not ticket provied by cli
	# 		contact to ticket provider service and grab a new one.

	# 		for demo example, ticket is downloaded directly from 
	# 		producer application, however in real env it should be
	# 		exchanged in secure second channel.
	# 	"""
	# 	if response := http.get('http://' + host + '/ask',
	# 							headers={'Content-Type': 'application/json'}):
	# 		if ticket := response.json().get('ticket'):
	# 			if armour.save(ticket):
	# 				logging.info('Key exchange success.')
	
	with armour(ticket, host, port) as arm:

		while not hasattr(cli, 'terminated'):
			if response := http.get('http://' + host,
									headers={'Content-Type': 'application/json',
											  **arm.headers()},
									json={'time': arm.encrypt(time.time())}):
				if ticket := arm.stamp(response.headers):
					logging.info('Decrypted %s', arm.decrypt(response.json().get('time')))
			else:
				logging.error('Faild.')
			time.sleep(int(sleep)/1000)