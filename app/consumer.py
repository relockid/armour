import sys
import time
import requests
import logging
import click
import os
import binascii
import base64

from . import cli
from .ticket import Ticket

from typing import Any
from dataclasses import dataclass

logging.basicConfig(level=0)
logging = logging.getLogger('cli.consumer.demo')

""" Key distribution is problematic anyway, even not valid cerytficate
	gives TLS encryption and it's worth to use it.
"""
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

http = requests.Session()
ticket = Ticket()

def _ticket(host):
	""" Ticket is downloaded directly from producer enclave
	"""
	if url := 'https://' + host + '/ticket':
		if response := http.get(url, headers={'Content-Type': 'application/json',
											  'Connection': 'keep-alive'},
									 json={},
									 verify=False):
			if json := response.json():
				if not json.get('error'):
					return Ticket(**json)

def save(id, ticket, local):
	""" Save ticket to local enclave - if running on same
		machine diffrent IP will be used for local
	"""
	if url := 'https://' + local + '/ticket/' + id + '/' + ticket:
		if response := http.get(url, headers={'Content-Type': 'application/json',
											  'Connection': 'keep-alive',
											  'X-Ticket-ID': ticket},
									 json={},
									 verify=False):
			if json := response.json():
				if not json.get('error'):
					return Ticket(**json)
	return False

def _register(host, ticket):
	""" Empty request to the producer running on port :80
		and initial key establishment
	"""
	print(host)
	if url := 'http://' + host + '/':
		if response := http.get(url, headers={'Content-Type': 'application/json',	
											  'Connection': 'keep-alive',	  
											  'X-Ticket-ID': ticket.value,
											  'X-Token-ID': ticket.token},
									 json={},
									 verify=False):
			print(response.json())
			if json := response.json():
				if not json.get('error'):
					return ticket
	return False

def _token(id, ticket, local):
	if url := 'https://' + local + '/token/' + id:
		if response := http.get(url, headers={'Content-Type': 'application/json',
											  'Connection': 'keep-alive',
											  'X-Last-ID': ticket.token},
									 json={},
									 verify=False):
			if json := response.json():
				if not json.get('error'):
					return Ticket(**json)
	return False

def stamp(id, response, local):
	if url := 'https://' + local + '/stamp/' + id:
		if response := http.post(url, headers={'Content-Type': 'application/json',
											   'Connection': 'keep-alive',
											   'X-Ticket-ID': response.headers.get('X-Ticket-ID'),
											   'X-Token-ID': response.headers.get('X-Token-ID')},
									  verify=False):
			if json := response.json():
				if not json.get('error'):
					return Ticket(**json)
	return False


def crypto(json, route, id, local):
	if url := 'https://' + local + '/crypto/' + route + '/' + id:
		if response := http.post(url, headers={'Content-Type': 'application/json',
											   'Connection': 'keep-alive',
											   'X-ADDR-ID': 'consumer.app'},
									  json=json,
									  verify=False):
			if json := response.json():
				if not json.get('error'):
					return json.get('payload')

def authenticate(host, local, id):
	global ticket
	# first, let's download the ticket from producer armour
	ticket = _ticket(host)
	# ok, we need to save the ticket on local consumer armour
	ticket = save(id, ticket.value, local)
	# now, token must to be exchanged with producer to 
	# establish mututal identity - this step is required
	if ticket := _register(host, ticket):
		return ticket
	return False

@click.option('--host', is_flag=False, default=None, help=('Host or IP producer enclave.'))
@click.option('--local', is_flag=False, default='127.0.0.1', help=('Host or IP of local enclave.'))
@click.option('--id', is_flag=False, default='APSD1E9M0', help=('Instance identyficator'))
@cli.command()
def register(host, local, id):
	""" Register consumer endpoint in producer system.
	"""
	global ticket

	if ticket := authenticate(host, local, id):
		if not ticket.error:
			logging.info('Identity establish sucess! %s', ticket)

@click.option('--host', is_flag=False, default=None, help=('Host or IP producer enclave.'))
@click.option('--local', is_flag=False, default='127.0.0.1', help=('Host or IP of local enclave.'))
@click.option('--id', is_flag=False, default='APSD1E9M0', help=('Instance identyficator'))
@click.option('--sleep', is_flag=False, default=0, help=('Delay between requests, in miliseconds.'))
@cli.command()
def consumer(host, local, id, sleep):
	""" API consumer demo - simple server with recurrent calls.
	"""
	global ticket

	while not hasattr(cli, 'terminated'):
		# before we request producer, let's generate valid token
		# for existing ticket in local armour
		if ticket := _token(id, ticket, local):
			if url := 'http://' + host + '/':
				if response := http.get(url, headers={'Content-Type': 'application/json',
													  'Connection': 'keep-alive',
													  'X-Ticket-ID': ticket.value,
													  'X-Token-ID': ticket.token},
											 json={'time': ticket.encrypt(time.time())},
										 	 verify=False):
					if json := response.json():
						# now, we need to stamp the current ticket,
						# to generate new one with valid encryption key
						if ticket := stamp(id, response, local):
							logging.info('Decrypted %s', ticket.decrypt(json.get('time')))
				else:
					logging.error('Faild.')
		time.sleep(int(sleep) / 1000)


@click.option('--host', is_flag=False, default=None, help=('Host or IP producer enclave.'))
@click.option('--local', is_flag=False, default='127.0.0.1', help=('Host or IP of local enclave.'))
@click.option('--id', is_flag=False, default='APSD1E9M0', help=('Instance identyficator'))
@cli.command()
def single(host, local, id):
	""" Make one single request.
	"""
	global ticket

	if ticket := _token(id, ticket, local):
		if url := 'http://' + host + '/':
			if response := http.get(url, headers={'Content-Type': 'application/json',
												  'Connection': 'keep-alive',
												  'X-Ticket-ID': ticket.value,
												  'X-Token-ID': ticket.token},
										 json={'time': ticket.encrypt(time.time())},
										 verify=False):
				if json := response.json():
					if ticket := stamp(id, response, local):
						logging.info('Decrypted %s', ticket.decrypt(json.get('time')))
			else:
				logging.error('Faild.')


@click.option('--host', is_flag=False, default=None, help=('Host or IP producer enclave.'))
@click.option('--local', is_flag=False, default='127.0.0.1', help=('Host or IP of local enclave.'))
@click.option('--id', is_flag=False, default='APSD1E9M0', help=('Instance identyficator'))
@cli.command()
def encrypted(host, local, id):
	""" Make enclave encrypted request.
	"""
	global ticket

	if ticket := _token(id, ticket, local):
		if url := 'http://' + host + '/encrypted':
			if response := requests.post(url, headers={'Content-Type': 'application/json',
													   'X-Ticket-ID': ticket.value,
													   'X-Token-ID': ticket.token},
											 json=dict(time=crypto(dict(payload=time.time()), 'encrypt', id, local)),
											 verify=False):
				if json := response.json():
					# now, we need to stamp the existing local ticket,
					# to generate new one for future
					if ticket := stamp(id, response, local):
						if response.headers.get('X-Ticket-ID') == ticket.value:
							print(json, crypto(dict(payload=json.get('time')), 'decrypt', id, local))


@click.option('--host', is_flag=False, default=None, help=('Host or IP producer enclave.'))
@click.option('--local', is_flag=False, default='127.0.0.1', help=('Host or IP of local enclave.'))
@click.option('--id', is_flag=False, default='APSD1E9M0', help=('Instance identyficator'))
@cli.command()
def compromise(host, local, id):
	""" Ticket interception simulation.
	"""
	global ticket

	while not hasattr(cli, 'terminated'):
		if ticket := _token(id, ticket, local):
			if url := 'http://' + host + '/':
				if response := requests.get(url, headers={'Content-Type': 'application/json',
														  'X-Ticket-ID': ticket.value,
														  'X-Token-ID': ticket.token},
												 json={'time': ticket.encrypt(time.time())},
												 verify=False):
					if json := response.json():
						# now, we need to stamp the existing local ticket,
						# to generate new one for future
						if ticket := stamp(id, response, local):
							print(json)
				else:
					logging.error('Faild.')
			time.sleep(100 / 1000)

