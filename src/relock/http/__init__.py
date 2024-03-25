import sys
import time
import pickle
import requests
import hashlib
import logging
import os
import binascii
import base64

from ..ticket import Ticket

from typing import Any

logging = logging.getLogger('armour.http.client')

""" Key distribution is problematic anyway, even not valid cerytficate
	gives TLS encryption and it's worth to use it.
"""
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

class HTTP(object):

	def __init__(self, host: str = None, 
					   port: str = None,
					   name: str = str(),
					   private: bool = True,
					   pool: int = 1):
		self.id      = None
		self.name    = name
		self.host    = host
		self.port    = str(port)
		self.private = private
		self.http    = requests.Session()
		self.ticket  = Ticket()
		self.pool    = 'https://' + self.host
		self.allowed = list()

		logging.info('API armour HTTP client %s:%s', host, port)

	def __call__(self, ticket:str = str(), host:str = str(), port:int = int(), schema:str = 'http'):
		self.addr = schema + '://' + host + ((':' + str(port)) if port else str())
		self.id = hashlib.blake2b((self.addr + self.name).encode(), salt=host.encode(),
							   		 								digest_size=16).digest()
		if not self.ticket and ticket:
			self.save(ticket.encode())
		return self

	def __enter__(self):
		return self

	def __exit__(self, *args):
		pass

	def allow(self, rule, **options):
		self.allowed.append(rule)
		def decorator(f):
			return f
		return decorator

	def headers(self):
		with self as conn:
			if not self.get():
				self.ticket = Ticket()
		return self.ticket.headers()

	def finalize(self, response):
		if self.ticket:
			for key, value in self.ticket.headers().items():
				response.headers.add(key, value)
		self.ticket = Ticket()
		return response

	def ask(self):
		with self as conn:
			if response := conn.http.get(conn.pool + '/ticket', 
										 headers={'Content-Type': 'application/json',
												  'Connection': 'keep-alive',
												  'X-Ticket-ID': binascii.hexlify(self.id)},
										 json={'route': 'ticket'},
										 verify=False):
				if ticket := response.json():
					self.ticket = Ticket(**ticket)
		return self.ticket

	def exchange(self, ticket):
		if response := requests.get(str(self.addr),
									headers={'Content-Type': 'application/json',
									 		  **self.ticket.headers()},
									json={}):
			if ticket := self.verify(response.headers):
				logging.info('Key exchange success.')
				self.ticket = ticket
		return self.ticket

	def save(self, ticket):
		with self as conn:
			try: 
				_ = binascii.unhexlify(ticket)
			except:
				logging.error('cannot unhexlify')
			else:
				if response := conn.http.post(conn.pool + '/save', 
											  headers={'Content-Type': 'application/json',
													   'Connection': 'keep-alive',
													   'X-Ticket-ID': binascii.hexlify(self.id or _).decode(),
													   'X-Key-ID': binascii.hexlify(_).decode()},
											  json={},
											  verify=False):
					if ticket := response.json():
						if not self.id:
							self.id = self.id or _
						self.ticket = Ticket(**ticket)
		return self.exchange(str(self.ticket))

	def init(self):
		with self as conn:
			if response := conn.http.post(conn.pool + '/init', 
										  headers={'Content-Type': 'application/json',
												   'Connection': 'keep-alive',
												   'X-Ticket-ID': binascii.hexlify(self.id).decode()},
										  json={'route': 'init'},
										  verify=False):
				if ticket := response.json():
					self.ticket = Ticket(**ticket)
					self.ticket.prior = None
		return self.ticket

	def validate(self, path, headers, addr):
		self.ticket = Ticket()
		if path in self.allowed:
			return True
		if headers.get('X-Ticket-ID'):
			with self as conn:
				if response := conn.http.post(conn.pool + '/validate', 
											  headers={'Content-Type': 'application/json',
													   'Connection': 'keep-alive',
													   'X-Ticket-ID': headers.get('X-Ticket-ID'),
													   'X-Key-ID': headers.get('X-Key-ID'),
													   'X-ADDR-ID': addr},
											  json={'route': 'validate'},
											  verify=False):
					if ticket := response.json():
						self.ticket = Ticket(**ticket)
		return True if not self.private or bool(self.ticket) else False

	def verify(self, headers):
		with self as conn:
			try:
				_ = binascii.unhexlify(headers.get('X-Ticket-ID'))
			except:
				pass
			else:
				if response := conn.http.post(conn.pool + '/verificate', 
											  headers={'Content-Type': 'application/json',
													   'Connection': 'keep-alive',
													   'X-Ticket-ID': binascii.hexlify(self.id).decode(),
													   'X-Key-ID': headers.get('X-Ticket-ID')},
											  json={'route': 'verificate'},
											  verify=False):
					if ticket := Ticket(**response.json()):
						if ticket.error:
							self.ticket = Ticket()
						else:
							self.ticket = ticket
		return self.ticket

	def get(self):
		with self as conn:
			if response := conn.http.post(conn.pool + '/get', 
										  headers={'Content-Type': 'application/json',
												   'Connection': 'keep-alive',
												   'X-Ticket-ID': binascii.hexlify(self.id).decode(),
												   'X-Actual-ID': binascii.hexlify(self.ticket.value).decode(),
												   'X-Prior-ID': binascii.hexlify(self.ticket.prior).decode() if self.ticket.prior else None},
										  json={'route': 'get'},
										  verify=False):
				if ticket := response.json():
					self.ticket = Ticket(**ticket)
		return self.ticket

	def init(self):
		with self as conn:
			if response := conn.http.post(conn.pool + '/init', 
										  headers={'Content-Type': 'application/json',
												   'Connection': 'keep-alive',
												   'X-Ticket-ID': binascii.hexlify(self.id).decode()},
										  json={'route': 'init'},
										  verify=False):
				if ticket := response.json():
					self.ticket = Ticket(**ticket)
		return self.ticket

	def stamp(self, headers):
		with self as conn:
			if response := conn.http.post(conn.pool + '/stamp', 
										  headers={'Content-Type': 'application/json',
												   'Connection': 'keep-alive',
												   'X-Name-ID': binascii.hexlify(self.id).decode(),
												   'X-Ticket-ID': headers.get('X-Ticket-ID'),
												   'X-Key-ID': headers.get('X-Key-ID')},
										  json={'route': 'stamp'},
										  verify=False):
				if ticket := response.json():
					self.ticket = Ticket(**ticket)
		return self.ticket

	def encrypt(self, data, enclave=False):
		if enclave:
			with self as conn:
				if response := conn.http.post(conn.pool + '/crypto/encrypt', 
											  headers={'Content-Type': 'application/json',
													   'Connection': 'keep-alive',
													   'X-Ticket-ID': binascii.hexlify(self.id or self.ticket.value).decode()},
											  json={'payload': binascii.hexlify(pickle.dumps(data)).decode()},
											  verify=False):
					if json := response.json():
						if not json.get('error'):
							return json.get('payload')
		return self.ticket.encrypt(data)

	def decrypt(self, data, enclave=False):
		if enclave:
			with self as conn:
				if response := conn.http.post(conn.pool + '/crypto/decrypt', 
											  headers={'Content-Type': 'application/json',
													   'Connection': 'keep-alive',
													   'X-Ticket-ID': binascii.hexlify(self.id or self.ticket.value).decode()},
											  json={'payload': data},
											  verify=False):
					if json := response.json():
						return pickle.loads(binascii.unhexlify(json.get('payload')))
		return self.ticket.decrypt(data)