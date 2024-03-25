import sys
import time, logging
import requests
import socket
import pickle
import binascii
import hashlib
import base64

logging = logging.getLogger('armour.tcp.client')

from ..ticket import Ticket
from ..xdh import XDH

from .base import Base
from .pool import Pool

class TCP(Base):

	def __init__(self, host: str = None, 
					   port: str = None,
					   name: str = str(),
					   private: bool = True,
					   pool: int = 2):
		self.id      = None
		self.name    = name
		self.host    = host
		self.port    = int(port)
		self.addr    = bytes()
		self.private = private
		self.ticket  = Ticket()
		self.pool    = Pool(self.host, self.port, pool)
		self.allowed = list()

		logging.info('API armour TCP client %s:%s', host, port)

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
		with self.pool as conn:
			if not self.get():
				self.ticket = Ticket()
		return self.ticket.headers()

	def finalize(self, response):
		if self:
			for key, value in self.ticket.headers().items():
				response.headers.add(key, value)
		else:
			raise ValueError('Empty ticket on finalize.')

	def ask(self):
		with self.pool as conn:
			self._put(conn, dict(route='ticket', 
								 id=self.id))
			if ticket := Ticket(**self._get(conn)):
				self.ticket = ticket
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
		with self.pool as conn:
			try: 
				_ = binascii.unhexlify(ticket) #identity_bytes
			except:
				logging.error('Invalid data.')
			else:
				if self._put(conn, dict(route='save',
										value=self.id or _,
										token=_)):
					if ticket := self._get(conn):
						if not self.id:
							self.id = self.id or _
						self.ticket = Ticket(**ticket)
					else:
						logging.error('The ticket has been compromised.')
		return self.exchange(str(self.ticket))

	def verify(self, headers):
		with self.pool as conn:
			try:
				_ = binascii.unhexlify(headers.get('X-Ticket-ID'))
			except:
				pass
			else:
				if self._put(conn, dict(route='verificate',
										value=self.id or _,
										token=_)):
					if ticket := self._get(conn):
						self.ticket = Ticket(**ticket)
					else:
						self.ticket = Ticket()
		return self.ticket

	def get(self):
		with self.pool as conn:
			self._put(conn, dict(route='get',
								 value=self.id,
								 actual=self.ticket.value,
								 prior=self.ticket.prior))
			if ticket := self._get(conn):
				self.ticket = Ticket(**ticket)
		return self.ticket

	def init(self):
		with self.pool as conn:
			self._put(conn, dict(route='init',
								 value=self.id))
			if ticket := self._get(conn):
				self.ticket = Ticket(**ticket)
		return self.ticket

	def validate(self, path, headers, addr):
		if path in self.allowed:
			return True
		if headers.get('X-Ticket-ID'):
			with self.pool as conn:
				try:
					ticket = binascii.unhexlify(headers.get('X-Ticket-ID'))
					token = binascii.unhexlify(headers.get('X-Key-ID'))
				except:
					return True if not self.private else False
				else:
					self._put(conn, dict(route='validate',
										 value=ticket,
										 token=token,
										 addr=addr))
					if ticket := self._get(conn):
						self.ticket = Ticket(**ticket)
						return self.ticket if not self.ticket.error else False
					elif headers.get('X-Ticket-ID'):
						return False
		return True if not self.private else False

	def stamp(self, headers):
		with self.pool as conn:
			if _ := self._put(conn, dict(route='stamp',
									     id=self.id,
									     value=binascii.unhexlify(headers.get('X-Ticket-ID')),
									     token=binascii.unhexlify(headers.get('X-Key-ID')))):
				if ticket := self._get(conn):
					self.ticket = Ticket(**ticket)
		return self.ticket

	def encrypt(self, data, enclave=False):
		if enclave:
			with self.pool as conn:
				if self._put(conn, dict(route='encrypt',
									    ticket=self.id or self.ticket.value,
									    payload=data)):
					return base64.b64encode(self._get(conn)).decode()
		return self.ticket.encrypt(data)

	def decrypt(self, data, enclave=False):
		if enclave:
			with self.pool as conn:
				if self._put(conn, dict(route='decrypt',
								        ticket=self.id or self.ticket.value,
								        payload=base64.b64decode(data))):
					return self._get(conn)
		return self.ticket.decrypt(data)