import binascii
import logging
import base64

from ..siv import SIV

class Ticket:
	
	def __init__(self, value:bytes = bytes(),
					   token:bytes = bytes(),
					   nonce:bytes = bytes(),
					   assoc:bytes = bytes(),
					   prior:bytes = bytes(),
					   bound:bytes = bytes(),
					   error:bool  = False):
		hex = lambda x: binascii.unhexlify(x) if x and not isinstance(x, bytes) else x

		self.value = hex(value)
		self.token = hex(token)
		self.nonce = hex(nonce)
		self.assoc = hex(assoc)
		self.prior = hex(prior)
		self.bound = hex(bound)
		self.error = error
		
		if self.error:
			logging.error(self.error)

	@property
	def key(self):
		return self.nonce

	@property
	def aead(self):
		return self.assoc

	@property
	def _key(self):
		return self.prior

	@property
	def _aead(self):
		return self.bound

	def encrypt(self, data: any) -> str:
		if self.key and self.aead and data:
			with SIV(self.key) as siv:
				return base64.b64encode(siv(self.aead).encrypt(data)).decode()
		return None

	def decrypt(self, data: str) -> any:
		if key := self._key if self.bound else self.key:
			if aead := self._aead if self.bound else self.aead:
				try:
					with SIV(key) as siv:
						_ = siv(aead).decrypt(base64.b64decode(data))
				except:
					return str()
				else:
					return _
		return None

	def headers(self):
		if self.token and self.value:
			return {'X-Ticket-ID': binascii.hexlify(self.value).decode(),
					'X-Key-ID': binascii.hexlify(self.token).decode()}
		return dict()

	def __bool__(self):
		return True if self.value else False

	def __iter__(self):
		return self

	def __next__(self):
		if not hasattr(self, '__id__'):
			self.__id__ = 0
		self.__id__ += 1
		if len(self.__dict__) and self.__id__ < len(self.__dict__):
			if item := list(self.__dict__)[self.__id__ - 1]:
				return (item, self.__dict__.get(item))
		raise StopIteration

	def __str__(self):
		if self.value:
			return binascii.hexlify(self.value).decode()
		return str()