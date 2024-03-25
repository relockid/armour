import os
import pickle
import base64

from cryptography.hazmat.primitives.ciphers.aead import AESSIV

from typing import Any

class SIV(object):

	def __init__(self, key:bytes, iv:bytes = None):
		self.aes = AESSIV(key)
		self.__iv = iv

	def __call__(self, aead:bytes, iv:bytes = None):
		self.aead = aead
		self.__iv = iv or os.urandom(16)
		return self

	def __enter__(self):
		return self
 
	def __exit__(self, *args):
		if 'aead' in self.__dict__:
			del self.aead
		if '__iv' in self.__dict__:
			del self.__iv

	@property
	def iv(self):
		if not self.__iv:
			self.__iv = os.urandom(16)
		return self.__iv

	@property
	def auth(self):
		if not 'aead' in self.__dict__:
			self.aead = bytes(1)
		return self.aead

	def encrypt(self, data:Any) -> bytes:
		return self.iv + self.aes.encrypt(pickle.dumps(data), [self.auth, self.iv])

	def decrypt(self, data:bytes) -> Any:
		return pickle.loads(self.aes.decrypt(data[16:], [self.auth, data[:16]]))

	def __str__(self):
		return 'AES/SIV/256'