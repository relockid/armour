import os
import pickle
import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from typing import Any

class GCM(object):

	def __init__(self, key:bytes, iv:bytes = None):
		self.aes = AESGCM(key[0:32])
		self.__iv = iv

	def __call__(self, aead:bytes, iv:bytes = None):
		self.aead = aead
		self.__iv = iv or os.urandom(12)
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
			self.__iv = os.urandom(12)
		return self.__iv

	@property
	def auth(self):
		if not 'aead' in self.__dict__:
			self.aead = bytes(1)
		return self.aead

	def encrypt(self, data:Any) -> str:
		return self.iv + self.aes.encrypt(self.iv, pickle.dumps(data), self.auth)

	def decrypt(self, data:str) -> Any:
		return pickle.loads(self.aes.decrypt(data[:12], data[12:], self.auth))

	def __str__(self):
		return 'AES/GCM/128'