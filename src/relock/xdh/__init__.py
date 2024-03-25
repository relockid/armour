""" 
"""

# By Marcin Sznyra, marcin(at)relock.id, 2023.
#    re:lock B.V. Blaak 16, 3011TA, Rotterdam. KVK: 91870879.

#                        #### WARNING ####

# Since this code makes use of Python's built-in large integer types, it is 
# NOT EXPECTED to run in constant time. While some effort is made to minimise 
# the time variations, the underlying functions are likely to have running 
# times that are highly value-dependent.

import logging
import hashlib
import os
import random
import sys
import pickle
import base64

from typing import Any

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric import ed25519

from ..gcm import GCM

class XDH(object):

	""" return None
	"""
	def __init__(self, *args,
					    iv: bytes = None,
					    power:int = 32):
		self.power    = power
		self.matrix   = args if len(args) else (os.urandom(power),)
		self(iv)

	@property
	def iv(self):
		return self.__iv

	@iv.setter
	def iv(self, value):
		self.__iv = value or os.urandom(16)

	@property
	def matrix(self):
		return self.__matrix

	@matrix.setter
	def matrix(self, args):
		self.__matrix = bytes()
		for _ in args:
			self.__matrix += _
		self.salt   = self.__matrix
		self.aead   = self.__matrix
		self.key    = self.__matrix
		self.engine = GCM(self.key)

	def __enter__(self):
		return self
 
	def __exit__(self, *args):
		del self.__iv

	""" return object self
	"""
	def __call__(self, iv:bytes = None):
		self.iv = iv or os.urandom(16)
		return self

	@property
	def salt(self):
		return bytes(self.__salt)

	@salt.setter
	def salt(self, value):
		if _ := sum(value):
			self.__salt = _.to_bytes((_.bit_length() + 7) // 8, 'little')

	@property
	def key(self):
		return bytes(self.__key)

	@key.setter
	def key(self, value):
		self.__key = hashlib.blake2b(value,
									 salt=self.salt,
									 digest_size=self.power).digest()

	@property
	def aead(self):
		""" returns 128 bits hash
		"""
		return bytes(self.__aead)

	@aead.setter
	def aead(self, value:bytes = bytes()):
		self.__aead = HKDFExpand(algorithm=hashes.SHA512(),
							     length=self.power,
							     info=self.salt).derive(value)

	@property
	def id(self):
		""" returns 128 bits hash
		"""
		return HKDFExpand(algorithm=hashes.SHA256(),
					      length=16,
					      info=self.salt).derive(self.key)

	def sign(self, data:bytes) -> bytes:
		return self.ed25519.sign(data)

	def verify(self, data:bytes, signature:bytes) -> bool:
		try:
			self.ed25519.public_key().verify(signature, data)
		except:
			return False
		else:
			return True

	@property
	def public(self):
		return self.ed25519.public_key().public_bytes(
		    encoding=serialization.Encoding.Raw,
		    format=serialization.PublicFormat.Raw
		)

	@property
	def identity(self):
		return self.x25519.public_key().public_bytes(
		    encoding=serialization.Encoding.Raw,
		    format=serialization.PublicFormat.Raw
		)

	@property
	def x25519(self):
		return x25519.X25519PrivateKey.from_private_bytes(self.key)

	@property
	def ed25519(self):
		return ed25519.Ed25519PrivateKey.from_private_bytes(self.key)

	def exchange(self, hex):
		if public := x25519.X25519PublicKey.from_public_bytes(hex):
			if shared := self.x25519.exchange(public):
				if _ := HKDF(algorithm=hashes.SHA256(),
						     length=32,
						     salt=None,
						     info=b'handshake data',
						).derive(shared):
					self.matrix = (_,)
		return self

	""" return bytes, ciphertext
	"""
	def encrypt(self, data: Any) -> Any:
		with self.engine(self.aead) as engine:
			return engine.encrypt(data)
		return bytes()
	
	""" return bytes, plaintext
	"""
	def decrypt(self, data: Any) -> Any:
		try:
			with self.engine(self.aead) as engine:
				_ = engine.decrypt(data)
		except:
			return bytes()
		else:
			return _
			
	def __str__(self):
		return 'XDH'
