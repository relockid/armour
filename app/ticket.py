import binascii

from dataclasses import dataclass
from .aes import SIV

@dataclass
class Ticket:
	value: str  = None
	token: str  = None
	nonce: str  = None
	assoc: str  = None
	prior: str  = None
	bound: str  = None
	error: bool = False

	@property
	def key(self):
		return binascii.unhexlify(self.nonce)

	@property
	def aead(self):
		return binascii.unhexlify(self.assoc)

	@property
	def _key(self):
		return binascii.unhexlify(self.prior)

	@property
	def _aead(self):
		return binascii.unhexlify(self.bound)

	def encrypt(self, data: any) -> str:
		with SIV(self.key) as siv:
			return siv(self.aead).encrypt(data)

	def decrypt(self, data: str) -> any:
		with SIV(self._key if self.prior else self.key) as siv:
			return siv(self._aead if self.prior else self.aead).decrypt(data)

	def headers(self):
		return {'X-Ticket-ID': self.value,
				'X-Token-ID': self.token,
				'X-ADDR-ID': request.remote_addr}