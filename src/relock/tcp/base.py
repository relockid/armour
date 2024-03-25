import pickle
import logging

from typing import Any

class Base(object):

	length = 1024

	def _get(self, conn, _: bytes = bytes()):
		try:
			while slice := conn.request.recv(Base.length):
				_ += slice
				if len(slice) < Base.length:
					break
		except ConnectionResetError:
			_ = bytes(1)
		finally:
			if not _:
				self.pool.shutdown(conn)
			elif _ == b'PING':
				conn.request.sendall(b'PONG')
			else:
				_ = conn.xdh.decrypt(_)
				if _ == b'SHUTDOWN':
					self.pool.shutdown(conn)
		return _

	def _put(self, conn, data: Any = bytes(), offset: int = 0) -> Any:
		if data == b'PING':
			conn.request.sendall(data);  offset += Base.length
		elif _ := conn.xdh.encrypt(data):
			while not offset >= len(_):
				if slice := _[offset:offset + Base.length]:
					conn.request.send(slice); offset += Base.length
		return offset
