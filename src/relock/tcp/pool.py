import sys
import socket
import signal

from dataclasses import dataclass
from ..xdh import XDH

@dataclass
class Connection:
	
	request: socket  = None
	xdh: XDH         = None
	addr: str        = tuple()

class Pool(list):

	length:int = 1024

	def __init__(self, host:str = str(), port:str = str(), size:int = 1):
		for x in range(size):
			self(host, port).__id__ = x

	def __enter__(self):
		return next(self)

	def __exit__(self, *args):
		pass

	def __call__(self, host, port):
		request = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		request.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		request.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
		request.connect((host, port))

		xdh = XDH()
		if public := request.recv(self.length):
			request.send(xdh.identity)
			xdh.exchange(public)

		if conn := Connection(request, xdh, (host, int(port))):
			self.append(conn)
			return conn

	def __iter__(self):
		return self

	def __next__(self):
		if not hasattr(self, '__id__') or self.__id__ >= len(self):
			self.__id__ = 0
		self.__id__ += 1
		if len(self):
			if conn := self[self.__id__ - 1]:
				try:
					conn.request.sendall(b'PING')
					if conn.request.recv(1024) != b'PONG':
						raise ConnectionResetError
				except:
					self.shutdown(conn)
					return next(self)
				else:
					return conn

	def __delete__(self):
		for id in range(len(self)):
			self.remove(self[0])

	def remove(self, conn):
		conn.request.close()
		super().remove(conn)

	def shutdown(self, conn):
		self(*conn.addr)
		self.remove(conn)
