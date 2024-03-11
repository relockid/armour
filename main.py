#!/usr/bin/python3
import sys
import os
import signal
import logging
import time

from gevent import monkey

monkey.patch_all()

from app import cli

if __name__ == "__main__":

	def signal_handler(signal, frame):
		logging.info('Terminated.')
		setattr(cli, 'terminated', time.time())
	signal.signal(signal.SIGINT, signal_handler)

	""" managment tools. """
	cli()
	