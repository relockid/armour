""" Active API Armour TCP/HTTP client.
"""

# By Marcin Sznyra, marcin(at)relock.id, 2024.
#    re:lock B.V. Blaak 16, 3011TA, Rotterdam. KVK: 91870879.

#                        #### WARNING ####

# Since this code makes use of Python's built-in large integer types, it is 
# NOT EXPECTED to run in constant time. While some effort is made to minimise 
# the time variations, the underlying functions are likely to have running 
# times that are highly value-dependent.

__version__ = "0.1.3"
__author__ = 'Marcin Sznyra'
__credits__ = 're:lock B.V.'

from .tcp import TCP
from .http import HTTP
from .gcm import GCM
from .siv import SIV