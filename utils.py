import os
import sys
import logging
import itertools
from typing import Union, Type

def chunks(n, b : Union[bytes, bytearray]):
    """
    generator utility function for iterating over 
    chunks of a byte string
    """
    it = iter(b)
    while True:
        chunk = bytes(itertools.islice(it, n))
        if not chunk:
            return
        yield chunk

def ipy_hexon():
    formatter = get_ipython().display_formatter.formatters['text/plain']
    formatter.for_type(int, lambda n, p, cycle: p.text("0x%x"%n))

def ipy_hexoff():
    formatter = get_ipython().display_formatter.formatters['text/plain']
    formatter.for_type(int, lambda n, p, cycle: p.text("%d"%n))

    