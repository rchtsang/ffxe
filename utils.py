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

