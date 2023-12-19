''' Various utilities from converting between formats '''

from math import ceil


def bytes_to_int(text: bytes):
    return int.from_bytes(text, 'big')


def int_to_bytes(num: int):
    return int.to_bytes(num, ceil(num.bit_length()/8), "big")
