import hashlib


def base58_decode(v):
    digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = 0
    for ch in v:
        num = num * 58 + digits.index(ch)
    return num.to_bytes(25, byteorder='big')


def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()
