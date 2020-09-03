
import demistomock as demisto
from hashlib import sha256

DIGITS58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def decode_base58(bitcoin, length):
    n = 0
    for char in bitcoin:
        n = n * 58 + DIGITS58.index(char)
    return n.to_bytes(length, 'big')


def verify_is_bitcoin(bitcoin):
    try:
        bitcoin_bytes = decode_base58(bitcoin, 25)
        return bitcoin_bytes[-4:] == sha256(sha256(bitcoin_bytes[:-4]).digest()).digest()[:4]
    except Exception:
        return False


def main():
    address = demisto.args().get('input')

    if verify_is_bitcoin(address):
        demisto.results(address)


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
