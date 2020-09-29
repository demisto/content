
import demistomock as demisto
from hashlib import sha256
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]

DIGITS58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def decode_base58(bitcoin, length):
    n = 0
    for char in bitcoin:
        n = n * 58 + DIGITS58.index(char)
    return n.to_bytes(length, 'big')


def verify_is_bitcoin(bitcoin):
    try:
        bitcoin_bytes = decode_base58(bitcoin, 25)
        '''Check if the last four bytes are equal to the
        first four bytes of a double SHA-256 digest of the previous 21 bytes.'''
        return bitcoin_bytes[-4:] == sha256(sha256(bitcoin_bytes[:-4]).digest()).digest()[:4]
    except Exception:
        return False


def main():
    address_list = argToList(demisto.args().get('input'))
    list_results = []
    for address in address_list:
        if verify_is_bitcoin(address):
            list_results.append(address)
    if list_results:
        demisto.results(list_results)
    else:
        demisto.results("")


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
