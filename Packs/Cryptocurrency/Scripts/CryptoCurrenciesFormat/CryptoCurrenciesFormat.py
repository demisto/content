import demistomock as demisto
from hashlib import sha256
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]

from typing import Union

DIGITS58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def decode_base58(address, length) -> bytes:
    n = 0
    for char in address:
        n = n * 58 + DIGITS58.index(char)
    return n.to_bytes(length, 'big')


def verify_is_bitcoin(address) -> Union[bytes, bool]:
    try:
        bitcoin_bytes = decode_base58(address, 25)
        '''Check if the last four bytes are equal to the
        first four bytes of a double SHA-256 digest of the previous 21 bytes.
        Source: https://rosettacode.org/wiki/Bitcoin/address_validation#Python '''
        return bitcoin_bytes[-4:] == sha256(sha256(bitcoin_bytes[:-4]).digest()).digest()[:4]
    except Exception:
        return False


def main():
    address_list = argToList(demisto.args().get('input'))

    list_results = [f'bitcoin-{address}' for address in address_list if verify_is_bitcoin(address)]

    if list_results:
        demisto.results(list_results)
    else:
        demisto.results('')


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
