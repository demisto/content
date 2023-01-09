
import hashlib
from hashlib import blake2b

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def create_hash(text, hashtype):
    """Create a sha256 hash from a given input

    Args:
        text (str): input to hash
        hashtype (str): hash type
    """
    if hashtype == "sha512":
        h = hashlib.sha512()
        h.update(text.encode('utf-8'))
    elif hashtype == "sha256":
        h = hashlib.sha256()
        h.update(text.encode('utf-8'))
    elif hashtype == 'sha1':
        h = hashlib.sha1()  # nosec
        h.update(text.encode('utf-8'))
    elif hashtype == 'md5':
        h = hashlib.md5()   # nosec
        h.update(text.encode('utf-8'))
    else:
        h = blake2b()
        h.update(text.encode('utf-8'))

    context = {
        "CreateHash": str(h.hexdigest())
    }
    command_results = CommandResults(outputs=context)

    return_results(command_results)


def main():
    args = demisto.args()
    text = args.get('text')
    hashtype = args.get('type')
    create_hash(text, hashtype)


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
