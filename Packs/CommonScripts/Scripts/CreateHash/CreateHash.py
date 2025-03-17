import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import hashlib
from hashlib import blake2b


def create_hash(text, hashtype):
    """Create a hash from a given input and return it as a context outputs

    Args:
        text (str): input to hash
        hashtype (str): hash type

    Returns:
        Dict[str,str]: Dictionary representing the command results context
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
        h = hashlib.md5()  # nosec
        h.update(text.encode('utf-8'))
    else:
        h = blake2b()  # type: ignore[assignment]
        h.update(text.encode('utf-8'))

    context = {
        "CreateHash": str(h.hexdigest())
    }

    return context


def main():  # pragma: no cover
    args = demisto.args()
    text = args.get('text')
    hashtype = args.get('type')

    context = create_hash(text, hashtype)
    return_results(CommandResults(outputs=context))


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
