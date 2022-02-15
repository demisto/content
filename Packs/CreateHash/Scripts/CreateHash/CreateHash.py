# Simple script to create a sha256 hash from agiven input
import hashlib
from hashlib import blake2b

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

text = demisto.args()['text']
hashtype = demisto.args()['type']

if hashtype == "sha256":
    h = hashlib.sha256()
    h.update(text.encode('utf-8'))
elif hashtype == 'sha1':
    h = hashlib.sha1()
    h.update(text.encode('utf-8'))
elif hashtype == 'md5':
    h = hashlib.md5()
    h.update(text.encode('utf-8'))
else:
    h = blake2b()
    h.update(text.encode('utf-8'))

context = {
    "CreateHash": str(h.hexdigest())
}
command_results = CommandResults(outputs=context)

return_results(command_results)
