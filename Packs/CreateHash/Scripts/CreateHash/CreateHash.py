# Simple script to create a sha256 hash from agiven input
import hashlib

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
    h = hashlib.blake2b()
    h.update(text.encode('utf-8'))

demisto.setContext("CreateHash", h.hexdigest())
return_results(h.hexdigest())
