import hashlib

import demistomock as demisto
from CommonServerPython import *

hash_object = hashlib.sha256(b'this is a test message we should hash and it should take time to test 1')
hash = hash_object.hexdigest()
demisto.results({
    'Type': 1,
    'ContentsFormat': 'text',
    'Contents': hash
})
