import json
import random
import string
import time

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def create_entry(title, data, ec):
    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': data,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, data) if data else 'No result were found',
        'EntryContext': ec
    }


def create_error_entry(error):
    return {
        'Type': entryTypes['error'],
        'ContentsFormat': formats['text'],
        'Contents': str(error)
    }


length = int(demisto.args()["Length"])
punctuation = demisto.args()["Punctuation"]
lowercase = demisto.args()["Lowercase"]
uppercase = demisto.args()["Uppercase"]
digits = demisto.args()["Digits"]

characters = ""
if length > 0:
    if uppercase == "True" or lowercase == "True" or digits == "True" or punctuation == "True":

        if lowercase == "True":
            characters += string.ascii_lowercase

        if uppercase == "True":
            characters += string.ascii_uppercase

        if digits == "True":
            characters += string.digits

        if punctuation == "True":
            characters += string.punctuation

    else:
        demisto.results(create_error_entry("Punctuation,Digits,Uppercase or Lowercase must be True."))
        sys.exit(0)
else:
    demisto.results(create_error_entry("Length must be grather than 0."))
    sys.exit(0)

password = ""
for x in range(0, length):
    password += random.SystemRandom(random.seed(time.time())).choice(characters)

raw = {"RandomString": password}
raw = json.loads(json.dumps(raw))
ec = {'RandomString': password}
demisto.results(create_entry('RandomString Generated.', raw, ec))
