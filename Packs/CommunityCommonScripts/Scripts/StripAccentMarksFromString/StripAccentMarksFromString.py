import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import unicodedata


string = demisto.args()["value"]
normalized = unicodedata.normalize('NFKD', string)
res = ""
for character in normalized:
    if not unicodedata.combining(character):
        res += character
demisto.results(res)
