import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

args = demisto.args()
value = args.get('value', '')
timeout = int(args.get('timeout', 10))

if type(value) != dict:
    try:
        value = json.loads(value)
    except:
        return_error("Invalid input")

custom_fields = value.get('CustomFields', {})
feed_related_indicators = custom_fields.get('feedrelatedindicators', [])

usernames = [x.get('value') for x in feed_related_indicators if x.get('type') == "Account"]
ip = value.get('value', None)

mappings = []

if usernames and ip:
    for username in usernames:
        mappings.append(f"<entry name=\"{username}\" ip=\"{ip}\" timeout=\"{timeout}\"></entry>")
    demisto.results(" ".join(mappings))
else:
    demisto.results(None)
