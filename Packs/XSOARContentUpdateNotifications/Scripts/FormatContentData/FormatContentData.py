import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

args = demisto.args()
value = args.get('value', '')
try:
    value = json.loads(value)
except Exception as err:
    return_error(err)

returned_data = ''

if value:
    for v in value:
        description = v.get('changelog', {}).get(v.get('itemVersion'), {}).get('releaseNotes', '')
        returned_data += f"_____\n### {v.get('name')} (version {v.get('itemVersion')})\n_____\n\n{description}\n\n"

demisto.results(returned_data)
