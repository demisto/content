import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

args = demisto.args()
field = args.get('field')
form_type = args.get('formType')
options = ['All']
try:
    packs = demisto.executeCommand("demisto-api-get", {"uri": "/contentpacks/installed-expired"})[0]['Contents'].get('response')
    installed_packs = [x.get('name') for x in packs]
except Exception:
    installed_packs = []

installed_packs = sorted(installed_packs, key=str.casefold)
[options.append(x) for x in installed_packs]
demisto.results({"hidden": False, "options": options})
