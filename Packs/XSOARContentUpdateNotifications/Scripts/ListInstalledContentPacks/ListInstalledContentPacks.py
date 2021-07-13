import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

args = demisto.args()
updated = True if args.get('updates') == 'true' else False

packs = demisto.executeCommand("demisto-api-get", {"uri": "/contentpacks/installed-expired"})[0]['Contents'].get('response')
parsed_packs = [{
    "name": x.get('name'),
    "version": x.get('currentVersion'),
    "update": x.get('updateAvailable', False)
} for x in packs]

if updated:
    parsed_packs[:] = [x for x in parsed_packs if x.get('update')]

command_results = CommandResults(
    outputs_prefix="InstalledPacks",
    outputs_key_field="name",
    outputs=parsed_packs,
    readable_output=tableToMarkdown("Installed Content Packs:", parsed_packs, ["name", "version", "update"])
)

return_results(command_results)
