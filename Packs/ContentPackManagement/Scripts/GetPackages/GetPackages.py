import demistomock as demisto
from CommonServerPython import *  # noqa: F401

demisto_version = demisto.demistoVersion()
version = demisto_version['version']

version_matrix = {
    "6.0.0": {
        "getInstalled": "/contentpacks/installed-expired",
        "getAll": "/contentpacks/marketplace/search",
        "deletePackage": "/contentpacks/installed/",
        "getDependancies": "/contentpacks/marketplace/search/dependencies",
        "updatePackage": "/contentpacks/marketplace/install"
    }
}

uris = version_matrix[str(version)]

# Get and output installed content packs
res = demisto.executeCommand("demisto-api-get", {"uri": uris['getInstalled']})[0]['Contents']['response']
installed_packs = [{
    "name": x['name'],
    "id": x['id'],
    "author": x['author'],
    "updateAvailable": x['updateAvailable'],
    "updated": x['updated']} for x in res]
command_results = CommandResults(
    outputs_prefix="ContentPacks.Installed",
    outputs_key_field=['id'],
    outputs=installed_packs,
    readable_output=tableToMarkdown("Installed Content Packs:", [
                                    {"Name": x['name'], "ID": x['id']} for x in installed_packs], ['Name', 'ID'])
)
return_results(command_results)
