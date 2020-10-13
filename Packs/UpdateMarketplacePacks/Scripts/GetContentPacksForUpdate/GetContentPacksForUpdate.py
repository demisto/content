import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Version check
dver = get_demisto_version()['version']
if int(dver.split(".")[0]) < 6:
    print("Please confirm server version is > 6.0")
    sys.exit()


def packages_to_update():
    """
    Returns a list of packages that needs to be updated on the Marketplace
    """
    global PACKAGE_LIST
    response = demisto.executeCommand("demisto-api-get", {"uri": "/contentpacks/installed-expired"})[0]['Contents'][
        'response']
    # Store packages in global var
    PACKAGE_LIST = response
    # Get list of packages to update, checking the updateAvailable field == True
    packages_to_update = [i for i in response if i['updateAvailable']]
    return packages_to_update


# Get Packs, return list of Packs...
packs_to_update = packages_to_update()
packs = [i['name'] for i in packs_to_update]
results = CommandResults(
    readable_output=tableToMarkdown('Packs with updates', packs, headers="Packs"),
    outputs_prefix='Marketplace.PacksToUpdate',
    outputs=packs
)
return_results(results)
