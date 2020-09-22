import demistomock as demisto
from CommonServerPython import *  # noqa: F401

args = demisto.args()
package_id = args.get('package_id')
packs = list()
dependencies = list()

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

# Get all packages
all_packages = demisto.executeCommand("demisto-api-post", {"uri": uris['getAll'], "body": {}})[0]['Contents']['response']['packs']

# Get installed packages
installed_packages = demisto.executeCommand("demisto-api-get", {"uri": uris['getInstalled']})[0]['Contents']['response']

# Get the package that needs to be installed / updated
package = [x for x in all_packages if x['id'] == package_id]
if not package:
    return_error("Could not find package to update")
else:
    package = package[0]
versions = [k for k, v in package['changelog'].items()]
version = sorted(versions, reverse=True)[0]
packs.append({
    "id": package['id'],
    "version": version,
    "transition": None,
    "skipInstall": False
})

# If there are dependencies, then evaluate that we have them
if package['dependencies']:

    # Get all the dependencies
    for k, v in package['dependencies'].items():

        # Get the dependency details
        dependency = [x for x in all_packages if x['id'] == k][0]
        available_versions = [k for k, v in dependency['changelog'].items()]
        available_version = sorted(available_versions, reverse=True)[0]
        required_version = v['minVersion']

        # Check to see if the dependency is installed
        if dependency['id'] not in [x['id'] for x in installed_packages]:
            dependencies.append({
                "id": k,
                "version": available_version,
                "transition": None
            })
        else:
            # Get our installed version
            installed_dependency = [x for x in installed_packages if x['id'] == k][0]
            installed_version = installed_dependency['itemVersion']
            if installed_version != sorted([required_version, installed_version], reverse=True)[0]:
                dependencies.append({
                    "id": k,
                    "version": available_version,
                    "transition": None
                })

# Create the body for the request
body = {
    "ignoreWarning": True,
    "packs": packs + dependencies,
    "transitionPrice": 0
}


update = demisto.executeCommand("demisto-api-post", {"uri": uris['updatePackage'], "body": body})[0]['Contents']
if type(update) == str:
    return_error(update)
else:
    demisto.results(f"Package {package_id} (and dependencies) successfully updated")
