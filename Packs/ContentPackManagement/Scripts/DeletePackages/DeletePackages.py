import demistomock as demisto
from CommonServerPython import *  # noqa: F401

args = demisto.args()
package_id = args.get('package_id')

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

# Delete the package using the package ID provided
full_url = urljoin(uris['deletePackage'], package_id)
res = demisto.executeCommand("demisto-api-delete", {"uri": full_url})[0]['Contents']
if type(res) == str:
    return_error(res)
else:
    demisto.results(f"Removed package {package_id} successfully")
