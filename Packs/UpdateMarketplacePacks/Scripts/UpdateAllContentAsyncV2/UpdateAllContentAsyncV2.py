from concurrent.futures import ThreadPoolExecutor, as_completed
from time import time

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Version check
dver = get_demisto_version()['version']
if int(dver.split(".")[0]) < 6:
    print("Please confirm server version is > 6.0")
    sys.exit()

# Global var for storing info of all installed packages
PACKAGE_LIST = []


def major_minor_micro(version):
    """
    Max function key method
    """
    major, minor, micro = re.search('(\d+)\.(\d+)\.(\d+)', version).groups()
    return int(major), int(minor), int(micro)


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


def checkDependencies(dep):
    """
    Returns True if all dependencies exist and version is > min version, False otherwise
    """
    for depname, values in dep.items():
        # Min Version needed: ver
        ver = values['minVersion']
        for pack in PACKAGE_LIST:
            if depname == pack['id']:
                # Name of dependency: depname
                # Currently installed version: pack['currentVersion'])
                # IS Current version newest?
                if pack['currentVersion'] != max([pack['currentVersion'], ver], key=major_minor_micro):
                    return False
    return True


def update_package(single_item):
    """
    Updates a single package on the marketplace
    Added dependency management, do not update if dependency is not installed
    """
    change_log_keys = list(single_item['changelog'].keys())
    # Grab the latest version
    latest_ver = max(change_log_keys, key=major_minor_micro)
    # Grab Name of package
    id_item = single_item['id']
    # Grab dependencies of package
    dependencies = single_item['dependencies']
    # True for good to update, False for dependency missing
    boolres = checkDependencies(dependencies)
    if not boolres:
        print(f"Dependency missing from {id_item}, skipping.. Please update {id_item} manually")
        return boolres
    data = {
        "packs": [{
            "id": id_item,
            "version": latest_ver,
            "transition": None,
            "skipInstall": False
        }],
        "ignoreWarnings": False,
        "transitionPrice": 0
    }
    demisto.executeCommand("demisto-api-post", {"uri": "/contentpacks/marketplace/install",
                                                "body": json.dumps(data)})[0]['Contents']
    return boolres


def update_packs(packs_to_update):
    """
    Updates marketplace packages
    """
    start = time()
    for i in range(2):
        if packs_to_update:
            processes = []
            with ThreadPoolExecutor(max_workers=50) as executor:
                for i in packs_to_update:
                    processes.append(executor.submit(update_package, i))

    demisto.results(f'Done with content update, time taken: {time() - start}')


update_all = demisto.args().get('update_all_packages')
if update_all == "no":
    pack_list = demisto.args().get('packages').split(',')
    if not pack_list:
        demisto.results("No packs submitted, make sure to send in a comma seperated list of packs to update")
    else:
        packs_to_update = [i for i in packages_to_update() if i['name'] in pack_list]
        update_packs(packs_to_update)
else:
    packs_to_update = packages_to_update()
    update_packs(packs_to_update)
