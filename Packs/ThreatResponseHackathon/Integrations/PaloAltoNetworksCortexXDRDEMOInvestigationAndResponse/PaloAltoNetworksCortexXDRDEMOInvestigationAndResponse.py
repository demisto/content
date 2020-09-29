from typing import Any, Dict, List, Optional, Tuple

import demistomock as demisto
from CommonServerPython import *  # noqa: F401

DEVICE_GROUP = demisto.params().get('device_group', None)


def prettify_address_group(address_group: Dict) -> Dict:
    pretty_address_group = {
        'Name': address_group['@name'],
        'Type': 'static' if 'static' in address_group else 'dynamic'
    }
    if DEVICE_GROUP:
        pretty_address_group['DeviceGroup'] = DEVICE_GROUP

    if 'description' in address_group:
        pretty_address_group['Description'] = address_group['description']
    if 'tag' in address_group and 'member' in address_group['tag']:
        pretty_address_group['Tags'] = address_group['tag']['member']

    if pretty_address_group['Type'] == 'static':
        pretty_address_group['Addresses'] = address_group['static']['member']
    else:
        pretty_address_group['Match'] = address_group['dynamic']['filter']

    return pretty_address_group


def prettify_address_groups_arr(address_groups_arr: list) -> List:
    if not isinstance(address_groups_arr, list):
        return prettify_address_group(address_groups_arr)
    pretty_address_groups_arr = []
    for address_group in address_groups_arr:
        pretty_address_group = {
            'Name': address_group['@name'],
            'Type': 'static' if 'static' in address_group else 'dynamic'
        }
        if DEVICE_GROUP:
            pretty_address_group['DeviceGroup'] = DEVICE_GROUP
        if 'description' in address_group:
            pretty_address_group['Description'] = address_group['description']
        if 'tag' in address_group and 'member' in address_group['tag']:
            pretty_address_group['Tags'] = address_group['tag']['member']

        if pretty_address_group['Type'] == 'static':
            # static address groups can have empty lists
            if address_group['static']:
                pretty_address_group['Addresses'] = address_group['static']['member']
        else:
            pretty_address_group['Match'] = address_group['dynamic']['filter']

        pretty_address_groups_arr.append(pretty_address_group)

    return pretty_address_groups_arr


def ad_enable_account_command():
    user = demisto.args().get('username')
    demisto.results('User ' + user + ' was enabled')


def ad_disable_account_command():
    user = demisto.args().get('username')
    demisto.results('User ' + user + ' was disabled')


def panorama_get_address_group_command():
    address_group_name = demisto.args()['name']
    result = {
        "@name": address_group_name,  # "Demisto-Blocked-IPs",
        "description": "IPs Blocked by Demisto Workflow",
        "static": {
            "member": "Block-Default-Entry"
        }
    }
    context = {
        "Addresses": "Block-Default-Entry",
        "Description": "IPs Blocked by Demisto Workflow",
        "Name": address_group_name,  # "Demisto-Blocked-IPs",
        "Type": "static"
    }
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Address group:', prettify_address_group(result),
                                         ['Name', 'Type', 'Addresses', 'Match', 'Description', 'Tags'],
                                         removeNull=True),
        'EntryContext': {
            "Panorama.AddressGroups(val.Name == obj.Name)": prettify_address_group(result)
        }
    })


def panorama_create_address_command():
    """
    Create an address object
    """
    address_name = demisto.args()['name']
    description = demisto.args().get('description')
    tags = argToList(demisto.args()['tag']) if 'tag' in demisto.args() else None
    ip_netmask = demisto.args().get('ip_netmask')

    address = None

    address_output = {'Name': address_name}
    if DEVICE_GROUP:
        address_output['DeviceGroup'] = DEVICE_GROUP
    if ip_netmask:
        address_output['IP_Netmask'] = ip_netmask
    if description:
        address_output['Description'] = description
    if tags:
        address_output['Tags'] = tags

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': address,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Address was created successfully.',
        'EntryContext': {
            "Panorama.Addresses(val.Name == obj.Name)": address_output
        }
    })


def panorama_edit_address_group_command():
    address_group_name = demisto.args()['name']
    type_ = demisto.args()['type']

    addresses = argToList(demisto.args().get('element_to_add', []))
    addresses.append("Block-Default-Entry")

    address_group_output = {'Name': address_group_name}
    address_group_output['Addresses'] = addresses

    result = {
        "response": {
            "@code": "20",
            "@status": "success",
            "msg": "command succeeded"
        }
    }

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Address Group was edited successfully.',
        'EntryContext': {
            "Panorama.AddressGroups(val.Name == obj.Name)": address_group_output
        }
    })


def panorama_commit_command():
    import random
    job_id = random.randint(1, 10000)

    result = {
        "response": {
            "@code": "19",
            "@status": "success",
            "result": {
                "job": str(job_id),
                "msg": {
                    "line": "Commit job enqueued with jobid 7365"
                }
            }
        }
    }

    commit_output = {
        'JobID': result['response']['result']['job'],
        'Status': 'Pending'
    }

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Commit:', commit_output, ['JobID', 'Status'], removeNull=True),
        'EntryContext': {
            "Panorama.Commit(val.JobID == obj.JobID)": commit_output
        }
    })


def panorama_commit_status_command():
    job_id = int(demisto.args()['job_id'])

    result = {
        "response": {
            "@status": "success",
            "result": {
                "job": {
                    "description": None,
                    "details": {
                        "line": "Configuration committed successfully"
                    },
                    "id": str(job_id),
                    "positionInQ": "0",
                    "progress": "100",
                    "queued": "NO",
                    "result": "OK",
                    "status": "FIN",
                    "stoppable": "no",
                    "tdeq": "10:54:12",
                    "tenq": "2020/02/23 10:54:12",
                    "tfin": "10:54:50",
                    "type": "Commit",
                    "user": "demisto-int",
                    "warnings": None
                }
            }
        }
    }

    commit_status_output = {
        'JobID': result['response']['result']['job']['id'],
        'Status': 'Completed',
        'Details': result['response']['result']['job']['details']['line']
    }

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Commit status:', commit_status_output, ['JobID', 'Status', 'Details'],
                                         removeNull=True),
        'EntryContext': {"Panorama.Commit(val.JobID == obj.JobID)": commit_status_output}
    })


def xdr_update_incident_command():
    incident_id = demisto.args().get('incident_id')
    res = f'Incident {incident_id} has been updated', None, None
    return_outputs(*res)


if demisto.command() == 'test-module':
    # This is the call made when pressing the integration test button.
    demisto.results('ok')
    sys.exit(0)


if demisto.command() == 'ad-enable-account':
    ad_enable_account_command()
    sys.exit(0)


if demisto.command() == 'ad-disable-account':
    ad_disable_account_command()
    sys.exit(0)


if demisto.command() == 'panorama-get-address-group':
    panorama_get_address_group_command()
    sys.exit(0)


if demisto.command() == 'panorama-create-address':
    panorama_create_address_command()
    sys.exit(0)


if demisto.command() == 'panorama-edit-address-group':
    panorama_edit_address_group_command()
    sys.exit(0)


if demisto.command() == 'panorama-commit':
    panorama_commit_command()
    sys.exit(0)

if demisto.command() == 'panorama-commit-status':
    panorama_commit_status_command()
    sys.exit(0)

if demisto.command() == 'xdr-update-incident':
    xdr_update_incident_command()
    sys.exit(0)


if demisto.command() == 'long-running-execution':
  # Should have here an endless loop
    pass
