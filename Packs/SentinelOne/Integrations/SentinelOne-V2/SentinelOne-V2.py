import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import json
import requests
from distutils.util import strtobool
from dateutil.parser import parse

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS '''

TOKEN: str
SERVER: str
FETCH_TIME: str
BASE_URL: str
FETCH_THREAT_RANK: int
FETCH_LIMIT: int
USE_SSL: bool
HEADERS: dict

''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, params={}, data=None):
    LOG(f'Attempting {method} request to {BASE_URL + url_suffix}\nWith params:{params}\nWith body:\n{data}')
    res = requests.request(
        method,
        BASE_URL + url_suffix,
        verify=USE_SSL,
        params=params,
        data=data,
        headers=HEADERS
    )
    if res.status_code not in {200}:
        try:
            errors = ''
            for error in res.json().get('errors'):
                errors += f"\n{error.get('detail', '')}"
            raise Exception(
                f'Error in API call to Sentinel One [{res.status_code}] - [{res.reason}] \n'
                f'Error details: [{errors}]'
            )
        except Exception as error:
            raise error
    try:
        return res.json()
    except Exception:
        return None


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Performs basic get request to get activities types.
    """
    http_request('GET', 'activities/types')
    return True


def get_activities_request(created_after=None, user_emails=None, group_ids=None, created_until=None,
                           activities_ids=None, include_hidden=None, created_before=None, threats_ids=None,
                           activity_types=None, user_ids=None, created_from=None, created_between=None, agent_ids=None,
                           limit=None):
    endpoint_url = 'activities'

    params = {
        'created_at__gt': created_after,
        'userEmails': user_emails,
        'groupIds': group_ids,
        'created_at__lte': created_until,
        'ids': activities_ids,
        'includeHidden': include_hidden,
        'created_at__lt': created_before,
        'threatIds': threats_ids,
        'activityTypes': activity_types,
        'userIds': user_ids,
        'created_at__gte': created_from,
        'createdAt_between': created_between,
        'agentIds': agent_ids,
        'limit': limit
    }

    response = http_request('GET', endpoint_url, params)
    if response.get('errors'):
        return_error(response.get('errors'))
    if 'data' in response:
        return response.get('data')
    return {}


def get_activities_command():
    """
    Get a list of activities.
    """
    context = {}
    context_entries = []
    contents = []
    headers = ['ID', 'Primary description', 'Data', 'User ID', 'Created at', 'Updated at', 'Threat ID']

    created_after = demisto.args().get('created_after')
    user_emails = demisto.args().get('user_emails')
    group_ids = argToList(demisto.args().get('group_ids', []))
    created_until = demisto.args().get('created_until')
    activities_ids = argToList(demisto.args().get('activities_ids', []))
    include_hidden = demisto.args().get('include_hidden')
    created_before = demisto.args().get('created_before')
    threats_ids = argToList(demisto.args().get('threats_ids', []))
    activity_types = argToList(demisto.args().get('activity_types', []))
    user_ids = argToList(demisto.args().get('user_ids', []))
    created_from = demisto.args().get('created_from')
    created_between = demisto.args().get('created_between')
    agent_ids = argToList(demisto.args().get('agent_ids', []))
    limit = int(demisto.args().get('limit', 50))

    activities = get_activities_request(created_after, user_emails, group_ids, created_until, activities_ids,
                                        include_hidden, created_before, threats_ids,
                                        activity_types, user_ids, created_from, created_between, agent_ids, limit)
    if activities:
        for activity in activities:
            contents.append({
                'ID': activity.get('id'),
                'Created at': activity.get('createdAt'),
                'Primary description': activity.get('primaryDescription'),
                'User ID': activity.get('userId'),
                'Data': activity.get('data'),
                'Threat ID': activity.get('threatId'),
                'Updated at': activity.get('updatedAt')
            })

            context_entries.append({
                'Hash': activity.get('hash'),
                'ActivityType': activity.get('activityType'),
                'OsFamily': activity.get('osFamily'),
                'PrimaryDescription': activity.get('primaryDescription'),
                'Comments': activity.get('comments'),
                'AgentUpdatedVersion': activity.get('agentUpdatedVersion'),
                'UserID': activity.get('userId'),
                'ID': activity.get('id'),
                'Data': activity.get('data'),
                'CreatedAt': activity.get('createdAt'),
                'SecondaryDescription': activity.get('secondaryDescription'),
                'ThreatID': activity.get('threatId'),
                'GroupID': activity.get('groupId'),
                'UpdatedAt': activity.get('updatedAt'),
                'Description': activity.get('description'),
                'AgentID': activity.get('agentId'),
                'SiteID': activity.get('siteId')
            })

        context['SentinelOne.Activity(val.ID && val.ID === obj.ID)'] = context_entries

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Sentinel One Activities', contents, headers, removeNull=True),
        'EntryContext': context
    })


def get_groups_request(group_type=None, group_ids=None, group_id=None, is_default=None, name=None, query=None,
                       rank=None, limit=None):
    endpoint_url = 'groups'

    params = {
        'type': group_type,
        'groupIds': group_ids,
        'id': group_id,
        'isDefault': is_default,
        'name': name,
        'query': query,
        'rank': rank,
        'limit': limit
    }

    response = http_request('GET', endpoint_url, params)
    if response.get('errors'):
        return_error(response.get('errors'))
    if 'data' in response:
        return response.get('data')
    return {}


def get_groups_command():
    """
    Gets the group data.
    """

    context = {}
    contents = []
    headers = ['ID', 'Name', 'Type', 'Creator', 'Creator ID', 'Created at', 'Rank']

    group_type = demisto.args().get('type')
    group_id = demisto.args().get('id')
    group_ids = argToList(demisto.args().get('group_ids', []))
    is_default = demisto.args().get('is_default')
    name = demisto.args().get('name')
    query = demisto.args().get('query')
    rank = demisto.args().get('rank')
    limit = int(demisto.args().get('limit', 50))

    groups = get_groups_request(group_type, group_id, group_ids, is_default, name, query, rank, limit)
    if groups:
        for group in groups:
            contents.append({
                'ID': group.get('id'),
                'Type': group.get('type'),
                'Name': group.get('name'),
                'Creator ID': group.get('creatorId'),
                'Creator': group.get('creator'),
                'Created at': group.get('createdAt'),
                'Rank': group.get('rank')
            })

        context['SentinelOne.Group(val.ID && val.ID === obj.ID)'] = groups

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Sentinel One Groups', contents, headers, removeNull=True),
        'EntryContext': context
    })


def delete_group_request(group_id=None):
    endpoint_url = f'groups/{group_id}'

    response = http_request('DELETE', endpoint_url)
    if response.get('errors'):
        return_error(response.get('errors'))
    if 'data' in response:
        return response.get('data')
    return {}


def delete_group():
    """
    Deletes a group by ID.
    """
    group_id = demisto.args().get('group_id')

    delete_group_request(group_id)
    demisto.results('The group was deleted successfully')


def move_agent_request(group_id, agents_id):
    endpoint_url = f'groups/{group_id}/move-agents'

    payload = {
        "filter": {
            "agentIds": agents_id
        }
    }

    response = http_request('PUT', endpoint_url, data=json.dumps(payload))
    if response.get('errors'):
        return_error(response.get('errors'))
    if 'data' in response:
        return response.get('data')
    return {}


def move_agent_to_group_command():
    """
    Move agents to a new group.
    """
    group_id = demisto.args().get('group_id')
    agents_id = argToList(demisto.args().get('agents_ids', []))
    context = {}

    agents_groups = move_agent_request(group_id, agents_id)

    # Parse response into context & content entries
    if agents_groups.get('agentsMoved') and int(agents_groups.get('agentsMoved')) > 0:
        agents_moved = True
    else:
        agents_moved = False
    date_time_utc = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    context_entries = contents = {
        'Date': date_time_utc,
        'AgentsMoved': agents_groups.get('agentsMoved'),
        'AffectedAgents': agents_moved
    }

    context['SentinelOne.Agent(val.Date && val.Date === obj.Date)'] = context_entries

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Sentinel One - Moved Agents \n' + 'Total of: ' + str(
            agents_groups.get('AgentsMoved')) + ' agents were Moved successfully', contents, removeNull=True),
        'EntryContext': context
    })


def get_agent_processes_request(agents_ids=None):
    endpoint_url = 'agents/processes'

    params = {
        'ids': agents_ids
    }

    response = http_request('GET', endpoint_url, params)
    if response.get('errors'):
        return_error(response.get('errors'))
    if 'data' in response:
        return response.get('data')
    return {}


def get_agent_processes():
    """
    Retrieve running processes for a specific agent.
    Note: This feature is obsolete and an empty array will always be returned
    """
    headers = ['ProcessName', 'StartTime', 'Pid', 'MemoryUsage', 'CpuUsage', 'ExecutablePath']
    contents = []
    context = {}
    agents_ids = demisto.args().get('agents_ids')

    processes = get_agent_processes_request(agents_ids)

    if processes:
        for process in processes:
            contents.append({
                'ProcessName': process.get('processName'),
                'CpuUsage': process.get('cpuUsage'),
                'MemoryUsage': process.get('memoryUsage'),
                'StartTime': process.get('startTime'),
                'ExecutablePath': process.get('executablePath'),
                'Pid': process.get('pid')
            })
        context['SentinelOne.Agent(val.Pid && val.Pid === obj.Pid)'] = processes

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Sentinel One Agent Processes', contents, headers, removeNull=True),
        'EntryContext': context
    })


def get_threats_command():
    """
    Gets a list of threats.
    """
    # Init main vars
    contents = []
    context = {}
    context_entries = []

    # Get arguments
    content_hash = demisto.args().get('content_hash')
    mitigation_status = argToList(demisto.args().get('mitigation_status'))
    created_before = demisto.args().get('created_before')
    created_after = demisto.args().get('created_after')
    created_until = demisto.args().get('created_until')
    created_from = demisto.args().get('created_from')
    resolved = bool(strtobool(demisto.args().get('resolved', 'false')))
    display_name = demisto.args().get('display_name_like')
    query = demisto.args().get('query', '')
    threat_ids = argToList(demisto.args().get('threat_ids', []))
    limit = int(demisto.args().get('limit', 20))
    classifications = argToList(demisto.args().get('classifications', []))
    rank = int(demisto.args().get('rank', 0))

    # Make request and get raw response
    threats = get_threats_request(content_hash, mitigation_status, created_before, created_after, created_until,
                                  created_from, resolved, display_name, query, threat_ids, limit, classifications)

    # Parse response into context & content entries
    if threats:
        for threat in threats:
            threat_rank = threat.get('rank')
            try:
                threat_rank = int(threat_rank)
            except TypeError:
                threat_rank = 0
            if not rank or (rank and threat_rank >= rank):
                contents.append({
                    'ID': threat.get('id'),
                    'Agent Computer Name': threat.get('agentComputerName'),
                    'Created Date': threat.get('createdDate'),
                    'Site ID': threat.get('siteId'),
                    'Classification': threat.get('classification'),
                    'Mitigation Status': threat.get('mitigationStatus'),
                    'Agent ID': threat.get('agentId'),
                    'Site Name': threat.get('siteName'),
                    'Rank': threat.get('rank'),
                    'Marked As Benign': threat.get('markedAsBenign'),
                    'File Content Hash': threat.get('fileContentHash')
                })
                context_entries.append({
                    'ID': threat.get('id'),
                    'AgentComputerName': threat.get('agentComputerName'),
                    'CreatedDate': threat.get('createdDate'),
                    'SiteID': threat.get('siteId'),
                    'Classification': threat.get('classification'),
                    'MitigationStatus': threat.get('mitigationStatus'),
                    'AgentID': threat.get('agentId'),
                    'Rank': threat.get('rank'),
                    'MarkedAsBenign': threat.get('markedAsBenign'),
                    'FileContentHash': threat.get('fileContentHash'),
                    'InQuarantine': threat.get('inQuarantine'),
                    'FileMaliciousContent': threat.get('fileMaliciousContent'),
                    'ThreatName': threat.get('threatName'),
                    'FileSha256': threat.get('fileSha256'),
                    'AgentOsType': threat.get('agentOsType'),
                    'Description': threat.get('description'),
                    'FileDisplayName': threat.get('fileDisplayName'),
                    'FilePath': threat.get('filePath'),
                    'Username': threat.get('username')

                })

        context['SentinelOne.Threat(val.ID && val.ID === obj.ID)'] = context_entries

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': threats,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Sentinel One - Getting Threat List \n' + 'Provides summary information and '
                                                                                   'details for all the threats that '
                                                                                   'matched your search criteria.',
                                         contents, removeNull=True),
        'EntryContext': context
    })


def get_threats_request(content_hash=None, mitigation_status=None, created_before=None, created_after=None,
                        created_until=None, created_from=None, resolved=None, display_name=None, query=None,
                        threat_ids=None, limit=None, classifications=None):
    endpoint_url = 'threats'

    params = {
        'contentHash': content_hash,
        'mitigationStatuses': mitigation_status,
        'createdAt__lt': created_before,
        'createdAt__gt': created_after,
        'createdAt__lte': created_until,
        'createdAt__gte': created_from,
        'resolved': resolved,
        'displayName__like': display_name,
        'query': query,
        'ids': threat_ids,
        'limit': limit,
        'classifications': classifications,
    }

    response = http_request('GET', endpoint_url, params)
    if response.get('errors'):
        return_error(response.get('errors'))
    if 'data' in response:
        return response.get('data')
    return {}


def get_hash_command():
    """
    Get hash reputation and classification.
    """
    # Init main vars
    headers = ['Hash', 'Rank', 'ClassificationSource', 'Classification']
    # Get arguments
    hash_ = demisto.args().get('hash')
    type_ = get_hash_type(hash_)
    if type_ == 'Unknown':
        return_error('Enter a valid hash format.')
    # Make request and get raw response
    hash_reputation = get_hash_reputation_request(hash_)
    reputation = hash_reputation.get('data', {})
    contents = {
        'Rank': reputation.get('rank'),
        'Hash': hash_
    }
    # try get classification - might return 404 (classification is not mandatory)
    try:
        hash_classification = get_hash_classification_request(hash_)
        classification = hash_classification.get('data', {})
        contents['ClassificationSource'] = classification.get('classificationSource')
        contents['Classification'] = classification.get('classification')
    except ValueError as e:
        if '404' in str(e):  # handling case classification not found for the specific hash
            contents['Classification'] = 'No classification was found.'
        else:
            raise e

    # Parse response into context & content entries
    title = 'Sentinel One - Hash Reputation and Classification \n' + \
            'Provides hash reputation (rank from 0 to 10):'

    context = {
        'SentinelOne.Hash(val.Hash && val.Hash === obj.Hash)': contents
    }

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, contents, headers, removeNull=True),
        'EntryContext': context
    })


def get_hash_reputation_request(hash_):
    endpoint_url = f'hashes/{hash_}/reputation'

    response = http_request('GET', endpoint_url)
    return response


def get_hash_classification_request(hash_):
    endpoint_url = f'hashes/{hash_}/classification'

    response = http_request('GET', endpoint_url)
    return response


def mark_as_threat_command():
    """
    Mark suspicious threats as threats
    """
    # Init main vars
    headers = ['ID', 'Marked As Threat']
    contents = []
    context = {}
    context_entries = []

    # Get arguments
    threat_ids = argToList(demisto.args().get('threat_ids'))
    target_scope = demisto.args().get('target_scope')

    # Make request and get raw response
    affected_threats = mark_as_threat_request(threat_ids, target_scope)

    # Parse response into context & content entries
    if affected_threats.get('affected') and int(affected_threats.get('affected')) > 0:
        title = 'Total of ' + str(affected_threats.get('affected')) + ' provided threats were marked successfully'
        affected = True
    else:
        affected = False
        title = 'No threats were marked'
    for threat_id in threat_ids:
        contents.append({
            'Marked As Threat': affected,
            'ID': threat_id,
        })
        context_entries.append({
            'MarkedAsThreat': affected,
            'ID': threat_id,
        })

    context['SentinelOne.Threat(val.ID && val.ID === obj.ID)'] = context_entries

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Sentinel One - Marking suspicious threats as threats \n' + title, contents,
                                         headers, removeNull=True),
        'EntryContext': context
    })


def mark_as_threat_request(threat_ids, target_scope):
    endpoint_url = 'threats/mark-as-threat'

    payload = {
        "filter": {
            "ids": threat_ids
        },
        "data": {
            "targetScope": target_scope
        }
    }

    response = http_request('POST', endpoint_url, data=json.dumps(payload))
    if response.get('errors'):
        return_error(response.get('errors'))
    if 'data' in response:
        return response.get('data')
    return {}


def mitigate_threat_command():
    """
    Apply a mitigation action to a group of threats
    """
    # Init main vars
    headers = ['ID', 'Mitigation Action', 'Mitigated']
    contents = []
    context = {}
    context_entries = []

    # Get arguments
    threat_ids = argToList(demisto.args().get('threat_ids'))
    action = demisto.args().get('action')

    # Make request and get raw response
    mitigated_threats = mitigate_threat_request(threat_ids, action)

    # Parse response into context & content entries
    if mitigated_threats.get('affected') and int(mitigated_threats.get('affected')) > 0:
        mitigated = True
        title = 'Total of ' + str(mitigated_threats.get('affected')) + ' provided threats were mitigated successfully'
    else:
        mitigated = False
        title = 'No threats were mitigated'
    for threat_id in threat_ids:
        contents.append({
            'Mitigated': mitigated,
            'ID': threat_id,
            'Mitigation Action': action
        })
        context_entries.append({
            'Mitigated': mitigated,
            'ID': threat_id,
            'Mitigation': {
                'Action': action
            }
        })

    context['SentinelOne.Threat(val.ID && val.ID === obj.ID)'] = context_entries

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Sentinel One - Mitigating threats \n' + title, contents, headers,
                                         removeNull=True),
        'EntryContext': context
    })


def mitigate_threat_request(threat_ids, action):
    endpoint_url = f'threats/mitigate/{action}'

    payload = {
        "filter": {
            "ids": threat_ids
        }
    }

    response = http_request('POST', endpoint_url, data=json.dumps(payload))
    if response.get('errors'):
        return_error(response.get('errors'))
    if 'data' in response:
        return response.get('data')
    return {}


def resolve_threat_command():
    """
    Mark threats as resolved
    """
    # Init main vars
    contents = []
    context = {}
    context_entries = []

    # Get arguments
    threat_ids = argToList(demisto.args().get('threat_ids'))

    # Make request and get raw response
    resolved_threats = resolve_threat_request(threat_ids)

    # Parse response into context & content entries
    if resolved_threats.get('affected') and int(resolved_threats.get('affected')) > 0:
        resolved = True
        title = 'Total of ' + str(resolved_threats.get('affected')) + ' provided threats were resolved successfully'
    else:
        resolved = False
        title = 'No threats were resolved'

    for threat_id in threat_ids:
        contents.append({
            'Resolved': resolved,
            'ID': threat_id
        })
        context_entries.append({
            'Resolved': resolved,
            'ID': threat_id
        })

    context['SentinelOne.Threat(val.ID && val.ID === obj.ID)'] = context_entries

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Sentinel One - Resolving threats \n' + title, contents, removeNull=True),
        'EntryContext': context
    })


def resolve_threat_request(threat_ids):
    endpoint_url = 'threats/mark-as-resolved'

    payload = {
        "filter": {
            "ids": threat_ids
        }
    }

    response = http_request('POST', endpoint_url, data=json.dumps(payload))
    if response.get('errors'):
        return_error(response.get('errors'))
    if 'data' in response:
        return response.get('data')
    return {}


def get_white_list_command():
    """
    List all white items matching the input filter
    """
    # Init main vars
    contents = []
    context = {}
    context_entries = []

    # Get arguments
    item_ids = argToList(demisto.args().get('item_ids', []))
    os_types = argToList(demisto.args().get('os_types', []))
    exclusion_type = demisto.args().get('exclusion_type')
    limit = int(demisto.args().get('limit', 10))

    # Make request and get raw response
    exclusion_items = get_white_list_request(item_ids, os_types, exclusion_type, limit)

    # Parse response into context & content entries
    if exclusion_items:
        for exclusion_item in exclusion_items:
            contents.append({
                'ID': exclusion_item.get('id'),
                'Type': exclusion_item.get('type'),
                'CreatedAt': exclusion_item.get('createdAt'),
                'Value': exclusion_item.get('value'),
                'Source': exclusion_item.get('source'),
                'UserID': exclusion_item.get('userId'),
                'UpdatedAt': exclusion_item.get('updatedAt'),
                'OsType': exclusion_item.get('osType'),
                'UserName': exclusion_item.get('userName'),
                'Mode': exclusion_item.get('mode')
            })
            context_entries.append({
                'ID': exclusion_item.get('id'),
                'Type': exclusion_item.get('type'),
                'CreatedAt': exclusion_item.get('createdAt'),
                'Value': exclusion_item.get('value'),
                'Source': exclusion_item.get('source'),
                'UserID': exclusion_item.get('userId'),
                'UpdatedAt': exclusion_item.get('updatedAt'),
                'OsType': exclusion_item.get('osType'),
                'UserName': exclusion_item.get('userName'),
                'Mode': exclusion_item.get('mode')
            })

        context['SentinelOne.Exclusions(val.ID && val.ID === obj.ID)'] = context_entries

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Sentinel One - Listing exclusion items \n'
                                         + 'provides summary information and details for all the exclusion items that '
                                           'matched your search criteria.', contents, removeNull=True),
        'EntryContext': context
    })


def get_white_list_request(item_ids, os_types, exclusion_type, limit):
    endpoint_url = 'exclusions'

    params = {
        "ids": item_ids,
        "osTypes": os_types,
        "type": exclusion_type,
        "limit": limit
    }

    response = http_request('GET', endpoint_url, params)
    if response.get('errors'):
        return_error(response.get('errors'))
    if 'data' in response:
        return response.get('data')
    return {}


def create_white_item_command():
    """
    Create white item.
    """
    # Init main vars
    contents = []
    context = {}
    context_entries = []
    title = ''

    # Get arguments
    group_ids = argToList(demisto.args().get('group_ids', []))
    site_ids = argToList(demisto.args().get('site_ids', []))
    exclusion_type = demisto.args().get('exclusion_type')
    exclusion_value = demisto.args().get('exclusion_value')
    os_type = demisto.args().get('os_type')
    description = demisto.args().get('description')
    exclusion_mode = demisto.args().get('exclusion_mode')
    path_exclusion_type = demisto.args().get('path_exclusion_type')

    # Make request and get raw response
    new_item = create_exclusion_item_request(exclusion_type, exclusion_value, os_type, description, exclusion_mode,
                                             path_exclusion_type, group_ids, site_ids)

    # Parse response into context & content entries
    if new_item:
        title = 'Sentinel One - Adding an exclusion item \n' + \
                'The provided item was successfully added to the exclusion list'
        contents.append({
            'ID': new_item.get('id'),
            'Type': new_item.get('type'),
            'Created At': new_item.get('createdAt')
        })
        context_entries.append({
            'ID': new_item.get('id'),
            'Type': new_item.get('type'),
            'CreatedAt': new_item.get('createdAt')
        })

        context['SentinelOne.Exclusion(val.ID && val.ID === obj.ID)'] = context_entries

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, contents, removeNull=True),
        'EntryContext': context
    })


def create_exclusion_item_request(exclusion_type, exclusion_value, os_type, description, exclusion_mode,
                                  path_exclusion_type, group_ids, site_ids):
    endpoint_url = 'exclusions'

    payload = {
        "filter": {
            "groupIds": group_ids,
            "siteIds": site_ids
        },
        "data": {
            "type": exclusion_type,
            "value": exclusion_value,
            "osType": os_type,
            "description": description,
            "mode": exclusion_mode
        }
    }

    if path_exclusion_type:
        payload['data']['pathExclusionType'] = path_exclusion_type

    response = http_request('POST', endpoint_url, data=json.dumps(payload))
    if response.get('errors'):
        return_error(response.get('errors'))
    if 'data' in response:
        return response.get('data')[0]
    return {}


def get_sites_command():
    """
    List all sites with filtering options
    """
    # Init main vars
    contents = []
    context = {}
    context_entries = []

    # Get arguments
    updated_at = demisto.args().get('updated_at')
    query = demisto.args().get('query')
    site_type = demisto.args().get('site_type')
    features = demisto.args().get('features')
    state = demisto.args().get('state')
    suite = demisto.args().get('suite')
    admin_only = bool(strtobool(demisto.args().get('admin_only', 'false')))
    account_id = demisto.args().get('account_id')
    site_name = demisto.args().get('site_name')
    created_at = demisto.args().get('created_at')
    limit = int(demisto.args().get('limit', 50))
    site_ids = argToList(demisto.args().get('site_ids', []))

    # Make request and get raw response
    sites, all_sites = get_sites_request(updated_at, query, site_type, features, state, suite, admin_only, account_id,
                                         site_name, created_at, limit, site_ids)

    # Parse response into context & content entries
    if sites:
        for site in sites:
            contents.append({
                'ID': site.get('id'),
                'Creator': site.get('creator'),
                'Name': site.get('name'),
                'Type': site.get('siteType'),
                'Account Name': site.get('accountName'),
                'State': site.get('state'),
                'Health Status': site.get('healthStatus'),
                'Suite': site.get('suite'),
                'Created At': site.get('createdAt'),
                'Expiration': site.get('expiration'),
                'Unlimited Licenses': site.get('unlimitedLicenses'),
                'Total Licenses': all_sites.get('totalLicenses'),
                'Active Licenses': all_sites.get('activeLicenses')
            })
            context_entries.append({
                'ID': site.get('id'),
                'Creator': site.get('creator'),
                'Name': site.get('name'),
                'Type': site.get('siteType'),
                'AccountName': site.get('accountName'),
                'State': site.get('state'),
                'HealthStatus': site.get('healthStatus'),
                'Suite': site.get('suite'),
                'CreatedAt': site.get('createdAt'),
                'Expiration': site.get('expiration'),
                'UnlimitedLicenses': site.get('unlimitedLicenses'),
                'TotalLicenses': all_sites.get('totalLicenses'),
                'ActiveLicenses': all_sites.get('activeLicenses')
            })

        context['SentinelOne.Site(val.ID && val.ID === obj.ID)'] = context_entries

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Sentinel One - Gettin List of Sites \n' + 'Provides summary information and '
                                                                                    'details for all sites that matched'
                                                                                    ' your search criteria.', contents,
                                         removeNull=True),
        'EntryContext': context
    })


def get_sites_request(updated_at, query, site_type, features, state, suite, admin_only, account_id, site_name,
                      created_at, limit, site_ids):
    endpoint_url = 'sites'

    params = {
        "updatedAt": updated_at,
        "query": query,
        "siteType": site_type,
        "features": features,
        "state": state,
        "suite": suite,
        "adminOnly": admin_only,
        "accountId": account_id,
        "name": site_name,
        "createdAt": created_at,
        "limit": limit,
        "siteIds": site_ids
    }

    response = http_request('GET', endpoint_url, params)
    if response.get('errors'):
        return_error(response.get('errors'))
    if 'data' in response:
        return response.get('data').get('sites'), response.get('data').get('allSites')
    return {}


def get_site_command():
    """
    Get a specific site by ID
    """
    # Init main vars
    contents = []
    context = {}
    context_entries = []
    title = ''

    # Get arguments
    site_id = demisto.args().get('site_id')

    # Make request and get raw response
    site = get_site_request(site_id)

    # Parse response into context & content entries
    if site:
        title = 'Sentinel One - Summary About Site: ' + site_id + '\n' + \
                'Provides summary information and details for specific site ID'
        contents.append({
            'ID': site.get('id'),
            'Creator': site.get('creator'),
            'Name': site.get('name'),
            'Type': site.get('siteType'),
            'Account Name': site.get('accountName'),
            'State': site.get('state'),
            'Health Status': site.get('healthStatus'),
            'Suite': site.get('suite'),
            'Created At': site.get('createdAt'),
            'Expiration': site.get('expiration'),
            'Unlimited Licenses': site.get('unlimitedLicenses'),
            'Total Licenses': site.get('totalLicenses'),
            'Active Licenses': site.get('activeLicenses'),
            'AccountID': site.get('accountId'),
            'IsDefault': site.get('isDefault')
        })
        context_entries.append({
            'ID': site.get('id'),
            'Creator': site.get('creator'),
            'Name': site.get('name'),
            'Type': site.get('siteType'),
            'AccountName': site.get('accountName'),
            'State': site.get('state'),
            'HealthStatus': site.get('healthStatus'),
            'Suite': site.get('suite'),
            'CreatedAt': site.get('createdAt'),
            'Expiration': site.get('expiration'),
            'UnlimitedLicenses': site.get('unlimitedLicenses'),
            'TotalLicenses': site.get('totalLicenses'),
            'ActiveLicenses': site.get('activeLicenses'),
            'AccountID': site.get('accountId'),
            'IsDefault': site.get('isDefault')
        })

        context['SentinelOne.Site(val.ID && val.ID === obj.ID)'] = context_entries

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, contents, removeNull=True),
        'EntryContext': context
    })


def get_site_request(site_id):
    endpoint_url = f'sites/{site_id}'

    response = http_request('GET', endpoint_url)
    if response.get('errors'):
        return_error(response.get('errors'))
    if 'data' in response:
        return response.get('data')
    return {}


def reactivate_site_command():
    """
    Reactivate specific site by ID
    """
    # Init main vars
    context = {}
    title = ''

    # Get arguments
    site_id = demisto.args().get('site_id')

    # Make request and get raw response
    site = reactivate_site_request(site_id)

    # Parse response into context & content entries
    if site:
        title = 'Sentinel One - Reactivated Site: ' + site_id + '\n' + 'Site has been reactivated successfully'
        contents = {
            'ID': site.get('id'),
            'Reactivated': site.get('success')
        }
        context_entries = {
            'ID': site.get('id'),
            'Reactivated': site.get('success')
        }

        context['SentinelOne.Site(val.ID && val.ID === obj.ID)'] = context_entries

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, contents, removeNull=True),
        'EntryContext': context
    })


def reactivate_site_request(site_id):
    endpoint_url = f'sites/{site_id}/reactivate'

    response = http_request('PUT', endpoint_url)
    if response.get('errors'):
        return_error(response.get('errors'))
    if response.get('data'):
        return response.get('data')
    return {}


def get_threat_summary_command():
    """
    Get dashboard threat summary
    """
    # Init main vars
    context = {}
    title = ''

    # Get arguments
    site_ids = argToList(demisto.args().get('site_ids', []))
    group_ids = argToList(demisto.args().get('group_ids', []))

    # Make request and get raw response
    threat_summary = get_threat_summary_request(site_ids, group_ids)

    # Parse response into context & content entries
    if threat_summary:
        title = 'Sentinel One - Dashboard Threat Summary'
        contents = {
            'Active': threat_summary.get('active'),
            'Total': threat_summary.get('total'),
            'Mitigated': threat_summary.get('mitigated'),
            'Suspicious': threat_summary.get('suspicious'),
            'Blocked': threat_summary.get('blocked')
        }

        context_entries = {
            'Active': threat_summary.get('active'),
            'Total': threat_summary.get('total'),
            'Mitigated': threat_summary.get('mitigated'),
            'Suspicious': threat_summary.get('suspicious'),
            'Blocked': threat_summary.get('blocked')
        }

        context['SentinelOne.Threat(val && val === obj)'] = context_entries

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, contents, removeNull=True),
        'EntryContext': context
    })


def get_threat_summary_request(site_ids, group_ids):
    endpoint_url = 'private/threats/summary'

    params = {
        "siteIds": site_ids,
        "groupIds": group_ids
    }

    response = http_request('GET', endpoint_url, params)
    if response.get('errors'):
        return_error(response.get('errors'))
    if 'data' in response:
        return response.get('data')
    return {}


# Agents Commands


def list_agents_command():
    """
    List all agents matching the input filter
    """
    # Init main vars
    contents = []
    context = {}
    context_entries = []

    # Get arguments
    active_threats = demisto.args().get('min_active_threats')
    computer_name = demisto.args().get('computer_name')
    scan_status = demisto.args().get('scan_status')
    os_type = demisto.args().get('os_type')
    created_at = demisto.args().get('created_at')

    # Make request and get raw response
    agents = list_agents_request(active_threats, computer_name, scan_status, os_type, created_at)

    # Parse response into context & content entries
    if agents:
        for agent in agents:
            contents.append({
                'ID': agent.get('id'),
                'Network Status': agent.get('networkStatus'),
                'Agent Version': agent.get('agentVersion'),
                'Is Decomissioned': agent.get('isDecommissioned'),
                'Is Active': agent.get('isActive'),
                'Last ActiveDate': agent.get('lastActiveDate'),
                'Registered At': agent.get('registeredAt'),
                'External IP': agent.get('externalIp'),
                'Threat Count': agent.get('activeThreats'),
                'Encrypted Applications': agent.get('encryptedApplications'),
                'OS Name': agent.get('osName'),
                'Computer Name': agent.get('computerName'),
                'Domain': agent.get('domain'),
                'Created At': agent.get('createdAt'),
                'Site Name': agent.get('siteName')
            })
            context_entries.append({
                'ID': agent.get('id'),
                'NetworkStatus': agent.get('networkStatus'),
                'AgentVersion': agent.get('agentVersion'),
                'IsDecomissioned': agent.get('isDecommissioned'),
                'IsActive': agent.get('isActive'),
                'LastActiveDate': agent.get('lastActiveDate'),
                'RegisteredAt': agent.get('registeredAt'),
                'ExternalIP': agent.get('externalIp'),
                'ThreatCount': agent.get('activeThreats'),
                'EncryptedApplications': agent.get('encryptedApplications'),
                'OSName': agent.get('osName'),
                'ComputerName': agent.get('computerName'),
                'Domain': agent.get('domain'),
                'CreatedAt': agent.get('createdAt'),
                'SiteName': agent.get('siteName')
            })

        context['SentinelOne.Agents(val.ID && val.ID === obj.ID)'] = context_entries

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Sentinel One - List of Agents \n Provides summary information and details for'
                                         ' all the agents that matched your search criteria',
                                         contents, removeNull=True),
        'EntryContext': context
    })


def list_agents_request(active_threats, computer_name, scan_status, os_type, created_at):
    endpoint_url = 'agents'

    params = {
        "activeThreats__gt": active_threats,
        "computerName": computer_name,
        "scanStatus": scan_status,
        "osType": os_type,
        "createdAt__gte": created_at
    }

    response = http_request('GET', endpoint_url, params)
    if response.get('errors'):
        return_error(response.get('errors'))
    if 'data' in response:
        return response.get('data')
    return {}


def get_agent_command():
    """
    Get single agent via ID
    """
    # Init main vars
    contents = []
    context = {}
    context_entries = []
    title = ''

    # Get arguments
    agent_id = demisto.args().get('agent_id')

    # Make request and get raw response
    agent = get_agent_request(agent_id)

    # Parse response into context & content entries
    if agent:
        title = 'Sentinel One - Get Agent Details \nProvides details for the following agent ID : ' + agent_id
        contents.append({
            'ID': agent.get('id'),
            'Network Status': agent.get('networkStatus'),
            'Agent Version': agent.get('agentVersion'),
            'Is Decomissioned': agent.get('isDecommissioned'),
            'Is Active': agent.get('isActive'),
            'Last ActiveDate': agent.get('lastActiveDate'),
            'Registered At': agent.get('registeredAt'),
            'External IP': agent.get('externalIp'),
            'Threat Count': agent.get('activeThreats'),
            'Encrypted Applications': agent.get('encryptedApplications'),
            'OS Name': agent.get('osName'),
            'Computer Name': agent.get('computerName'),
            'Domain': agent.get('domain'),
            'Created At': agent.get('createdAt'),
            'Site Name': agent.get('siteName')
        })
        context_entries.append({
            'ID': agent.get('id'),
            'NetworkStatus': agent.get('networkStatus'),
            'AgentVersion': agent.get('agentVersion'),
            'IsDecomissioned': agent.get('isDecommissioned'),
            'IsActive': agent.get('isActive'),
            'LastActiveDate': agent.get('lastActiveDate'),
            'RegisteredAt': agent.get('registeredAt'),
            'ExternalIP': agent.get('externalIp'),
            'ThreatCount': agent.get('activeThreats'),
            'EncryptedApplications': agent.get('encryptedApplications'),
            'OSName': agent.get('osName'),
            'ComputerName': agent.get('computerName'),
            'Domain': agent.get('domain'),
            'CreatedAt': agent.get('createdAt'),
            'SiteName': agent.get('siteName')
        })

        context['SentinelOne.Agent(val.ID && val.ID === obj.ID)'] = context_entries

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, contents, removeNull=True),
        'EntryContext': context
    })


def get_agent_request(agent_id):
    endpoint_url = 'agents'

    params = {
        "ids": [agent_id]
    }

    response = http_request('GET', endpoint_url, params)
    if response.get('errors'):
        return_error(response.get('errors'))
    if 'data' in response:
        return response.get('data')[0]
    return {}


def connect_to_network_request(agents_id):
    endpoint_url = 'agents/actions/connect'

    payload = {
        'filter': {
            'ids': agents_id
        }
    }

    response = http_request('POST', endpoint_url, data=json.dumps(payload))
    if response.get('errors'):
        return_error(response.get('errors'))
    if 'data' in response:
        return response
    return {}


def connect_agent_to_network():
    """
    Sends a "connect to network" command to all agents matching the input filter.
    """
    # Get arguments
    agents_id = demisto.args().get('agent_id')

    # Make request and get raw response
    agents = connect_to_network_request(agents_id)
    agents_affected = agents.get('data', {}).get('affected', 0)

    # Parse response into context & content entries
    if agents_affected > 0:
        network_status = get_agent_request(agents_id)
        contents = {
            'NetworkStatus': network_status.get('networkStatus'),
            'ID': agents_id
        }
    else:
        return_error('No agents were connected to the network.')

    context = {
        'SentinelOne.Agent(val.ID && val.ID === obj.ID)': contents
    }

    return_outputs(
        f'{agents_affected} agent(s) successfully connected to the network.',
        context,
        agents
    )


def disconnect_from_network_request(agents_id):
    endpoint_url = 'agents/actions/disconnect'

    payload = {
        'filter': {
            'ids': agents_id
        }
    }

    response = http_request('POST', endpoint_url, data=json.dumps(payload))
    if response.get('errors'):
        return_error(response.get('errors'))
    else:
        return response


def disconnect_agent_from_network():
    """
    Sends a "disconnect from network" command to all agents matching the input filter.
    """
    # Get arguments
    agents_id = demisto.args().get('agent_id')

    # Make request and get raw response
    agents = disconnect_from_network_request(agents_id)
    agents_affected = agents.get('data', {}).get('affected', 0)

    # Parse response into context & content entries
    if agents_affected > 0:
        network_status = get_agent_request(agents_id)
        contents = {
            'NetworkStatus': network_status.get('networkStatus'),
            'ID': agents_id
        }
    else:
        return_error('No agents were disconnected from the network.')

    context = {
        'SentinelOne.Agent(val.ID && val.ID === obj.ID)': contents
    }

    return_outputs(
        f'{agents_affected} agent(s) successfully disconnected from the network.',
        context,
        agents
    )


def broadcast_message_request(message, is_active=None, group_id=None, agent_id=None, domain=None):
    filters = {}
    endpoint_url = 'agents/actions/broadcast'

    if is_active:
        filters['isActive'] = is_active
    if group_id:
        filters['groupIds'] = group_id
    if agent_id:
        filters['ids'] = agent_id
    if domain:
        filters['domains'] = domain

    payload = {
        'data': {
            'message': message
        },
        'filter': filters
    }
    response = http_request('POST', endpoint_url, data=json.dumps(payload))

    if response.get('errors'):
        return_error(response.get('errors'))
    else:
        return response


def broadcast_message():
    """
    Broadcasts a message to all agents matching the input filter.
    """
    message = demisto.args().get('message')
    is_active = bool(demisto.args().get('active_agent'))
    group_id = demisto.args().get('group_id')
    agent_id = demisto.args().get('agent_id')
    domain = demisto.args().get('domain')

    broadcast_message = broadcast_message_request(message, is_active=is_active, group_id=group_id, agent_id=agent_id,
                                                  domain=domain)

    agents_affected = broadcast_message.get('data', {}).get('affected', 0)
    if agents_affected > 0:
        demisto.results('The message was successfully delivered to the agent(s)')
    else:
        return_error('No messages were sent. Verify that the inputs are correct.')


def shutdown_agents_request(query, agent_id, group_id):
    endpoint_url = 'agents/actions/shutdown'
    filters = {}

    if query:
        filters['query'] = query
    if agent_id:
        filters['ids'] = agent_id
    if group_id:
        filters['groupIds'] = group_id

    payload = {
        'filter': filters
    }

    response = http_request('POST', endpoint_url, data=json.dumps(payload))
    if response.get('errors'):
        return_error(response.get('errors'))
    else:
        return response


def shutdown_agents():
    """
    Sends a shutdown command to all agents matching the input filter
    """
    query = demisto.args().get('query', '')

    agent_id = argToList(demisto.args().get('agent_id'))
    group_id = argToList(demisto.args().get('group_id'))
    if not (agent_id or group_id):
        return_error('Expecting at least one of the following arguments to filter by: agent_id, group_id.')

    affected_agents = shutdown_agents_request(query, agent_id, group_id)
    agents = affected_agents.get('data', {}).get('affected', 0)
    if agents > 0:
        demisto.results(f'Shutting down {agents} agent(s).')
    else:
        return_error('No agents were shutdown.')


def uninstall_agent_request(query=None, agent_id=None, group_id=None):
    endpoint_url = 'agents/actions/uninstall'
    filters = {}

    if query:
        filters['query'] = query
    if agent_id:
        filters['ids'] = agent_id
    if group_id:
        filters['groupIds'] = group_id

    payload = {
        'filter': filters
    }

    response = http_request('POST', endpoint_url, data=json.dumps(payload))
    if response.get('errors'):
        return_error(response.get('errors'))
    else:
        return response


def uninstall_agent():
    """
    Sends an uninstall command to all agents matching the input filter.
    """
    query = demisto.args().get('query', '')

    agent_id = argToList(demisto.args().get('agent_id'))
    group_id = argToList(demisto.args().get('group_id'))
    if not (agent_id or group_id):
        return_error('Expecting at least one of the following arguments to filter by: agent_id, group_id.')

    affected_agents = shutdown_agents_request(query, agent_id, group_id)
    agents = affected_agents.get('data', {}).get('affected', 0)
    if agents > 0:
        demisto.results(f' Uninstall was sent to {agents} agent(s).')
    else:
        return_error('No agents were affected.')


# Event Commands

def create_query_request(query, from_date, to_date):
    endpoint_url = 'dv/init-query'
    payload = {
        'query': query,
        'fromDate': from_date,
        'toDate': to_date
    }

    response = http_request('POST', endpoint_url, data=json.dumps(payload))
    if response.get('errors'):
        return_error(response.get('errors'))
    else:
        return response.get('data', {}).get('queryId')


def create_query():
    query = demisto.args().get('query')
    from_date = demisto.args().get('from_date')
    to_date = demisto.args().get('to_date')

    query_id = create_query_request(query, from_date, to_date)

    context_entries = {
        'Query': query,
        'FromDate': from_date,
        'ToDate': to_date,
        'QueryID': query_id
    }

    context = {
        'SentinelOne.Query(val.QueryID && val.QueryID === obj.QueryID)': context_entries
    }
    return_outputs('The query ID is ' + str(query_id), context, query_id)


def get_events_request(query_id=None, limit=None):
    endpoint_url = 'dv/events'

    params = {
        'query_id': query_id,
        'limit': limit
    }

    response = http_request('GET', endpoint_url, params)
    if response.get('errors'):
        return_error(response.get('errors'))
    if 'data' in response:
        return response.get('data')
    return {}


def get_events():
    """
    Get all Deep Visibility events from query
    """
    contents = []
    event_standards = []
    headers = ['EventType', 'AgentName', 'SiteName', 'User', 'Time', 'AgentOS', 'ProcessID', 'ProcessUID',
               'ProcessName', 'MD5', 'SHA256']
    query_id = demisto.args().get('query_id')
    limit = int(demisto.args().get('limit'))

    events = get_events_request(query_id, limit)
    if events:
        for event in events:
            contents.append({
                'EventType': event.get('eventType'),
                'Endpoint': event.get('agentName'),
                'SiteName': event.get('siteName'),
                'User': event.get('user'),
                'Time': event.get('processStartTime'),
                'AgentOS': event.get('agentOs'),
                'ProcessID': event.get('pid'),
                'ProcessUID': event.get('processUniqueKey'),
                'ProcessName': event.get('processName'),
                'MD5': event.get('md5'),
                'SHA256': event.get('sha256')
            })

            event_standards.append({
                'Type': event.get('eventType'),
                'Name': event.get('processName'),
                'ID': event.get('pid'),
            })

        context = {
            'SentinelOne.Event(val.ProcessID && val.ProcessID === obj.ProcessID)': contents,
            'Event': event_standards
        }

        return_outputs(tableToMarkdown('SentinelOne Events', contents, headers, removeNull=True), context, events)
    else:
        demisto.results('No events were found.')


def get_processes_request(query_id=None, limit=None):
    endpoint_url = 'dv/events/process'

    params = {
        'query_id': query_id,
        'limit': limit
    }

    response = http_request('GET', endpoint_url, params)
    if response.get('errors'):
        return_error(response.get('errors'))
    if 'data' in response:
        return response.get('data')
    return {}


def get_processes():
    """
    Get Deep Visibility events from query by event type - process
    """
    contents = []
    headers = ['EventType', 'AgentName', 'SiteName', 'User', 'Time', 'ParentProcessID', 'ParentProcessUID',
               'ProcessName', 'ParentProcessName', 'ProcessDisplayName', 'ProcessID', 'ProcessUID',
               'SHA1', 'CMD', 'SubsystemType', 'IntegrityLevel', 'ParentProcessStartTime']
    query_id = demisto.args().get('query_id')
    limit = int(demisto.args().get('limit'))

    processes = get_events_request(query_id, limit)
    if processes:
        for process in processes:
            contents.append({
                'EventType': process.get('eventType'),
                'Endpoint': process.get('agentName'),
                'SiteName': process.get('siteName'),
                'User': process.get('user'),
                'Time': process.get('processStartTime'),
                'ParentProcessID': process.get('parentPid'),
                'ParentProcessUID': process.get('parentProcessUniqueKey'),
                'ParentProcessName': process.get('parentProcessName'),
                'ProcessID': process.get('pid'),
                'ProcessUID': process.get('processUniqueKey'),
                'ProcessName': process.get('processName'),
                'ProcessDisplayName': process.get('processDisplayName'),
                'SHA1': process.get('processImageSha1Hash'),
                'CMD': process.get('"processCmd'),
                'SubsystemType': process.get('processSubSystem'),
                'IntegrityLevel': process.get('processIntegrityLevel'),
                'ParentProcessStartTime': process.get('parentProcessStartTime')
            })

        context = {
            'SentinelOne.Event(val.ProcessID && val.ProcessID === obj.ProcessID)': contents
        }

        return_outputs(tableToMarkdown('SentinelOne Processes', contents, headers, removeNull=True), context, processes)

    else:
        demisto.results('No processes were found.')


def fetch_incidents():
    last_run = demisto.getLastRun()
    last_fetch = last_run.get('time')

    # handle first time fetch
    if last_fetch is None:
        last_fetch, _ = parse_date_range(FETCH_TIME, to_timestamp=True)

    current_fetch = last_fetch
    incidents = []
    last_fetch_date_string = timestamp_to_datestring(last_fetch, '%Y-%m-%dT%H:%M:%S.%fZ')
    threats = get_threats_request(limit=FETCH_LIMIT, created_after=last_fetch_date_string)
    for threat in threats:
        rank = threat.get('rank')
        try:
            rank = int(rank)
        except TypeError:
            rank = 0
        # If no fetch threat rank is provided, bring everything, else only fetch above the threshold
        if rank >= FETCH_THREAT_RANK:
            incident = threat_to_incident(threat)
            date_occurred_dt = parse(incident['occurred'])
            incident_date = date_to_timestamp(date_occurred_dt, '%Y-%m-%dT%H:%M:%S.%fZ')
            # update last run
            if incident_date > last_fetch:
                incidents.append(incident)

            if incident_date > current_fetch:
                current_fetch = incident_date

    demisto.setLastRun({'time': current_fetch})
    demisto.incidents(incidents)


def threat_to_incident(threat):
    incident = {}
    incident['name'] = 'Sentinel One Threat: ' + str(threat.get('classification', 'Not classified'))
    incident['occurred'] = threat.get('createdDate')
    incident['rawJSON'] = json.dumps(threat)
    return incident


def main():
    ''' PARSE INTEGRATION PARAMETERS '''

    global TOKEN, SERVER, USE_SSL, FETCH_TIME
    global FETCH_THREAT_RANK, FETCH_LIMIT, BASE_URL, HEADERS

    TOKEN = demisto.params().get('token')
    SERVER = demisto.params().get('url')[:-1] if (demisto.params().get('url')
                                                  and demisto.params().get('url').endswith('/')) \
        else demisto.params().get('url')
    USE_SSL = not demisto.params().get('insecure', False)
    FETCH_TIME = demisto.params().get('fetch_time', '3 days')
    FETCH_THREAT_RANK = int(demisto.params().get('fetch_threat_rank', 0))
    FETCH_LIMIT = int(demisto.params().get('fetch_limit', 10))
    BASE_URL = SERVER + '/web/api/v2.0/'
    HEADERS = {
        'Authorization': 'ApiToken ' + TOKEN if TOKEN else 'ApiToken',
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    ''' COMMANDS MANAGER / SWITCH PANEL '''

    LOG('command is %s' % (demisto.command()))

    try:
        handle_proxy()
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration test button.
            test_module()
            demisto.results('ok')
        elif demisto.command() == 'fetch-incidents':
            fetch_incidents()
        elif demisto.command() == 'sentinelone-get-activities':
            get_activities_command()
        elif demisto.command() == 'sentinelone-get-threats':
            get_threats_command()
        elif demisto.command() == 'sentinelone-mark-as-threat':
            mark_as_threat_command()
        elif demisto.command() == 'sentinelone-mitigate-threat':
            mitigate_threat_command()
        elif demisto.command() == 'sentinelone-resolve-threat':
            resolve_threat_command()
        elif demisto.command() == 'sentinelone-threat-summary':
            get_threat_summary_command()
        elif demisto.command() == 'sentinelone-get-hash':
            get_hash_command()
        elif demisto.command() == 'sentinelone-get-white-list':
            get_white_list_command()
        elif demisto.command() == 'sentinelone-create-white-list-item':
            create_white_item_command()
        elif demisto.command() == 'sentinelone-get-sites':
            get_sites_command()
        elif demisto.command() == 'sentinelone-get-site':
            get_site_command()
        elif demisto.command() == 'sentinelone-reactivate-site':
            reactivate_site_command()
        elif demisto.command() == 'sentinelone-list-agents':
            list_agents_command()
        elif demisto.command() == 'sentinelone-get-agent':
            get_agent_command()
        elif demisto.command() == 'sentinelone-get-groups':
            get_groups_command()
        elif demisto.command() == 'sentinelone-move-agent':
            move_agent_to_group_command()
        elif demisto.command() == 'sentinelone-delete-group':
            delete_group()
        elif demisto.command() == 'sentinelone-agent-processes':
            get_agent_processes()
        elif demisto.command() == 'sentinelone-connect-agent':
            connect_agent_to_network()
        elif demisto.command() == 'sentinelone-disconnect-agent':
            disconnect_agent_from_network()
        elif demisto.command() == 'sentinelone-broadcast-message':
            broadcast_message()
        elif demisto.command() == 'sentinelone-get-events':
            get_events()
        elif demisto.command() == 'sentinelone-create-query':
            create_query()
        elif demisto.command() == 'sentinelone-get-processes':
            get_processes()
        elif demisto.command() == 'sentinelone-shutdown-agent':
            shutdown_agents()
        elif demisto.command() == 'sentinelone-uninstall-agent':
            uninstall_agent()

    except Exception as e:
        if demisto.command() == 'fetch-incidents':
            LOG(str(e))
            raise
        else:
            return_error(e)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
