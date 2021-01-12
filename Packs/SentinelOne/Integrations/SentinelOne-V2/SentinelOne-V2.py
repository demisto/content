from typing import Callable

import demistomock as demisto
from CommonServerPython import *

''' IMPORTS '''

import json
import requests
import traceback

from dateutil.parser import parse

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS '''

IS_VERSION_2_1: bool

''' HELPER FUNCTIONS '''


def get_threats_outputs(threats, rank: int = 0):
    for threat in threats:
        threat_rank = int(threat.get('rank') or 0)
        if IS_VERSION_2_1 or threat_rank >= rank:
            threat_info = threat.get('threatInfo', {}) if IS_VERSION_2_1 else threat
            agent_realtime_info = threat.get('agentRealtimeInfo', {}) if IS_VERSION_2_1 else threat
            entry = {
                'ID': threat.get('id'),
                'AgentComputerName': agent_realtime_info.get('agentComputerName'),
                'CreatedDate': threat_info.get('createdAt'),
                'SiteID': agent_realtime_info.get('siteId'),
                'SiteName': agent_realtime_info.get('siteName'),
                'Classification': threat_info.get('classification'),
                'ClassificationSource': threat_info.get('classificationSource'),
                'MitigationStatus': threat_info.get('mitigationStatus'),
                'AgentID': agent_realtime_info.get('agentId'),
                'ConfidenceLevel': threat_info.get('confidenceLevel'),
                'FileContentHash': threat_info.get('sha1') if IS_VERSION_2_1 else threat_info.get('fileContentHash'),
                'ThreatName': threat_info.get('threatName'),
                'FileSha256': threat_info.get('fileSha256'),
                'AgentOsType': agent_realtime_info.get('agentOsType'),
                'FilePath': threat_info.get('filePath'),
                'Username': threat_info.get('processUser') if IS_VERSION_2_1 else threat_info.get('username'),
                'Description': threat_info.get('description'),  # Only available in 2.0
                'FileDisplayName': threat.get('fileDisplayName'),  # Only available in 2.0
                'Rank': threat_info.get('rank'),  # Only available in 2.0
                'MarkedAsBenign': threat_info.get('markedAsBenign'),  # Only available in 2.0
                'InQuarantine': threat_info.get('inQuarantine'),  # Only available in 2.0
                'FileMaliciousContent': threat_info.get('fileMaliciousContent'),  # Only available in 2.0
            }
            remove_nulls_from_dictionary(entry)
            yield entry


def get_agents_outputs(agents):
    for agent in agents:
        entry = {
            'ID': agent.get('id'),
            'NetworkStatus': agent.get('networkStatus'),
            'AgentVersion': agent.get('agentVersion'),
            'IsDecommissioned': agent.get('isDecommissioned'),
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
            'SiteName': agent.get('siteName'),
        }
        remove_nulls_from_dictionary(entry)
        yield entry


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def get_activities_request(self, created_after: str = None, user_emails: str = None, group_ids=None,
                               created_until: str = None,
                               activities_ids=None, include_hidden: str = None, created_before: str = None,
                               threats_ids=None,
                               activity_types=None, user_ids=None, created_from: str = None,
                               created_between: str = None, agent_ids=None,
                               limit: str = '50'):
        params = assign_params(
            created_at__gt=created_after,
            userEmails=user_emails,
            groupIds=argToList(group_ids),
            created_at__lte=created_until,
            ids=argToList(activities_ids),
            includeHidden=include_hidden,
            created_at__lt=created_before,
            threatIds=argToList(threats_ids),
            activityTypes=argToList(activity_types),
            userIds=argToList(user_ids),
            created_at__gte=created_from,
            createdAt_between=created_between,
            agentIds=argToList(agent_ids),
            limit=int(limit), )
        response = self._http_request(method='GET', url_suffix='activities', params=params)
        return response.get('data', {})

    def get_threats_request(self, content_hash=None, mitigation_status=None, created_before=None, created_after=None,
                            created_until=None, created_from=None, resolved='false', display_name=None, query=None,
                            threat_ids=None, limit=20, classifications=None):
        keys_to_ignore = ['displayName__like' if IS_VERSION_2_1 else 'displayName']

        params = assign_params(
            contentHashes=argToList(content_hash),
            mitigationStatuses=argToList(mitigation_status),
            createdAt__lt=created_before,
            createdAt__gt=created_after,
            createdAt__lte=created_until,
            createdAt__gte=created_from,
            resolved=argToBoolean(resolved),
            displayName__like=display_name,
            displayName=display_name,
            query=query,
            ids=argToList(threat_ids),
            limit=int(limit),
            classifications=argToList(classifications),
            keys_to_ignore=keys_to_ignore,
        )
        response = self._http_request(method='GET', url_suffix='threats', params=params)
        return response.get('data', {})

    def mark_as_threat_request(self, threat_ids, target_scope):
        endpoint_url = 'threats/mark-as-threat'

        payload = {
            "filter": {
                "ids": threat_ids
            },
            "data": {
                "targetScope": target_scope
            }
        }

        response = self._http_request(method='POST', url_suffix=endpoint_url, json_data=payload)
        return response.get('data', {})

    def mitigate_threat_request(self, threat_ids, action):
        endpoint_url = f'threats/mitigate/{action}'

        payload = {
            "filter": {
                "ids": threat_ids
            }
        }

        response = self._http_request(method='POST', url_suffix=endpoint_url, json_data=payload)
        return response.get('data', {})

    def resolve_threat_request(self, threat_ids):
        endpoint_url = 'threats/mark-as-resolved'

        payload = {
            "filter": {
                "ids": threat_ids
            }
        }

        response = self._http_request(method='POST', url_suffix=endpoint_url, json_data=payload)
        return response.get('data', {})

    def get_groups_request(self, params: dict):
        response = self._http_request(method='GET', url_suffix='groups', params=params)
        return response.get('data', {})

    def delete_group_request(self, group_id=None):
        endpoint_url = f'groups/{group_id}'
        response = self._http_request(method='DELETE', url_suffix=endpoint_url)
        return response.get('data', {})

    def get_sites_request(self, params):
        response = self._http_request(method='GET', url_suffix='sites', params=params)
        return response.get('data', {})

    def move_agent_request(self, group_id, agents_id):
        endpoint_url = f'groups/{group_id}/move-agents'

        payload = {
            "filter": {
                "ids": agents_id
            }
        }

        response = self._http_request(method='PUT', url_suffix=endpoint_url, json_data=payload)
        return response.get('data', {})

    def get_agent_processes_request(self, agents_ids=None):
        """
        [DEPRECATED BY S1] Returns empty array. To get processes of an Agent, see Applications.

        """
        endpoint_url = 'agents/processes'

        params = {
            'ids': agents_ids
        }

        response = self._http_request(method='GET', url_suffix=endpoint_url, params=params)
        return response.get('data', {})

    def get_site_request(self, site_id):
        endpoint_url = f'sites/{site_id}'
        response = self._http_request(method='GET', url_suffix=endpoint_url)
        return response.get('data', {})

    def reactivate_site_request(self, site_id):
        endpoint_url = f'sites/{site_id}/reactivate'
        response = self._http_request(method='PUT', url_suffix=endpoint_url)
        return response.get('data', {})

    def get_threat_summary_request(self, site_ids=None, group_ids=None):
        endpoint_url = 'private/threats/summary'
        params = {
            "siteIds": site_ids,
            "groupIds": group_ids
        }
        response = self._http_request(method='GET', url_suffix=endpoint_url, params=params)
        return response.get('data', {})

    def list_agents_request(self, params: dict):
        response = self._http_request(method='GET', url_suffix='agents', params=params)
        return response.get('data', {})

    def get_agent_request(self, agent_ids):
        params = {
            "ids": agent_ids
        }

        response = self._http_request(method='GET', url_suffix='agents', params=params)
        return response.get('data', {})

    def connect_to_network_request(self, agent_ids):
        endpoint_url = 'agents/actions/connect'

        payload = {
            'filter': {
                'ids': agent_ids
            }
        }

        response = self._http_request(method='POST', url_suffix=endpoint_url, json_data=payload)
        return response.get('data', {})

    def disconnect_from_network_request(self, agents_id):
        endpoint_url = 'agents/actions/disconnect'

        payload = {
            'filter': {
                'ids': agents_id
            }
        }

        response = self._http_request(method='POST', url_suffix=endpoint_url, json_data=payload)
        return response.get('data', {})

    def broadcast_message_request(self, message, filters):
        endpoint_url = 'agents/actions/broadcast'

        payload = {
            'data': {
                'message': message
            },
            'filter': filters
        }
        response = self._http_request(method='POST', url_suffix=endpoint_url, json_data=payload)

        return response.get('data', {})

    def uninstall_agent_request(self, query, agent_id=None, group_id=None):
        endpoint_url = 'agents/actions/uninstall'
        payload = {
            'filter': assign_params(
                query=query,
                ids=agent_id,
                groupIds=group_id,
            )
        }

        response = self._http_request(method='POST', url_suffix=endpoint_url, json_data=payload)
        return response.get('data', {})

    def shutdown_agents_request(self, query, agent_id=None, group_id=None):
        endpoint_url = 'agents/actions/shutdown'
        payload = {
            'filter': assign_params(
                query=query,
                ids=agent_id,
                groupIds=group_id
            )
        }

        response = self._http_request(method='POST', url_suffix=endpoint_url, json_data=payload)
        return response.get('data', {})

    def create_query_request(self, query, from_date, to_date):
        endpoint_url = 'dv/init-query'
        payload = {
            'query': query,
            'fromDate': from_date,
            'toDate': to_date
        }

        response = self._http_request(method='POST', url_suffix=endpoint_url, json_data=payload)
        return response.get('data', {}).get('queryId')

    def get_events_request(self, query_id=None, limit=None):
        endpoint_url = 'dv/events'

        params = {
            'query_id': query_id,
            'limit': limit
        }

        response = self._http_request(method='GET', url_suffix=endpoint_url, params=params)
        return response.get('data', {})

    def get_processes_request(self, query_id=None, limit=None):
        endpoint_url = 'dv/events/process'
        params = {
            'query_id': query_id,
            'limit': limit
        }

        response = self._http_request(method='GET', url_suffix=endpoint_url, params=params)
        return response.get('data', {})

    def get_hash_reputation_request(self, hash_):
        endpoint_url = f'hashes/{hash_}/reputation'
        response = self._http_request(method='GET', url_suffix=endpoint_url)
        return response

    def get_hash_classification_request(self, hash_):
        """
        [DEPRECATED by S1] IN BOTH 2.0 and 2.1
        """
        endpoint_url = f'hashes/{hash_}/classification'
        response = self._http_request(method='GET', url_suffix=endpoint_url)
        return response

    def get_exclusions_request(self, item_ids=None, os_types=None, exclusion_type: str = None, limit: int = 10):
        endpoint_url = 'exclusions'

        params = {
            "ids": item_ids,
            "osTypes": os_types,
            "type": exclusion_type,
            "limit": limit
        }

        response = self._http_request(method='GET', url_suffix=endpoint_url, params=params)
        return response.get('data', {})

    def create_exclusion_item_request(self, exclusion_type, exclusion_value, os_type, description=None,
                                      exclusion_mode=None, path_exclusion_type=None, group_ids=None, site_ids=None):
        payload = {
            "filter": {
                "groupIds": group_ids,
                "siteIds": site_ids
            },
            "data": assign_params(
                type=exclusion_type,
                value=exclusion_value,
                osType=os_type,
                description=description,
                mode=exclusion_mode,
                pathExclusionType=path_exclusion_type
            )
        }

        response = self._http_request(method='POST', url_suffix='exclusions', json_data=payload)
        if 'data' in response:
            return response.get('data')[0]
        return {}


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module(client: Client, args: dict):
    """
    Performs basic get request to get activities types.
    """
    try:
        client._http_request(method='GET', url_suffix='activities/types')
    except Exception as e:
        raise DemistoException(f"Test failed. Please verify the URL and Token parameters.\nReason:\n{e}")
    return 'ok'


def get_activities_command(client: Client, args: dict) -> CommandResults:
    """
    Get a list of activities.
    """
    context_entries = []
    headers = ['ID', 'PrimaryDescription', 'Data', 'UserID', 'CreatedAt', 'ThreatID', 'UpdatedAt']
    activities = client.get_activities_request(**args)

    if activities:
        for activity in activities:
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
                'SiteID': activity.get('siteId'),
            })

    return CommandResults(
        readable_output=tableToMarkdown('Sentinel One Activities', context_entries, headers=headers, removeNull=True,
                                        headerTransform=pascalToSpace),
        outputs_prefix='SentinelOne.Activity',
        outputs_key_field='ID',
        outputs=context_entries,
        raw_response=activities)


def get_groups_command(client: Client, args: dict) -> CommandResults:
    """
    Gets the group data.
    """

    headers = ['id', 'name', 'type', 'creator', 'creatorId', 'createdAt', 'rank']

    query_params = assign_params(
        type=args.get('group_type'),
        id=args.get('id'),
        groupIds=argToList(args.get('group_ids')),
        isDefault=args.get('is_default'),
        name=args.get('name'),
        query=args.get('query'),
        rank=args.get('rank'),
        limit=int(args.get('limit', 50)),
    )
    groups = client.get_groups_request(query_params)

    return CommandResults(
        readable_output=tableToMarkdown('Sentinel One Groups', groups, headers, headerTransform=pascalToSpace,
                                        removeNull=True),
        outputs_prefix='SentinelOne.Group',
        outputs_key_field='ID',
        outputs=groups,
        raw_response=groups)


def delete_group(client: Client, args: dict) -> str:
    """
    Deletes a group by ID.
    """
    group_id = args.get('group_id')
    response = client.delete_group_request(group_id)
    if response.get('success'):
        return f'Group: {group_id} was deleted successfully'
    return f'The deletion of group: {group_id} has failed'


def move_agent_to_group_command(client: Client, args: dict) -> CommandResults:
    """
    Move agents to a new group.
    """
    group_id = args.get('group_id')
    agents_id = argToList(args.get('agents_ids', []))

    agents_groups = client.move_agent_request(group_id, agents_id)

    # Parse response into context & content entries
    if agents_groups.get('agentsMoved') and int(agents_groups.get('agentsMoved')) > 0:
        agents_moved = True
    else:
        agents_moved = False
    date_time_utc = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    context_entries = {
        'Date': date_time_utc,
        'AgentsMoved': agents_groups.get('agentsMoved'),
        'AffectedAgents': agents_moved,
    }

    return CommandResults(
        readable_output=tableToMarkdown(f'Sentinel One - Moved Agents\nTotal of: {agents_groups.get("AgentsMoved", 0)}'
                                        f'agents were Moved successfully', context_entries, removeNull=True),
        outputs_prefix='SentinelOne.Agent',
        outputs_key_field='Date',
        outputs=context_entries,
        raw_response=agents_groups)


def get_agent_processes(client: Client, args: dict):
    """
    Retrieve running processes for a specific agent.
    Note: This feature is obsolete and an empty array will always be returned
    """
    headers = ['ProcessName', 'StartTime', 'Pid', 'MemoryUsage', 'CpuUsage', 'ExecutablePath']
    contents = []
    context = {}
    agents_ids = args.get('agents_ids')

    processes = client.get_agent_processes_request(agents_ids)

    if processes:
        for process in processes:
            contents.append({
                'ProcessName': process.get('processName'),
                'CpuUsage': process.get('cpuUsage'),
                'MemoryUsage': process.get('memoryUsage'),
                'StartTime': process.get('startTime'),
                'ExecutablePath': process.get('executablePath'),
                'Pid': process.get('pid'),
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


def get_threats_command(client: Client, args: dict) -> CommandResults:
    """
    Gets a list of threats.
    Rank only relevant for API version 2.0
    """
    headers = ['ID', 'AgentComputerName', 'CreatedDate', 'SiteID', 'SiteName', 'Classification', 'MitigationStatus',
               'ConfidenceLevel' if IS_VERSION_2_1 else 'Rank', 'AgentID', 'FileContentHash', 'MarkedAsBenign']

    threats = client.get_threats_request(**args)
    outputs = list(get_threats_outputs(threats, int(args.get('rank', 0)))) if threats else None

    return CommandResults(
        readable_output=tableToMarkdown(
            'Sentinel One - Getting Threat List', outputs,
            metadata='Provides summary information and details for all the threats that matched your search criteria.',
            headers=headers, headerTransform=pascalToSpace, removeNull=True),
        outputs_prefix='SentinelOne.Threat',
        outputs_key_field='ID',
        outputs=outputs,
        raw_response=threats)


def get_hash_command(client: Client, args: dict) -> CommandResults:
    """
    Get hash reputation.
    Removed hash classification since SentinelOne has deprecated it - Breaking BC.
    """
    hash_ = args.get('hash')
    type_ = get_hash_type(hash_)
    if type_ == 'Unknown':
        raise DemistoException('Enter a valid hash format.')

    hash_reputation = client.get_hash_reputation_request(hash_)
    reputation = hash_reputation.get('data', {})
    contents = {
        'Rank': reputation.get('rank'),
        'Hash': hash_,
    }

    return CommandResults(
        readable_output=tableToMarkdown('Sentinel One - Hash Reputation\nProvides hash reputation (rank from 0 to 10):',
                                        contents, removeNull=True),
        outputs_prefix='SentinelOne.Hash',
        outputs_key_field='Hash',
        outputs=contents,
        raw_response=hash_reputation)


def mark_as_threat_command(client: Client, args: dict) -> CommandResults:
    """
    Mark suspicious threats as threats
    """
    context_entries = []

    threat_ids = argToList(args.get('threat_ids'))
    target_scope = args.get('target_scope')

    # Make request and get raw response
    affected_threats = client.mark_as_threat_request(threat_ids, target_scope)

    # Parse response into context & content entries
    if affected_threats.get('affected') and int(affected_threats.get('affected')) > 0:
        title = f'Total of {affected_threats.get("affected")} provided threats were marked successfully'
        affected = True
    else:
        affected = False
        title = 'No threats were marked'
    for threat_id in threat_ids:
        context_entries.append({
            'MarkedAsThreat': affected,
            'ID': threat_id,
        })

    return CommandResults(
        readable_output=tableToMarkdown('Sentinel One - Marking suspicious threats as threats \n' + title,
                                        context_entries, headerTransform=pascalToSpace, removeNull=True),
        outputs_prefix='SentinelOne.Threat',
        outputs_key_field='ID',
        outputs=context_entries,
        raw_response=affected_threats)


def mitigate_threat_command(client: Client, args: dict) -> CommandResults:
    """
    Apply a mitigation action to a group of threats
    """
    contents = []
    context_entries = []

    # Get arguments
    threat_ids = argToList(args.get('threat_ids'))
    action = args.get('action')

    # Make request and get raw response
    mitigated_threats = client.mitigate_threat_request(threat_ids, action)

    # Parse response into context & content entries
    if mitigated_threats.get('affected') and int(mitigated_threats.get('affected')) > 0:
        mitigated = True
        meta = f'Total of {mitigated_threats.get("affected")} provided threats were mitigated successfully'
    else:
        mitigated = False
        meta = 'No threats were mitigated'
    for threat_id in threat_ids:
        contents.append({
            'Mitigated': mitigated,
            'ID': threat_id,
            'Mitigation Action': action,
        })
        context_entries.append({
            'Mitigated': mitigated,
            'ID': threat_id,
            'Mitigation': {
                'Action': action
            },
        })

    return CommandResults(
        readable_output=tableToMarkdown('Sentinel One - Mitigating threats', contents, metadata=meta, removeNull=True),
        outputs_prefix='SentinelOne.Threat',
        outputs_key_field='ID',
        outputs=context_entries,
        raw_response=mitigated_threats)


def resolve_threat_command(client: Client, args: dict) -> CommandResults:
    """
    Mark threats as resolved
    """
    context_entries = []

    threat_ids = argToList(args.get('threat_ids'))

    # Make request and get raw response
    resolved_threats = client.resolve_threat_request(threat_ids)

    # Parse response into context & content entries
    if resolved_threats.get('affected') and int(resolved_threats.get('affected')) > 0:
        resolved = True
        title = f'Total of {resolved_threats.get("affected")} provided threats were resolved successfully'
    else:
        resolved = False
        title = 'No threats were resolved'

    for threat_id in threat_ids:
        context_entries.append({
            'Resolved': resolved,
            'ID': threat_id,
        })

    return CommandResults(
        readable_output=tableToMarkdown('Sentinel One - Resolving threats\n' + title, context_entries, removeNull=True),
        outputs_prefix='SentinelOne.Threat',
        outputs_key_field='ID',
        outputs=context_entries,
        raw_response=resolved_threats)


def get_white_list_command(client: Client, args: dict) -> CommandResults:
    """
    List all white items matching the input filter
    """
    context_entries = []

    # Get arguments
    item_ids = argToList(args.get('item_ids', []))
    os_types = argToList(args.get('os_types', []))
    exclusion_type = args.get('exclusion_type')
    limit = int(args.get('limit', 10))

    # Make request and get raw response
    exclusion_items = client.get_exclusions_request(item_ids, os_types, exclusion_type, limit)

    # Parse response into context & content entries
    if exclusion_items:
        for exclusion_item in exclusion_items:
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
                'Mode': exclusion_item.get('mode'),
            })

    return CommandResults(
        readable_output=tableToMarkdown('Sentinel One - Listing exclusion items', context_entries, removeNull=True,
                                        metadata='Provides summary information and details for all the exclusion items'
                                                 ' that matched your search criteria.'),
        outputs_prefix='SentinelOne.Exclusions',
        outputs_key_field='ID',
        outputs=context_entries,
        raw_response=exclusion_items)


def create_white_item_command(client: Client, args: dict):
    """
    Create white item.
    """
    context_entries = []
    title = ''

    group_ids = argToList(args.get('group_ids', []))
    site_ids = argToList(args.get('site_ids', []))
    exclusion_type = args.get('exclusion_type')
    exclusion_value = args.get('exclusion_value')
    os_type = args.get('os_type')
    description = args.get('description')
    exclusion_mode = args.get('exclusion_mode')
    path_exclusion_type = args.get('path_exclusion_type')

    if not (group_ids or site_ids):
        raise DemistoException("You must provide either group_ids or site_ids.")

    # Make request and get raw response
    new_item = client.create_exclusion_item_request(exclusion_type, exclusion_value, os_type, description,
                                                    exclusion_mode, path_exclusion_type, group_ids, site_ids)

    # Parse response into context & content entries
    if new_item:
        title = 'Sentinel One - Adding an exclusion item \n' + \
                'The provided item was successfully added to the exclusion list'
        context_entries.append({
            'ID': new_item.get('id'),
            'Type': new_item.get('type'),
            'CreatedAt': new_item.get('createdAt'),
        })

    return CommandResults(
        readable_output=tableToMarkdown(title, context_entries, removeNull=True, headerTransform=pascalToSpace),
        outputs_prefix='SentinelOne.Exclusion',
        outputs_key_field='ID',
        outputs=context_entries,
        raw_response=new_item)


def get_sites_command(client: Client, args: dict) -> CommandResults:
    """
    List all sites with filtering options
    """
    context_entries = []

    query_params = assign_params(
        updatedAt=args.get('updated_at'),
        query=args.get('query'),
        siteType=args.get('site_type'),
        features=args.get('features'),
        state=args.get('state'),
        suite=args.get('suite'),
        # HTTP 500 - server internal error when passing admin_only.
        adminOnly=argToBoolean(args.get('admin_only')) if args.get('admin_only') else None,
        accountId=args.get('account_id'),
        name=args.get('site_name'),
        createdAt=args.get('created_at'),
        limit=int(args.get('limit', 50)),
        siteIds=argToList(args.get('site_ids')),
    )

    # Make request and get raw response
    raw_response = client.get_sites_request(query_params)
    sites, all_sites = raw_response.get('sites'), raw_response.get('allSites')

    # Parse response into context & content entries
    if sites:
        for site in sites:
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
                'ActiveLicenses': all_sites.get('activeLicenses'),
            })

    return CommandResults(
        readable_output=tableToMarkdown('Sentinel One - Getting List of Sites', context_entries, removeNull=True,
                                        metadata='Provides summary information and details for all sites that matched '
                                                 'your search criteria.', headerTransform=pascalToSpace),
        outputs_prefix='SentinelOne.Site',
        outputs_key_field='ID',
        outputs=context_entries,
        raw_response=raw_response)


def get_site_command(client: Client, args: dict) -> CommandResults:
    """
    Get a specific site by ID
    """
    # Init main vars
    context_entries = []

    # Get arguments
    site_id = args.get('site_id')

    # Make request and get raw response
    site = client.get_site_request(site_id)

    # Parse response into context & content entries
    if site:
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
            'IsDefault': site.get('isDefault'),
        })

    return CommandResults(
        readable_output=tableToMarkdown(f'Sentinel One - Summary About Site: {site_id}', context_entries,
                                        removeNull=True,
                                        metadata='Provides summary information and details for specific site ID',
                                        headerTransform=pascalToSpace),
        outputs_prefix='SentinelOne.Site',
        outputs_key_field='ID',
        outputs=context_entries,
        raw_response=site)


def reactivate_site_command(client: Client, args: dict) -> CommandResults:
    """
    Reactivate specific site by ID
    """
    # Init main vars
    context = {}

    # Get arguments
    site_id = args.get('site_id')

    # Make request and get raw response
    site = client.reactivate_site_request(site_id)

    # Parse response into context & content entries
    if site:
        context = {
            'ID': site.get('id'),
            'Reactivated': site.get('success'),
        }

    return CommandResults(
        readable_output=tableToMarkdown(f'Sentinel One - Reactivated Site: {site_id}', context, removeNull=True),
        outputs_prefix='SentinelOne.Site',
        outputs_key_field='ID',
        outputs=context,
        raw_response=site)


def get_threat_summary_command(client: Client, args: dict) -> CommandResults:
    """
    Get dashboard threat summary
    """
    # Init main vars
    context_entries = {}

    site_ids = argToList(args.get('site_ids'))
    group_ids = argToList(args.get('group_ids'))

    # Make request and get raw response
    threat_summary = client.get_threat_summary_request(site_ids, group_ids)

    # Parse response into context & content entries
    if threat_summary:
        context_entries = {
            'InProgress': threat_summary.get('inProgress'),
            'MaliciousNotResolved': threat_summary.get('maliciousNotResolved'),
            'NotMitigated': threat_summary.get('notMitigated'),
            'NotMitigatedNotResolved': threat_summary.get('notMitigatedNotResolved'),
            'NotResolved': threat_summary.get('notResolved'),
            'Resolved': threat_summary.get('resolved'),
            'SuspiciousNotMitigatedNotResolved': threat_summary.get('suspiciousNotMitigatedNotResolved'),
            'SuspiciousNotResolved': threat_summary.get('suspiciousNotResolved'),
            'Total': threat_summary.get('total'),
        }

    return CommandResults(
        readable_output=tableToMarkdown('Sentinel One - Dashboard Threat Summary', context_entries, removeNull=True,
                                        headerTransform=pascalToSpace),
        outputs_prefix='SentinelOne.Threat',
        outputs_key_field='ID',
        outputs=context_entries,
        raw_response=threat_summary)


# Agents Commands


def list_agents_command(client: Client, args: dict) -> CommandResults:
    """
    List all agents matching the input filter
    """
    # Get arguments
    query_params = assign_params(
        active_threats=args.get('min_active_threats'),
        computer_name=args.get('computer_name'),
        scan_status=args.get('scan_status'),
        os_type=args.get('os_type'),
        created_at=args.get('created_at'),
    )

    # Make request and get raw response
    agents = client.list_agents_request(query_params)

    # Parse response into context & content entries
    context_entries = list(get_agents_outputs(agents)) if agents else None

    return CommandResults(
        readable_output=tableToMarkdown('Sentinel One - List of Agents', context_entries, headerTransform=pascalToSpace,
                                        removeNull=True, metadata='Provides summary information and details for all'
                                                                  ' the agents that matched your search criteria'),
        outputs_prefix='SentinelOne.Agents',
        outputs_key_field='ID',
        outputs=context_entries,
        raw_response=agents)


def get_agent_command(client: Client, args: dict) -> CommandResults:
    """
    Get single agent via ID
    """
    # Get arguments
    agent_ids = argToList(args.get('agent_id'))

    # Make request and get raw response
    agents = client.get_agent_request(agent_ids)

    # Parse response into context & content entries
    context_entries = list(get_agents_outputs(agents)) if agents else None

    return CommandResults(
        readable_output=tableToMarkdown('Sentinel One - Get Agent Details', context_entries,
                                        headerTransform=pascalToSpace, removeNull=True),
        outputs_prefix='SentinelOne.Agent',
        outputs_key_field='ID',
        outputs=context_entries,
        raw_response=agents)


def connect_agent_to_network(client: Client, args: dict) -> Union[CommandResults, str]:
    """
    Sends a "connect to network" command to all agents matching the input filter.
    """
    agent_ids = argToList(args.get('agent_id'))

    # Make request and get raw response
    raw_response = client.connect_to_network_request(agent_ids)
    agents_affected = raw_response.get('affected', 0)

    # Parse response into context & content entries
    if agents_affected > 0:
        agents = client.list_agents_request({'ids': agent_ids})
        contents = [{
            'NetworkStatus': agent.get('networkStatus'),
            'ID': agent.get('id')
        } for agent in agents]

        return CommandResults(
            readable_output=f'{agents_affected} agent(s) successfully connected to the network.',
            outputs_prefix='SentinelOne.Agent',
            outputs_key_field='ID',
            outputs=contents,
            raw_response=raw_response)

    return 'No agents were connected to the network.'


def disconnect_agent_from_network(client: Client, args: dict) -> Union[CommandResults, str]:
    """
    Sends a "disconnect from network" command to all agents matching the input filter.
    """
    agent_ids = argToList(args.get('agent_id'))

    # Make request and get raw response
    raw_response = client.disconnect_from_network_request(agent_ids)
    agents_affected = raw_response.get('affected', 0)

    if agents_affected > 0:
        agents = client.list_agents_request({'ids': agent_ids})
        contents = [{
            'NetworkStatus': agent.get('networkStatus'),
            'ID': agent.get('id')
        } for agent in agents]

        return CommandResults(
            readable_output=f'{agents_affected} agent(s) successfully disconnected from the network.',
            outputs_prefix='SentinelOne.Agent',
            outputs_key_field='ID',
            outputs=contents,
            raw_response=raw_response)

    return 'No agents were disconnected from the network.'


def broadcast_message(client: Client, args: dict) -> str:
    """
    Broadcasts a message to all agents matching the input filter.
    """
    message = args.get('message')
    filters = assign_params(
        isActive=argToBoolean(args.get('active_agent', 'false')),
        groupIds=argToList(args.get('group_id')),
        ids=argToList(args.get('agent_id')),
        domains=argToList(args.get('domain')),
    )

    response = client.broadcast_message_request(message, filters)

    agents_affected = response.get('affected', 0)
    if agents_affected > 0:
        return 'The message was successfully delivered to the agent(s)'

    return 'No messages were sent. Verify that the inputs are correct.'


def shutdown_agents(client: Client, args: dict) -> str:
    """
    Sends a shutdown command to all agents matching the input filter
    """
    query = args.get('query', '')

    agent_id = argToList(args.get('agent_id'))
    group_id = argToList(args.get('group_id'))
    if not (agent_id or group_id):
        raise DemistoException('Expecting at least one of the following arguments to filter by: agent_id, group_id.')

    response = client.shutdown_agents_request(query, agent_id, group_id)
    affected_agents = response.get('affected', 0)
    if affected_agents > 0:
        return f'Shutting down {affected_agents} agent(s).'

    return 'No agents were shutdown.'


def uninstall_agent(client: Client, args: dict) -> str:
    """
    Sends an uninstall command to all agents matching the input filter.
    """
    query = args.get('query', '')

    agent_id = argToList(args.get('agent_id'))
    group_id = argToList(args.get('group_id'))
    if not (agent_id or group_id):
        raise DemistoException('Expecting at least one of the following arguments to filter by: agent_id, group_id.')

    response = client.uninstall_agent_request(query, agent_id, group_id)
    affected_agents = response.get('affected', 0)
    if affected_agents > 0:
        return f'Uninstall was sent to {affected_agents} agent(s).'
    return 'No agents were affected.'


# Event Commands

def create_query(client: Client, args: dict) -> CommandResults:
    query = args.get('query')
    from_date = args.get('from_date')
    to_date = args.get('to_date')

    query_id = client.create_query_request(query, from_date, to_date)

    context_entries = {
        'Query': query,
        'FromDate': from_date,
        'ToDate': to_date,
        'QueryID': query_id,
    }
    return CommandResults(
        readable_output=f'The query ID is {query_id}',
        outputs_prefix='SentinelOne.Query',
        outputs_key_field='QueryID',
        outputs=context_entries,
        raw_response=query_id)


def get_events(client: Client, args: dict) -> Union[CommandResults, str]:
    """
    Get all Deep Visibility events from query
    """
    contents = []
    event_standards = []
    query_id = args.get('query_id')
    limit = int(args.get('limit', 50))

    events = client.get_events_request(query_id, limit)
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
                'ProcessUID': event.get('srcProcUid') if IS_VERSION_2_1 else event.get('processUniqueKey'),
                'ProcessName': event.get('processName'),
                'MD5': event.get('md5'),
                'SHA256': event.get('sha256'),
            })

            event_standards.append({
                'Type': event.get('eventType'),
                'Name': event.get('processName'),
                'ID': event.get('pid'),
            })

        context = {
            'SentinelOne.Event(val.ProcessID && val.ProcessID === obj.ProcessID)': contents,
            'Event(val.ID && val.ID === obj.ID)': event_standards
        }
        return CommandResults(
            readable_output=tableToMarkdown('SentinelOne Events', contents, removeNull=True),
            outputs=context,
            raw_response=events)

    return 'No events were found.'


def get_processes(client: Client, args: dict) -> CommandResults:
    """
    Get Deep Visibility events from query by event type - process
    """
    contents = []

    query_id = args.get('query_id')
    limit = int(args.get('limit', 50))

    processes = client.get_processes_request(query_id, limit)
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
                'ProcessUID': process.get('srcProcUid') if IS_VERSION_2_1 else process.get('processUniqueKey'),
                'ProcessName': process.get('processName'),
                'ProcessDisplayName': process.get('processDisplayName'),
                'SHA1': process.get('processImageSha1Hash'),
                'CMD': process.get('"processCmd'),
                'SubsystemType': process.get('processSubSystem'),
                'IntegrityLevel': process.get('processIntegrityLevel'),
                'ParentProcessStartTime': process.get('parentProcessStartTime'),
            })

    return CommandResults(
        readable_output=tableToMarkdown('SentinelOne Processes', contents, removeNull=True),
        outputs_prefix='SentinelOne.Event',
        outputs_key_field='ProcessID',
        outputs=contents,
        raw_response=processes)


def fetch_incidents(client: Client, fetch_limit: int, first_fetch: str, fetch_threat_rank: int):
    last_run = demisto.getLastRun()
    last_fetch = last_run.get('time')

    # handle first time fetch
    if last_fetch is None:
        last_fetch, _ = parse_date_range(first_fetch, to_timestamp=True)

    current_fetch = last_fetch
    incidents = []
    last_fetch_date_string = timestamp_to_datestring(last_fetch, '%Y-%m-%dT%H:%M:%S.%fZ')

    threats = client.get_threats_request(limit=fetch_limit, created_after=last_fetch_date_string)
    for threat in threats:
        rank = threat.get('rank')
        try:
            rank = int(rank)
        except TypeError:
            rank = 0
        # If no fetch threat rank is provided, bring everything, else only fetch above the threshold
        if rank >= fetch_threat_rank or IS_VERSION_2_1:
            incident = threat_to_incident(threat)
            date_occurred_dt = parse(incident['occurred'])
            incident_date = date_to_timestamp(date_occurred_dt, '%Y-%m-%dT%H:%M:%S.%fZ')
            if incident_date > last_fetch:
                incidents.append(incident)

            if incident_date > current_fetch:
                current_fetch = incident_date

    demisto.setLastRun({'time': current_fetch})
    demisto.incidents(incidents)


def threat_to_incident(threat) -> dict:
    threat_info = threat.get('threatInfo', {}) if IS_VERSION_2_1 else threat
    incident = {
        'name': f'Sentinel One Threat: {threat_info.get("classification", "Not classified")}',
        'occurred': threat_info.get('createdAt'),
        'rawJSON': json.dumps(threat)}
    return incident


def main():
    """ PARSE INTEGRATION PARAMETERS """

    global IS_VERSION_2_1

    params = demisto.params()
    token = params.get('token')
    api_version = params.get('api_version', '2.1')
    server = params.get('url').rstrip('/')
    base_url = urljoin(server, f'/web/api/v{api_version}/')
    use_ssl = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    IS_VERSION_2_1 = api_version == '2.1'

    first_fetch_time = params.get('fetch_time', '3 days')
    fetch_threat_rank = int(params.get('fetch_threat_rank', 0))
    fetch_limit = int(params.get('fetch_limit', 10))

    headers = {
        'Authorization': 'ApiToken ' + token if token else 'ApiToken',
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    commands: Dict[str, Dict[str, Callable]] = {
        'common': {
            'test-module': test_module,
            'sentinelone-get-activities': get_activities_command,
            'sentinelone-get-threats': get_threats_command,
            'sentinelone-mitigate-threat': mitigate_threat_command,
            'sentinelone-get-hash': get_hash_command,
            'sentinelone-get-white-list': get_white_list_command,
            'sentinelone-create-white-list-item': create_white_item_command,
            'sentinelone-get-sites': get_sites_command,
            'sentinelone-get-site': get_site_command,
            'sentinelone-reactivate-site': reactivate_site_command,
            'sentinelone-list-agents': list_agents_command,
            'sentinelone-get-agent': get_agent_command,
            'sentinelone-get-groups': get_groups_command,
            'sentinelone-move-agent': move_agent_to_group_command,
            'sentinelone-delete-group': delete_group,
            'sentinelone-connect-agent': connect_agent_to_network,
            'sentinelone-disconnect-agent': disconnect_agent_from_network,
            'sentinelone-broadcast-message': broadcast_message,
            'sentinelone-get-events': get_events,
            'sentinelone-create-query': create_query,
            'sentinelone-get-processes': get_processes,
            'sentinelone-shutdown-agent': shutdown_agents,
            'sentinelone-uninstall-agent': uninstall_agent,
        },
        '2.0': {
            'sentinelone-mark-as-threat': mark_as_threat_command,
            'sentinelone-resolve-threat': resolve_threat_command,
            'sentinelone-agent-processes': get_agent_processes,
        },
        '2.1': {
            'sentinelone-threat-summary': get_threat_summary_command,
        },
    }

    ''' COMMANDS MANAGER / SWITCH PANEL '''
    demisto.info(f'Command being called is {demisto.command()}')
    command = demisto.command()

    try:
        client = Client(
            base_url=base_url,
            verify=use_ssl,
            headers=headers,
            proxy=proxy,
        )

        if command == 'fetch-incidents':
            fetch_incidents(client, fetch_limit, first_fetch_time, fetch_threat_rank)

        else:
            if command in commands['common']:
                return_results(commands['common'][command](client, demisto.args()))
            elif command in commands[api_version]:
                return_results(commands[api_version][command](client, demisto.args()))
            else:
                raise NotImplementedError(f'The {command} command is not supported for API version {api_version}')

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
