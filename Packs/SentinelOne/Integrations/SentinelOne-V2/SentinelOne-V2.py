import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import io
import json
import requests
import traceback
from datetime import datetime
import zipfile
from collections.abc import Callable

import urllib3

from dateutil.parser import parse

''' IMPORTS '''

# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBALS '''

IS_VERSION_2_1: bool
OS_COUNT = 4

MIRROR_DIRECTION = {
    "None": None,
    "Incoming": "In",
    "Outgoing": "Out",
    "Incoming And Outgoing": "Both",
}

INCIDENT_STATUS = {"in_progress", "resolved", "unresolved"}
SENTINELONE_INCIDENT_OUTGOING_ARGS = {
    "analystVerdict": "Analyst verdict of the incident",
    "incidentStatus": "Incident status"
}
ANALYST_VERDICT = {
    "True positive": "true_positive",
    "Suspicious": "suspicious",
    "False positive": "false_positive",
    "Undefined": "undefined"
}
THREAT_STATUS = {
    "Unresolved": "unresolved",
    "Resolved": "resolved",
    "In progress": "in_progress"
}

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


def get_agents_outputs(agents, column_to_display: list | None = None):
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
            'MachineType': agent.get('machineType'),
            'Domain': agent.get('domain'),
            'CreatedAt': agent.get('createdAt'),
            'SiteName': agent.get('siteName'),
            'Tags': agent.get('tags'),
        }

        for c in set(column_to_display or []).intersection(agent.keys()):
            entry[c] = agent[c]

        remove_nulls_from_dictionary(entry)
        yield entry


class Client(BaseClient):

    def __init__(self, base_url, verify=True, proxy=False, headers=None, block_site_ids=None):
        super().__init__(base_url, verify, proxy, headers=headers)
        self.block_site_ids = block_site_ids

    def remove_hash_from_blocklist_request(self, hash_id) -> dict:
        body = {
            "data": {
                "ids": [hash_id]
            }
        }
        response = self._http_request(method='DELETE', url_suffix='restrictions', json_data=body)
        return response.get('data') or {}

    def add_hash_to_blocklist_request(self, value, os_type, description='', source='') -> dict:
        """
        Only supports adding to the Global block list
        """
        # We do not use the assign_params function, because if these values are empty or None, we still want them
        # sent to the server

        data = {
            'value': value,
            'source': source,
            'osType': os_type,
            'type': "black_hash",
            'description': description
        }

        filt = {
            'tenant': True
        }

        body = {
            'data': data,
            'filter': filt
        }

        response = self._http_request(method='POST', url_suffix='restrictions', json_data=body)
        return response.get('data') or {}

    def add_hash_to_blocklists_request(self, value, os_type, site_ids, description='', source='') -> dict:
        """
        Supports adding hashes to multiple scoped site blocklists
        """
        demisto.debug(f'Site ids: {site_ids}')
        # We do not use the assign_params function, because if these values are empty or None, we still want them
        # sent to the server
        for site_id in site_ids:
            data = {
                'value': value,
                'source': source,
                'osType': os_type,
                'type': "black_hash",
                'description': description
            }

            filt = {
                'siteIds': [site_id],
                'tenant': True
            }

            body = {
                'data': data,
                'filter': filt
            }
            demisto.debug(f'Site id: {site_id}')
            response = self._http_request(method='POST', url_suffix='restrictions', json_data=body, ok_codes=[200])
        return response.get('data') or {}

    def get_blocklist_request(self, tenant: bool, group_ids: str = None, site_ids: str = None, account_ids: str = None,
                              skip: int = None, limit: int = None, os_type: str = None, sort_by: str = None,
                              sort_order: str = None, value_contains: str = None) -> list[dict]:
        """
        We use the `value_contains` instead of `value` parameter because in our testing
        (API 2.1) the `value` parameter is case sensitive. So if an analyst put in the hash with uppercase entries
        and it's searched using lowercase, this search will not find it
        """
        params = assign_params(
            tenant=tenant,
            groupIds=group_ids,
            siteIds=site_ids,
            accountIds=account_ids,
            skip=skip,
            limit=limit,
            osTypes=os_type,
            sortBy=sort_by,
            sortOrder=sort_order,
            value__contains=value_contains,
        )

        response = self._http_request(method='GET', url_suffix='restrictions', params=params)
        return response.get('data', [])

    def fetch_file_request(self, agent_id, file_path, password) -> dict:
        body = {
            "data": {
                "password": password,
                "files": [
                    file_path
                ]
            }
        }

        response = self._http_request(method='POST', url_suffix=f'agents/{agent_id}/actions/fetch-files', json_data=body)
        return response.get('data', {})

    def download_fetched_file_request(self, agent_id, activity_id) -> bytes:
        return self._http_request(method='GET', url_suffix=f'agents/{agent_id}/uploads/{activity_id}', resp_type='content')

    def get_activities_request(self, created_after: str = None, user_emails: str = None, group_ids=None,
                               created_until: str = None,
                               activities_ids=None, include_hidden: str = None, created_before: str = None,
                               threats_ids=None,
                               activity_types=None, user_ids=None, created_from: str = None,
                               created_between: str = None, agent_ids: str = None, sort_by: str = None, sort_order: str = None,
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
            sortBy=sort_by,
            sortOrder=sort_order,
            limit=int(limit), )
        response = self._http_request(method='GET', url_suffix='activities', params=params)
        return response.get('data', {})

    def get_threats_request(self, content_hash=None, mitigation_status=None, created_before=None, created_after=None,
                            created_until=None, created_from=None, updated_from=None, resolved='false', display_name=None,
                            query=None, threat_ids=None, limit=20, classifications=None, site_ids=None, rank=None,
                            include_resolved_param=True, incident_statuses=None):
        keys_to_ignore = ['displayName__like' if IS_VERSION_2_1 else 'displayName']

        created_before_parsed = None
        created_after_parsed = None
        created_until_parsed = None
        created_from_parsed = None
        updated_from_parsed = None

        if created_before:
            created_before_parsed = dateparser.parse(created_before, settings={'TIMEZONE': 'UTC'})
        if created_after:
            created_after_parsed = dateparser.parse(created_after, settings={'TIMEZONE': 'UTC'})
        if created_until:
            created_until_parsed = dateparser.parse(created_until, settings={'TIMEZONE': 'UTC'})
        if created_from:
            created_from_parsed = dateparser.parse(created_from, settings={'TIMEZONE': 'UTC'})
        if updated_from:
            updated_from_parsed = dateparser.parse(updated_from, settings={'TIMEZONE': 'UTC'})

        params = assign_params(
            contentHashes=argToList(content_hash),
            mitigationStatuses=argToList(mitigation_status),
            createdAt__lt=created_before_parsed,
            createdAt__gt=created_after_parsed,
            createdAt__lte=created_until_parsed,
            createdAt__gte=created_from_parsed,
            updatedAt__gte=updated_from_parsed,
            resolved=argToBoolean(resolved) if argToBoolean(include_resolved_param) else None,
            displayName__like=display_name,
            displayName=display_name,
            query=query,
            ids=threat_ids,
            limit=int(limit),
            classifications=argToList(classifications),
            siteIds=site_ids,
            rank=int(rank) if rank else None,
            keys_to_ignore=keys_to_ignore,
            incidentStatuses=incident_statuses.lower() if incident_statuses else None
        )
        response = self._http_request(method='GET', url_suffix='threats', params=params, ok_codes=[200])
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
        [DEPRECATED BY SentinelOne] Returns empty array. To get processes of an Agent, see Applications.

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

    def reactivate_site_request(self, site_id, expiration, unlimited):
        endpoint_url = f'sites/{site_id}/reactivate'
        payload = {
            "data": {
                "expiration": expiration,
                "unlimited": unlimited
            }
        }
        response = self._http_request(method='PUT', url_suffix=endpoint_url, json_data=payload)
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

    def create_status_request(self, query_id=None):
        endpoint_url = 'dv/query-status'
        params = {
            'query_id': query_id
        }

        response = self._http_request(method='GET', url_suffix=endpoint_url, params=params)
        return response.get('data', {})

    def get_events_request(self, query_id=None, limit=None, cursor=None):
        endpoint_url = 'dv/events'

        params = {
            'query_id': query_id,
            'cursor': cursor,
            'limit': limit
        }

        response = self._http_request(method='GET', url_suffix=endpoint_url, params=params)
        events = response.get('data', {})
        pagination = response.get('pagination')
        return events, pagination

    def get_processes_request(self, query_id=None, limit=None):
        endpoint_url = 'dv/events/process'
        params = {
            'query_id': query_id,
            'limit': limit
        }

        response = self._http_request(method='GET', url_suffix=endpoint_url, params=params)
        return response.get('data', {})

    def get_hash_reputation_request(self, hash_):
        """
        [DEPRECATED by S1] IN 2.1
        """
        endpoint_url = f'hashes/{hash_}/reputation'
        response = self._http_request(method='GET', url_suffix=endpoint_url)
        return response

    def get_hash_verdict_request(self, hash_):
        endpoint_url = f'hashes/{hash_}/verdict'
        response = self._http_request(method='GET', url_suffix=endpoint_url)
        return response

    def get_hash_classification_request(self, hash_):
        """
        [DEPRECATED by S1] IN BOTH 2.0 and 2.1
        """
        endpoint_url = f'hashes/{hash_}/classification'
        response = self._http_request(method='GET', url_suffix=endpoint_url)
        return response

    def get_exclusions_request(self, item_ids=None,
                               os_types=None,
                               exclusion_type: str = None,
                               limit: int = 10,
                               value_contains: str | None = None,
                               ok_codes: list = [200],
                               include_children: bool | None = None,
                               include_parents: bool | None = None):
        """
        When includeChildren and includeParents are set to True in API request-
        it will return all items in the exclusion list.
        If left blank they default to false and the API call will return a subset of the exclusion list.
        """
        endpoint_url = 'exclusions'

        params = assign_params(
            ids=item_ids,
            osTypes=os_types,
            type=exclusion_type,
            value__contains=value_contains,
            includeChildren=include_children,
            includeParents=include_parents,
            limit=limit
        )

        response = self._http_request(method='GET', url_suffix=endpoint_url, params=params, ok_codes=ok_codes)
        return response.get('data', {})

    def create_exclusion_item_request(self, exclusion_type,
                                      exclusion_value, os_type,
                                      description=None,
                                      exclusion_mode=None,
                                      path_exclusion_type=None,
                                      group_ids=None,
                                      site_ids=None):
        if group_ids != []:
            demisto.debug(f'Group IDs: {group_ids}')
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
        else:
            payload = {
                "filter": {
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

    def remove_exclusion_item_request(self, item_id) -> dict:
        body = {
            "data": {
                "ids": [item_id]
            }
        }
        response = self._http_request(method='DELETE', url_suffix='exclusions', json_data=body, ok_codes=[200])
        return response.get('data') or {}

    def update_threat_analyst_verdict_request(self, threat_ids, action):
        endpoint_url = 'threats/analyst-verdict'

        payload = {
            "data": {
                "analystVerdict": action
            },
            "filter": {
                "ids": threat_ids,
                "tenant": "true"
            }
        }
        response = self._http_request(method='POST', url_suffix=endpoint_url, json_data=payload)
        return response.get('data', {})

    def update_alert_analyst_verdict_request(self, alert_ids, action):
        endpoint_url = 'cloud-detection/alerts/analyst-verdict'

        payload = {
            "data": {
                "analystVerdict": action
            },
            "filter": {
                "ids": alert_ids,
                "tenant": "true"
            }
        }
        response = self._http_request(method='POST', url_suffix=endpoint_url, json_data=payload)
        return response.get('data', {})

    def _create_filter_dict(self, filter_dict):
        return {
            filter_key: filter_value
            for filter_key, filter_value in filter_dict.items()
            if filter_value
        }

    def create_star_rule_request(self, name, description, query, query_type, rule_severity, account_ids, group_ids,
                                 site_ids, expiration_mode, expiration_date, network_quarantine, treatAsThreat):
        endpoint_url = 'cloud-detection/rules'
        filter_dict = {
            "siteIds": site_ids,
            "groupIds": group_ids,
            "accountIds": account_ids
        }
        filter_dict = self._create_filter_dict(filter_dict)
        payload = {
            "data": {
                "expiration": expiration_date,
                "networkQuarantine": network_quarantine,
                "status": "Draft",
                "queryType": query_type,
                "expirationMode": expiration_mode,
                "severity": rule_severity,
                "treatAsThreat": treatAsThreat,
                "s1ql": query,
                "name": name,
                "description": description
            },
            "filter": {
                "tenant": "true",
                **filter_dict
            }
        }
        response = self._http_request(method='POST', url_suffix=endpoint_url, json_data=payload)
        return response.get('data', {})

    def get_star_rule_request(self, params):
        endpoint_url = 'cloud-detection/rules'
        response = self._http_request(method='GET', url_suffix=endpoint_url, params=params)
        return response.get('data', [])

    def update_star_rule_request(self, rule_id, name, description, query, query_type, rule_severity, account_ids, group_ids,
                                 site_ids, expiration_mode, expiration_date, network_quarantine,
                                 treatAsThreat):
        endpoint_url = f'cloud-detection/rules/{rule_id}'
        filter_dict = {
            "siteIds": site_ids,
            "groupIds": group_ids,
            "accountIds": account_ids
        }
        filter_dict = self._create_filter_dict(filter_dict)
        payload = {
            "data": {
                "expiration": expiration_date,
                "networkQuarantine": network_quarantine,
                "status": "Draft",
                "queryType": query_type,
                "expirationMode": expiration_mode,
                "severity": rule_severity,
                "treatAsThreat": treatAsThreat,
                "s1ql": query,
                "name": name,
                "description": description
            },
            "filter": {
                "tenant": "true",
                **filter_dict
            }
        }
        response = self._http_request(method='PUT', url_suffix=endpoint_url, json_data=payload)
        return response.get('data', {})

    def enable_star_rule_request(self, rule_ids):
        endpoint_url = 'cloud-detection/rules/enable'
        payload = {
            "filter": {
                "ids": rule_ids
            }
        }
        response = self._http_request(method='PUT', url_suffix=endpoint_url, json_data=payload)
        return response.get('data', {})

    def disable_star_rule_request(self, rule_ids):
        endpoint_url = 'cloud-detection/rules/disable'
        payload = {
            "filter": {
                "ids": rule_ids
            }
        }
        response = self._http_request(method='PUT', url_suffix=endpoint_url, json_data=payload)
        return response.get('data', {})

    def delete_star_rule_request(self, rule_ids):
        endpoint_url = 'cloud-detection/rules'
        payload = {
            "filter": {
                "ids": rule_ids
            }
        }
        response = self._http_request(method='DELETE', url_suffix=endpoint_url, json_data=payload)
        return response.get('data', {})

    def write_threat_note_request(self, threat_ids, note):
        endpoint_url = 'threats/notes'
        payload = {
            "data": {
                "text": note
            },
            "filter": {
                "ids": threat_ids
            }
        }
        response = self._http_request(method='POST', url_suffix=endpoint_url, json_data=payload)
        return response.get('data', {})

    def get_threat_notes_request(self, threatid):
        endpoint_url = f'threats/{threatid}/notes'
        response = self._http_request(method='GET', url_suffix=endpoint_url)
        return response.get('data', {})

    def create_ioc_request(self, name,
                           source,
                           ioc_type,
                           method,
                           validUntil,
                           value,
                           account_ids,
                           externalId,
                           description):
        endpoint_url = 'threat-intelligence/iocs'
        payload = {
            "filter": {
                "accountIds": account_ids
            },
            "data": [
                {
                    "source": source,
                    "type": ioc_type,
                    "method": method,
                    "validUntil": validUntil,
                    "name": name,
                    "value": value,
                    "externalId": externalId,
                    "description": description
                }
            ]
        }
        response = self._http_request(method='POST', url_suffix=endpoint_url, json_data=payload)
        return response.get('data', {})

    def delete_ioc_request(self, account_ids, uuids):
        endpoint_url = 'threat-intelligence/iocs'
        payload = {
            "filter": {
                "accountIds": account_ids,
                "uuids": uuids
            }
        }
        response = self._http_request(method='DELETE', url_suffix=endpoint_url, json_data=payload)
        return response.get('data', {})

    def get_iocs_request(self, params):
        endpoint_url = 'threat-intelligence/iocs'
        response = self._http_request(method='GET', url_suffix=endpoint_url, params=params)
        data = response.get('data')
        pagination = response.get('pagination')
        return data, pagination

    def get_accounts_request(self, account_id: str = None):
        response = self._http_request(method='GET', url_suffix=f'accounts/{account_id}' if account_id else 'accounts')
        return response.get('data', {})

    def create_power_query_request(self, limit, query, from_date, to_date):
        endpoint_url = 'dv/events/pq'
        payload = {
            "limit": limit,
            "query": query,
            "toDate": to_date,
            "fromDate": from_date
        }
        response = self._http_request(method='POST', url_suffix=endpoint_url, json_data=payload)
        return response.get('data', {})

    def ping_power_query_request(self, params):
        endpoint_url = 'dv/events/pq-ping'
        response = self._http_request(method='GET', url_suffix=endpoint_url, params=params)
        return response.get('data', [])

    def update_threat_status_request(self, threat_ids, status):
        endpoint_url = 'threats/incident'

        payload = {
            "data": {
                "incidentStatus": status
            },
            "filter": {
                "ids": threat_ids
            }
        }
        response = self._http_request(method='POST', url_suffix=endpoint_url, json_data=payload)
        return response.get('data', {})

    def update_alert_status_request(self, alert_ids, status):
        endpoint_url = 'cloud-detection/alerts/incident'

        payload = {
            "data": {
                "incidentStatus": status
            },
            "filter": {
                "ids": alert_ids
            }
        }
        response = self._http_request(method='POST', url_suffix=endpoint_url, json_data=payload)
        return response.get('data', {})

    def expire_site_request(self, site_id):
        endpoint_url = f'sites/{site_id}/expire-now'

        response = self._http_request(method='POST', url_suffix=endpoint_url)
        return response.get('data', {})

    def fetch_threat_file_request(self, password, threat_ids):
        endpoint_url = 'threats/fetch-file'

        payload = {
            "data": {
                "password": password
            },
            "filter": {
                "ids": threat_ids
            }
        }
        response = self._http_request(method='POST', url_suffix=endpoint_url, json_data=payload)
        return response.get('data', {})

    def download_url_request(self, threat_id):
        endpoint_url = f'threats/{threat_id}/timeline'
        query_params = assign_params(
            skip=0,
            limit=30,
            sortOrder="desc",
        )
        response = self._http_request(method='GET', url_suffix=endpoint_url, params=query_params,
                                      retries=3, backoff_factor=5, status_list_to_retry=[200, 202])
        urls_found = []
        data = []
        if response["data"] is not None:
            data = response["data"]
        for i in data:
            if i['data'].get('downloadUrl') is not None:
                urls_found.append(i['data'].get('downloadUrl'))
        for item in urls_found:
            if item[:8] == "/agents/":
                return item
        return "-1"

    def get_alerts_request(self, query_params):
        endpoint_url = 'cloud-detection/alerts'

        response = self._http_request(method='GET', url_suffix=endpoint_url, params=query_params)
        alerts = response.get('data', {})
        pagination = response.get('pagination')
        return alerts, pagination

    def download_threat_file_request(self, endpoint_url):
        return self._http_request(method='GET', url_suffix=endpoint_url, resp_type='content')

    def get_installed_applications_request(self, query_params):
        endpoint_url = 'agents/applications'
        response = self._http_request(method='GET', url_suffix=endpoint_url, params=query_params)
        return response.get('data', [])

    def initiate_endpoint_scan_request(self, agent_ids):
        endpoint_url = 'agents/actions/initiate-scan'
        payload = {
            "filter": {
                "ids": agent_ids
            },
            "data": {}
        }
        response = self._http_request(method='POST', url_suffix=endpoint_url, json_data=payload)
        return response.get('data', {})

    def get_s1_threats_information(self, threat_ids: str) -> dict:
        response = self._http_request(method="GET", url_suffix=f"threats?ids={threat_ids}")
        return response.get("data", [])

    def get_power_query_request(self, account_ids: list, site_ids: list, query: str, from_date: str, to_date: str, limit: Any):
        endpoint_url = 'dv/events/pq'
        payload = assign_params(
            accountIds=account_ids,
            siteIds=site_ids,
            limit=limit,
            query=query,
            toDate=to_date,
            fromDate=from_date
        )
        response = self._http_request(method='POST', url_suffix=endpoint_url, json_data=payload)
        return response.get('data', {})

    def get_ping_power_query_request(self, query_id: str):
        endpoint_url = 'dv/events/pq-ping'
        params = assign_params(
            queryId=query_id
        )
        response = self._http_request(method='GET', url_suffix=endpoint_url, params=params)
        return response.get('data', {})

    def run_remote_script_request(self,
                                  account_ids: list, script_id: str, output_destination: str,
                                  task_description: str, output_directory: str, agent_ids: list,
                                  singularity_xdr_keyword: str, singularity_xdr_url: str, api_key: str,
                                  input_params: str, password: str, script_runtime_timeout_seconds: int,
                                  requires_approval: bool) -> dict:
        endpoint_url = "remote-scripts/execute"
        payload = {
            "filter": {
                "accountIds": account_ids,
                "ids": agent_ids
            },
            "data": {
                "taskDescription": task_description,
                "outputDestination": output_destination,
                "scriptId": script_id,
                "outputDirectory": output_directory,
                "singularityxdrKeyword": singularity_xdr_keyword,
                "singularityxdrUrl": singularity_xdr_url,
                "apiKey": api_key,
                "inputParams": input_params,
                "password": password,
                "scriptRuntimeTimeoutSeconds": script_runtime_timeout_seconds,
                "requiresApproval": requires_approval
            }
        }
        payload["data"] = self.remove_empty_fields(payload.get("data", {}))
        response = self._http_request(method='POST', url_suffix=endpoint_url, json_data=payload)
        return response.get('data', {})

    def get_remote_script_status_request(self, account_ids: str = None, computer_name_contains: str = None,
                                         count_only: str = None, created_at_gt: str = None, created_at_gte: str = None,
                                         created_at_lt: str = None, created_at_lte: str = None, cursor: str = None,
                                         description_contains: str = None, detailed_status_contains: str = None,
                                         group_ids: str = None, ids: str = None, initiated_by_contains: str = None,
                                         limit: str = '50', parent_task_id: str = None, parent_task_id_in: str = None,
                                         query: str = None, site_ids: str = None, status: str = None,
                                         tenant: str = None, updated_at_gt: str = None, updated_at_gte: str = None,
                                         updated_at_lt: str = None, updated_at_lte: str = None, uuid_contains: str = None):
        params = assign_params(
            accountIds=argToList(account_ids),
            computerName__contains=computer_name_contains,
            countOnly=count_only,
            createdAt__gt=created_at_gt,
            createdAt__gte=created_at_gte,
            createdAt__lt=created_at_lt,
            createdAt__lte=created_at_lte,
            cursor=cursor,
            description__contains=description_contains,
            detailedStatus__contains=argToList(detailed_status_contains),
            groupIds=argToList(group_ids),
            ids=argToList(ids),
            initiatedBy__contains=argToList(initiated_by_contains),
            limit=int(limit),
            parentTaskId=parent_task_id,
            parentTaskId__in=argToList(parent_task_id_in),
            query=query,
            siteIds=argToList(site_ids),
            status=status,
            tenant=tenant,
            updatedAt__gt=updated_at_gt,
            updatedAt__gte=updated_at_gte,
            updatedAt__lt=updated_at_lt,
            updatedAt__lte=updated_at_lte,
            uuid__contains=uuid_contains,
        )
        response = self._http_request(method='GET', url_suffix='remote-scripts/status', params=params)
        return response.get('data', {})

    def get_remote_script_results_request(self, computer_names: list, task_ids: list):
        endpoint_url = "remote-scripts/fetch-files"
        payload = {
            "data": {
                "taskIds": task_ids,
                "computerNames": computer_names,
            }
        }
        payload["data"] = self.remove_empty_fields(payload.get("data", {}))
        response = self._http_request(method='POST', url_suffix=endpoint_url, json_data=payload)
        return response.get("data", {}).get("download_links", [])

    def remove_empty_fields(self, json_payload):
        """
        Removes empty fields from a JSON payload and returns a new JSON object with non-empty fields.

        Parameters:
        - json_payload (dict): The input JSON payload.

        Returns:
        - dict: A new JSON object containing only non-empty fields.
        """
        # Returning updated dictionary with non-empty fields
        return {key: value for key, value in json_payload.items() if str(value)}


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module(client: Client, is_fetch: bool, first_fetch: str = None):
    """
    Performs basic get request to verify connection and creds.
    """
    if is_fetch:
        first_fetch_date = dateparser.parse(first_fetch, settings={'TIMEZONE': 'UTC'})  # type: ignore
        assert first_fetch_date is not None, f'could not parse {first_fetch}'
        last_fetch = date_to_timestamp(first_fetch_date)
        last_fetch_date_string = timestamp_to_datestring(last_fetch, '%Y-%m-%dT%H:%M:%S.%fZ')
        client.get_threats_request(limit=1, created_after=last_fetch_date_string)
    else:
        client._http_request(method='GET', url_suffix='activities/types')
    return 'ok'


def get_activities_command(client: Client, args: dict) -> CommandResults:
    """
    Get a list of activities.
    """
    context_entries = []
    headers = ['ID', 'PrimaryDescription', 'Data', 'UserID', 'CreatedAt', 'ThreatID', 'UpdatedAt']
    activities = client.get_activities_request(**args)

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


def delete_group(client: Client, args: dict) -> CommandResults:
    """
    Deletes a group by ID.
    """
    group_id = args.get('group_id')
    response = client.delete_group_request(group_id)
    if response.get('success'):
        success = f'Group: {group_id} was deleted successfully'
    success = f'The deletion of group: {group_id} has failed'
    context = {'Success': success}
    return CommandResults(
        readable_output=tableToMarkdown('Sentinel One - Delete Group', context, removeNull=True,
                                        headerTransform=pascalToSpace),
        outputs_prefix='SentinelOne.DeleteGroup',
        outputs_key_field='Success',
        outputs=context,
        raw_response=response)


def move_agent_to_group_command(client: Client, args: dict) -> CommandResults:
    """
    Move agents to a new group.
    """
    group_id = args.get('group_id')
    agents_id = argToList(args.get('agents_ids', []))

    agents_groups = client.move_agent_request(group_id, agents_id)

    # Parse response into context & content entries
    agents_moved = bool(agents_groups.get("agentsMoved") and int(agents_groups.get("agentsMoved")) > 0)
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
    Get hash verdict.
    Removed hash reputation since SentinelOne has deprecated it - Breaking BC.
    Removed hash classification since SentinelOne has deprecated it - Breaking BC.
    """
    hash_ = args.get('hash')
    type_ = get_hash_type(hash_)
    if type_ == 'Unknown':
        raise DemistoException('Enter a valid hash format.')

    hash_verdict = client.get_hash_verdict_request(hash_)
    reputation = hash_verdict.get('data', {})
    contents = {
        'Verdict': reputation.get('verdict'),
        'Hash': hash_,
    }

    return CommandResults(
        readable_output=tableToMarkdown('SentinelOne - Hash Reputation Verdict\nProvides hash reputation verdict:',
                                        contents, removeNull=True),
        outputs_prefix='SentinelOne.Hash',
        outputs_key_field='Hash',
        outputs=contents,
        raw_response=hash_verdict)


def mark_as_threat_command(client: Client, args: dict) -> CommandResults:
    """
    Mark suspicious threats as threats.  Relevant for API version 2.0
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
    Apply a mitigation action to a group of threats. Relevant for API version 2.0
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


def update_threat_analyst_verdict(client: Client, args: dict) -> CommandResults:
    """
    Apply a update analyst verdict action to a group of threats. Relevant for API version 2.1
    """
    contents = []
    context_entries = []

    # Get arguments
    threat_ids = argToList(args.get('threat_ids'))
    action = args.get('verdict')

    # Make request and get raw response
    updated_threats = client.update_threat_analyst_verdict_request(threat_ids, action)

    # Parse response into context & content entries
    if updated_threats.get('affected') and int(updated_threats.get('affected')) > 0:
        updated = True
        meta = f'Total of {updated_threats.get("affected")} provided threats analyst verdict were updated successfully'
    else:
        updated = False
        meta = 'No threats were updated'
    for threat_id in threat_ids:
        contents.append({
            'Updated': updated,
            'ID': threat_id,
            'Analyst Verdict Action': action,
        })
        context_entries.append({
            'Updated': updated,
            'ID': threat_id,
            'Update': {
                'Action': action
            },
        })

    return CommandResults(
        readable_output=tableToMarkdown('Sentinel One - Update threats analyst verdict',
                                        contents, metadata=meta, removeNull=True),
        outputs_prefix='SentinelOne.Threat',
        outputs_key_field='ID',
        outputs=context_entries,
        raw_response=updated_threats)


def update_alert_analyst_verdict(client: Client, args: dict) -> CommandResults:
    """
    Apply a update analyst verdict action to a group of alerts. Relevant for API version 2.1
    """
    contents = []
    context_entries = []

    # Get arguments
    alert_ids = argToList(args.get('alert_ids'))
    action = args.get('verdict')

    # Make request and get raw response
    updated_alerts = client.update_alert_analyst_verdict_request(alert_ids, action)

    # Parse response into context & content entries
    if updated_alerts.get('affected') and int(updated_alerts.get('affected')) > 0:
        updated = True
        meta = f'Total of {updated_alerts.get("affected")} provided alerts analyst verdict were updated successfully'
    else:
        updated = False
        meta = 'No alerts were updated'
    for alert_id in alert_ids:
        contents.append({
            'Updated': updated,
            'ID': alert_id,
            'Analyst Verdict Action': action,
        })
        context_entries.append({
            'Updated': updated,
            'ID': alert_id,
            'Update': {
                'Action': action
            },
        })

    return CommandResults(
        readable_output=tableToMarkdown('Sentinel One - Update alerts analyst verdict', contents, metadata=meta, removeNull=True),
        outputs_prefix='SentinelOne.Alert',
        outputs_key_field='ID',
        outputs=context_entries,
        raw_response=updated_alerts)


def create_star_rule(client: Client, args: dict) -> CommandResults:
    """
    Creates the custom STAR rule (cloud detection rule). Relavent for API version 2.1
    """
    context = {}

    # Get arguments
    name = args.get('name')
    description = args.get('description')
    query = args.get('query')
    query_type = args.get('query_type')
    rule_severity = args.get('rule_severity')
    account_ids = argToList(args.get('account_ids'))
    group_ids = argToList(args.get('group_ids'))
    site_ids = argToList(args.get('site_ids'))
    expiration_mode = args.get('expiration_mode')
    expiration_date = args.get('expiration_date')
    network_quarantine = argToBoolean(args.get('network_quarantine'))
    treatAsThreat = args.get('treatAsThreat')
    # if the expiration_mode is Temporary then expiration_date is required
    if expiration_mode == "Temporary" and expiration_date is None:
        raise DemistoException("You must provide expiration_date argument when you selected the Temporary as expiration_mode")

    # Make request and get raw response
    rule = client.create_star_rule_request(name, description, query, query_type, rule_severity, account_ids, group_ids, site_ids,
                                           expiration_mode, expiration_date, network_quarantine, treatAsThreat)
    if rule:
        context = {
            'ID': rule.get('id'),
            'Name': rule.get('name'),
            'Status': rule.get('status'),
            'Severity': rule.get('severity'),
            'Description': rule.get('description'),
            'Network Quarantine': rule.get('networkQuarantine'),
            'Treat As Threat': rule.get('treatAsThreat'),
            'Expiration Mode': rule.get('expirationMode'),
            'Expiration Date': rule.get('expiration'),
            'Scope Hierarchy': rule.get('scope'),
            'Created At': rule.get('createdAt'),
            'Updated At': rule.get('updatedAt')
        }
    return CommandResults(
        readable_output=tableToMarkdown('Sentinel One - Create star rule', context, removeNull=True),
        outputs_prefix='SentinelOne.StarRule',
        outputs_key_field='ID',
        outputs=context,
        raw_response=rule)


def get_star_rule(client: Client, args: dict) -> CommandResults:
    """
    Get the custom STAR rule(s) (cloud detection rule). Relavent for API version 2.1
    """
    context_entries = []
    query_params = assign_params(
        status=args.get('status'),
        creator__contains=args.get('creator_contains'),
        queryType=args.get('queryType'),
        query=args.get('query'),
        description__contains=args.get('description_contains'),
        ids=args.get('ruleIds'),
        name__contains=args.get('name_contains'),
        accountIds=args.get('accountIds'),
        expirationMode=args.get('expirationMode'),
        siteIds=args.get('siteIds'),
        limit=int(args.get('limit', 1000)),
    )

    # Make request and get raw response
    rules = client.get_star_rule_request(query_params)

    if rules:
        # Parse response into context & content entries
        for rule in rules:
            context_entries.append({
                'ID': rule.get('id'),
                'Creator': rule.get('creator'),
                'Name': rule.get('name'),
                'Status': rule.get('status'),
                'Severity': rule.get('severity'),
                'Generated Alerts': rule.get('generatedAlerts'),
                'Description': rule.get('description'),
                'Status Reason': rule.get('statusReason'),
                'Expiration Mode': rule.get('expirationMode'),
                'Expiration Date': rule.get('expiration'),
                'Expired': rule.get('expired'),
            })

    return CommandResults(
        readable_output=tableToMarkdown('Sentinel One - Getting List of Star Rules', context_entries, removeNull=True,
                                        metadata='Provides summary information and details for all star rules that matched '
                                                 'your search criteria.', headerTransform=pascalToSpace),
        outputs_prefix='SentinelOne.StarRule',
        outputs_key_field='ID',
        outputs=context_entries,
        raw_response=rules)


def update_star_rule(client: Client, args: dict) -> CommandResults:
    """
    Get the custom STAR rule(s) (cloud detection rule). Relavent for API version 2.1
    """
    context = {}
    # Get arguments
    rule_id = args.get('rule_id')
    name = args.get('name')
    description = args.get('description')
    query = args.get('query')
    query_type = args.get('query_type')
    rule_severity = args.get('rule_severity')
    account_ids = argToList(args.get('account_ids'))
    group_ids = argToList(args.get('group_ids'))
    site_ids = argToList(args.get('site_ids'))
    expiration_mode = args.get('expiration_mode')
    expiration_date = args.get('expiration_date')
    network_quarantine = argToBoolean(args.get('network_quarantine'))
    treatAsThreat = args.get('treatAsThreat')
    # if the expiration_mode is Temporary then expiration_date is required
    if expiration_mode == "Temporary" and expiration_date is None:
        raise DemistoException("You must provide expiration_date argument when you selected the Temporary as expiration_mode")

    # Make request and get raw response
    rule = client.update_star_rule_request(rule_id, name, description, query, query_type, rule_severity, account_ids, group_ids,
                                           site_ids, expiration_mode, expiration_date, network_quarantine, treatAsThreat)
    if rule:
        context = {
            'ID': rule.get('id'),
            'Name': rule.get('name'),
            'Status': rule.get('status'),
            'Severity': rule.get('severity'),
            'Description': rule.get('description'),
            'Network Quarantine': rule.get('networkQuarantine'),
            'Treat As Threat': rule.get('treatAsThreat'),
            'Expiration Mode': rule.get('expirationMode'),
            'Expiration Date': rule.get('expiration'),
            'Scope Hierarchy': rule.get('scope'),
            'Created At': rule.get('createdAt'),
            'Updated At': rule.get('updatedAt')
        }
    return CommandResults(
        readable_output=tableToMarkdown('Sentinel One - Updated star rule', context, removeNull=True),
        outputs_prefix='SentinelOne.StarRule',
        outputs_key_field='ID',
        outputs=context,
        raw_response=rule)


def enable_star_rules(client: Client, args: dict) -> CommandResults:
    """
    Enables the custom STAR rule (cloud detection rule). Relavent for API version 2.1
    """
    context_entries = []

    # Get arguments
    rule_ids = argToList(args.get('rule_ids'))

    # Make request and get raw response
    enabled_rules = client.enable_star_rule_request(rule_ids)

    # Parse response into context & content entries
    if enabled_rules.get('affected') and int(enabled_rules.get('affected')) > 0:
        enabled = True
        meta = f'Total of {enabled_rules.get("affected")} provided star rules were enabled successfully'
    else:
        enabled = False
        meta = 'No star rules were enabled'
    for rule_id in rule_ids:
        context_entries.append({
            'ID': rule_id,
            'Enabled': enabled
        })
    return CommandResults(
        readable_output=tableToMarkdown('Sentinel One - Enable List of Star Rules', context_entries, removeNull=True,
                                        metadata=meta, headerTransform=pascalToSpace),
        outputs_prefix='SentinelOne.StarRule',
        outputs_key_field='ID',
        outputs=context_entries,
        raw_response=enabled_rules)


def disable_star_rules(client: Client, args: dict) -> CommandResults:
    """
    Disables the custom STAR rule (cloud detection rule). Relavent for API version 2.1
    """
    context_entries = []

    # Get arguments
    rule_ids = argToList(args.get('rule_ids'))

    # Make request and get raw response
    disabled_rules = client.disable_star_rule_request(rule_ids)

    # Parse response into context & content entries
    if disabled_rules.get('affected') and int(disabled_rules.get('affected')) > 0:
        disabled = True
        meta = f'Total of {disabled_rules.get("affected")} provided star rules were disabled successfully'
    else:
        disabled = False
        meta = 'No star rules were disabled'
    for rule_id in rule_ids:
        context_entries.append({
            'ID': rule_id,
            'Disabled': disabled
        })
    return CommandResults(
        readable_output=tableToMarkdown('Sentinel One - Disable List of Star Rules', context_entries, removeNull=True,
                                        metadata=meta, headerTransform=pascalToSpace),
        outputs_prefix='SentinelOne.StarRule',
        outputs_key_field='ID',
        outputs=context_entries,
        raw_response=disabled_rules)


def delete_star_rule(client: Client, args: dict) -> CommandResults:
    """
    Deletes the custom STAR rule (cloud detection rule). Relavent for API version 2.1
    """
    context_entries = []

    # Get arguments
    rule_ids = argToList(args.get('rule_ids'))

    # Make request and get raw response
    deleted_rules = client.delete_star_rule_request(rule_ids)

    # Parse response into context & content entries
    if deleted_rules.get('affected') and int(deleted_rules.get('affected')) > 0:
        deleted = True
        meta = f'Total of {deleted_rules.get("affected")} provided star rules were deleted successfully'
    else:
        deleted = False
        meta = 'No star rules were deleted'
    for rule_id in rule_ids:
        context_entries.append({
            'ID': rule_id,
            'Deleted': deleted
        })
    return CommandResults(
        readable_output=tableToMarkdown('Sentinel One - Deleted List of Star Rules', context_entries, removeNull=True,
                                        metadata=meta, headerTransform=pascalToSpace),
        outputs_prefix='SentinelOne.StarRule',
        outputs_key_field='ID',
        outputs=context_entries,
        raw_response=deleted_rules)


def write_threat_note(client: Client, args: dict) -> CommandResults:
    """
    Write the notes for particular threat(s). Relavent for API version 2.1
    """
    context_entries = []

    # Get arguments
    note = args.get('note')
    threat_ids = argToList(args.get('threat_ids'))

    # Make request and get raw response
    threat_notes = client.write_threat_note_request(threat_ids, note)

    # Parse response into context & content entries
    if threat_notes.get('affected') and int(threat_notes.get('affected')) > 0:
        status = "Success"
        meta = f'Total of {threat_notes.get("affected")} provided threats. THreat notes were successfully Added for them'
    else:
        status = "Failed"
        meta = 'No threat notes were Added'
    for threat_id in threat_ids:
        context_entries.append({
            'ID': threat_id,
            'Note': note,
            'Status': status
        })
    return CommandResults(
        readable_output=tableToMarkdown('Sentinel One - Write threat note', context_entries, removeNull=True,
                                        metadata=meta, headerTransform=pascalToSpace),
        outputs_prefix='SentinelOne.Threat',
        outputs_key_field='ID',
        outputs=context_entries,
        raw_response=threat_notes)


def get_threat_notes(client: Client, args: dict) -> CommandResults:
    """
    Get the note of a particular threat.
    """
    threat_id = args.get('threat_id')

    context_entries = []
    notes = client.get_threat_notes_request(threat_id)
    if notes:
        for note in notes:
            context_entries.append({
                'CreatedAt': note.get('createdAt'),
                'Creator': note.get('creator'),
                'CreatorID': note.get('creatorId'),
                'Edited': note.get('edited'),
                'ID': note.get('id'),
                'Text': note.get('text'),
                'UpdatedAt': note.get('updatedAt')
            })

    return CommandResults(
        readable_output=tableToMarkdown('Sentinel One - Get Threat Notes', context_entries,
                                        headerTransform=pascalToSpace, removeNull=True),
        outputs_prefix='SentinelOne.Notes',
        outputs_key_field='ID',
        outputs=context_entries,
        raw_response=notes)


def create_ioc(client: Client, args: dict) -> CommandResults:
    """
    Add an IoC to the Threat Intelligence database. . Relavent for API version 2.1
    """
    context = {}

    # Get arguments
    name = args.get('name')
    source = args.get('source')
    ioc_type = args.get('type')
    method = args.get('method')
    validUntil = args.get('validUntil')
    value = args.get('value')
    account_ids = argToList(args.get('account_ids'))
    # not-requied arguments
    externalId = args.get('externalId')
    description = args.get("description")

    # Make request and get raw response
    ioc = client.create_ioc_request(name, source, ioc_type, method, validUntil, value, account_ids, externalId, description)[0]

    if ioc:
        context = {
            'UUID': ioc.get('uuid'),
            'Name': ioc.get('name'),
            'Source': ioc.get('source'),
            'Type': ioc.get('type'),
            'Batch Id': ioc.get('batchId'),
            'Creator': ioc.get('creator'),
            'Scope': ioc.get('scope'),
            'Scope Id': ioc.get('scopeId')[0],
            'Valid Until': ioc.get('validUntil'),
            'Description': ioc.get('description'),
            'External Id': ioc.get('externalId'),
        }
    return CommandResults(
        readable_output=tableToMarkdown('Sentinel One - Create IOC', context, removeNull=True),
        outputs_prefix='SentinelOne.IOC',
        outputs_key_field='UUID',
        outputs=context,
        raw_response=ioc)


def delete_ioc(client: Client, args: dict) -> CommandResults:
    """
    Deletes an IoC from the Threat Intelligence database. Relavent for API version 2.1
    """
    context_entries = []

    # Get arguments
    account_ids = argToList(args.get('account_ids'))
    uuids = argToList(args.get('uuids'))

    # Make request and get raw response
    deleted_iocs = client.delete_ioc_request(account_ids, uuids)

    # Parse response into context & content entries
    if deleted_iocs.get('affected') and int(deleted_iocs.get('affected')) > 0:
        deleted = True
        meta = f'Total of {deleted_iocs.get("affected")} provided IOCs were deleted successfully'
    else:
        deleted = False
        meta = 'No IOC were deleted'

    for uuid in uuids:
        context_entries.append({
            'UUID': uuid,
            'Deleted': deleted
        })
    return CommandResults(
        readable_output=tableToMarkdown('Sentinel One - Delete List of IOCs', context_entries, removeNull=True,
                                        metadata=meta, headerTransform=pascalToSpace),
        outputs_prefix='SentinelOne.IOC',
        outputs_key_field='UUID',
        outputs=context_entries,
        raw_response=deleted_iocs)


def get_iocs(client: Client, args: dict) -> CommandResults:
    """
    Get the IOCs of a specified Account that match the filter. Relavent for API version 2.1
    """
    context_entries = []
    query_params = assign_params(
        accountIds=args.get('account_ids'),
        uploadTime__gte=args.get('upload_time_gte'),
        uploadTime__lte=args.get('upload_time_lte'),
        limit=int(args.get('limit', 1000)),
        cursor=args.get('cursor'),
        uuids=args.get('uuids'),
        type=args.get('type'),
        batchId=args.get('batch_id'),
        source=args.get('source'),
        value=args.get('value'),
        externalId=args.get('external_id'),
        name__contains=args.get('name_contains'),
        creator__contains=args.get('creator_contains'),
        description__contains=args.get('description_contains'),
        category__in=args.get('category_in'),
        updatedAt__gte=args.get('updated_at_gte'),
        updatedAt__lte=args.get('updated_at_lte'),
        creationTime__gte=args.get('creation_time_gte'),
        creationTime__lte=args.get('creation_time_lte'),
    )

    # Make request and get raw response
    iocs, pagination = client.get_iocs_request(query_params)

    if pagination['nextCursor'] is not None:
        demisto.results("Use the below cursor value to get the next page iocs \n {}".format(pagination['nextCursor']))

    if iocs:
        # Parse response into context & content entries
        for ioc in iocs:
            context_entries.append({
                'UUID': ioc.get('uuid'),
                'Creator': ioc.get('creator'),
                'Name': ioc.get('name'),
                'Value': ioc.get('value'),
                'Description': ioc.get('description'),
                'Type': ioc.get('type'),
                'External Id': ioc.get('externalId'),
                'Source': ioc.get('source'),
                'Upload Time': ioc.get('uploadTime'),
                'Valid Until': ioc.get('validUntil')
            })

    return CommandResults(
        readable_output=tableToMarkdown('Sentinel One - Getting List of IOCs', context_entries, removeNull=True,
                                        metadata='Provides summary information and details for all iocs that matched '
                                                 'your search criteria.', headerTransform=pascalToSpace),
        outputs_prefix='SentinelOne.IOC',
        outputs_key_field='UUID',
        outputs=context_entries,
        raw_response=iocs)


def create_power_query(client: Client, args: dict) -> CommandResults:
    """
    Create the power query and get the events or get the query ID. Relavent for API version 2.1
    """
    context_entries = []

    # Get arguments
    limit = int(args.get('limit', 1000))
    query = args.get('query')
    from_date = args.get('from_date')
    to_date = args.get('to_date')

    # Make request and get raw response
    response = client.create_power_query_request(limit, query, from_date, to_date)

    if response['status'] == 'RUNNING':
        context_entries.append({
            'queryId': response['queryId']
        })
        meta = "Ping a Deep Visibility Power Query using the queryId"

    elif response['status'] == 'FINISHED':
        for row in response['data']:
            temp = {}
            for i in range(len(row)):
                temp.update({response['columns'][i]['name']: row[i]})
            context_entries.append(temp)

        meta = 'Provides summary information and details aboput the power query and its id \n your search criteria.'
    else:
        meta = ""
        demisto.debug(f"{response['status']=} -> {meta=}")

    return CommandResults(
        readable_output=tableToMarkdown('Sentinel One - Create a Power Query and Get QueryId', context_entries, removeNull=True,
                                        metadata=meta, headerTransform=pascalToSpace),
        outputs_prefix='SentinelOne.PowerQuery',
        outputs=context_entries,
        raw_response=response)


def ping_power_query(client: Client, args: dict) -> CommandResults:
    """
    Create the power query and get the events or get the query ID. Relavent for API version 2.1
    """
    context_entries = []
    query_params = assign_params(
        queryId=args.get('queryId')
    )

    response = client.ping_power_query_request(query_params)
    if response.get('data'):
        for row in response['data']:
            temp = {}
            for i in range(len(row)):
                temp.update({response['columns'][i]['name']: row[i]})
            context_entries.append(temp)
        return CommandResults(
            readable_output=tableToMarkdown('Sentinel One - Ping the Power Query', context_entries, removeNull=True,
                                            metadata='Provides summary information and details aboput the power query and its id '
                                                     ' your search criteria.', headerTransform=pascalToSpace),
            outputs_prefix='SentinelOne.PowerQuery',
            outputs=context_entries,
            raw_response=response)
    else:
        return CommandResults(readable_output='There is no data returned by the id that you provided,'
                                              ' please re-check the id to ping')


def update_threat_status(client: Client, args: dict) -> CommandResults:
    """
    Apply a update status action to a group of threats. Relevant for API version 2.1
    """
    context_entries = []

    # Get arguments
    threat_ids = argToList(args.get('threat_ids'))
    status = args.get('status')
    affected = 0
    meta = 'No threats were updated'

    for threat_id in threat_ids:
        # Make request and get raw response
        updated_threats = client.update_threat_status_request(threat_id, status)
        # Parse response into context & content entries
        if updated_threats.get('affected') and int(updated_threats.get('affected')) > 0:
            updated = True
            affected += 1
        else:
            updated = False
        context_entries.append({
            'Updated': updated,
            'ID': threat_id,
            'Status': status,
        })

    if affected > 0:
        meta = f'Total of {affected} provided threats status were updated successfully'

    return CommandResults(
        readable_output=tableToMarkdown('Sentinel One - Update threats status', context_entries, metadata=meta, removeNull=True),
        outputs_prefix='SentinelOne.Threat',
        outputs_key_field='ID',
        outputs=context_entries,
        raw_response=updated_threats)


def update_alert_status(client: Client, args: dict) -> CommandResults:
    """
    Updates the status for group of Alerts. Relevant for API version 2.1
    """
    context_entries = []

    # Get arguments
    alert_ids = argToList(args.get('alert_ids'))
    status = args.get('status')
    affected = 0
    meta = 'No alerts were updated'

    for alert_id in alert_ids:
        # Make request and get raw response
        updated_alerts = client.update_alert_status_request(alert_id, status)
        # Parse response into content entries
        if updated_alerts.get('affected') and int(updated_alerts.get('affected')) > 0:
            updated = True
            affected += 1
        else:
            updated = False
        context_entries.append({
            'Updated': updated,
            'ID': alert_id,
            'Status': status,
        })

    if affected > 0:
        meta = f'Total of {affected} provided alerts status were updated successfully'

    return CommandResults(
        readable_output=tableToMarkdown('Sentinel One - Update alerts status', context_entries, metadata=meta, removeNull=True),
        outputs_prefix='SentinelOne.Alert',
        outputs_key_field='ID',
        outputs=context_entries,
        raw_response=updated_alerts)


def expire_site(client: Client, args: dict) -> CommandResults:
    """
    Expires the site from the server. Relavent to both API Versions
    """
    context_entries = {}

    # Get arguments
    site_id = args.get("site_id")

    # Make request and get raw response
    Expired_site = client.expire_site_request(site_id)

    if Expired_site:
        context_entries = {
            "ID": Expired_site.get('id'),
            "Name": Expired_site.get('name'),
            "State": Expired_site.get('state'),
            "SKU": Expired_site.get('sku'),
            "Site Type": Expired_site.get('siteType'),
            "Suite": Expired_site.get('suite'),
            "Total Licences": Expired_site.get('totalLicenses'),
            "Account ID": Expired_site.get('accountId'),
            "Creator": Expired_site.get('creator'),
            "Creator ID": Expired_site.get('creatorId'),
            "Description": Expired_site.get('description'),
            "Expiration": Expired_site.get('expiration'),
        }
    return CommandResults(
        readable_output=tableToMarkdown('Sentinel One - Expire Site', context_entries, removeNull=True),
        outputs_prefix='SentinelOne.Site',
        outputs_key_field='ID',
        outputs=context_entries,
        raw_response=Expired_site)


def fetch_threat_file(client: Client, args: dict) -> list[CommandResults]:
    """
    Fetches the threat file. Relevent to both API Versions
    """
    context_entries = []

    # Get Arguments
    threat_ids = argToList(args.get('threat_id'))
    password = args.get('password')

    downloaded_files = client.fetch_threat_file_request(password, threat_ids)

    if downloaded_files.get('affected') and int(downloaded_files.get('affected')) > 0:
        downloadable = True
        meta = f'Total of {downloaded_files.get("affected")} provided threats were downloaded successfully'
    else:
        downloadable = False
        meta = 'No threats were downloaded'
    files = []
    for threat_id in threat_ids:
        zipped_file = "Session timeout, unable to download the Zip file."
        threat_file_download_endpoint = client.download_url_request(threat_id)
        if threat_file_download_endpoint != "-1":
            zip_file_data = client.download_threat_file_request(threat_file_download_endpoint)
            files.append(fileResult(filename=f"{threat_id}.zip", data=zip_file_data, file_type=EntryType.ENTRY_INFO_FILE))
            zipped_file = fileResult(filename=f"{threat_id}.zip", data=zip_file_data, file_type=EntryType.ENTRY_INFO_FILE)
        context_entries.append({
            'Downloadable': downloadable,
            'ID': threat_id,
            'ZippedFile': zipped_file
        })
    return [CommandResults(
        readable_output=tableToMarkdown('Sentinel One - Fetch threat file', context_entries, metadata=meta, removeNull=False),
        outputs_prefix='SentinelOne.Threat',
        outputs_key_field='ID',
        outputs=context_entries,
        raw_response=downloaded_files),
        *files
    ]


def get_alerts(client: Client, args: dict) -> CommandResults:
    """
    Get the Alerts from server. Relevant to API Version 2.1
    """
    created_until = None
    created_from = None

    context_entries = []
    headers = ['AlertId', 'EventType', 'RuleName', 'EndpointName', 'SrcProcName', 'SrcProcPath', 'SrcProcCommandline',
               'SrcProcSHA1', 'SrcProcStartTime', 'SrcProcStorylineId', 'SrcParentProcName',
               'AlertCreatedAt', 'AgentId', 'AgentUUID', 'RuleName']

    if args.get('created_until'):
        created_until = dateparser.parse(str(args.get('created_until')), settings={'TIMEZONE': 'UTC'})

    if args.get('created_from'):
        created_from = dateparser.parse(str(args.get('created_from')), settings={'TIMEZONE': 'UTC'})

    query_params = assign_params(
        ruleName__contains=args.get('ruleName'),
        incidentStatus=args.get('incidentStatus'),
        analystVerdict=args.get('analystVerdict'),
        createdAt__lte=created_until,
        createdAt__gte=created_from,
        ids=argToList(args.get('alert_ids')),
        limit=int(args.get('limit', 1000)),
        siteIds=args.get('site_ids'),
        cursor=args.get('cursor'),
    )

    alerts, pagination = client.get_alerts_request(query_params)

    if pagination['nextCursor'] is not None:
        demisto.results("Use the below cursor value to get the next page alerts \n {}".format(pagination['nextCursor']))

    if alerts:
        for alert in alerts:
            alert_info = alert.get('alertInfo')
            rule_info = alert.get('ruleInfo')
            source_process_info = alert.get('sourceProcessInfo')
            source_parent_process_info = alert.get('sourceParentProcessInfo')
            agent_realtime_info = alert.get('agentRealtimeInfo')
            agent_detection_info = alert.get('agentDetectionInfo')
            context_entries.append({
                'EventType': alert_info.get('eventType'),
                'RuleName': rule_info.get('name'),
                'SrcProcUser': source_process_info.get('user'),
                'SrcProcName': source_process_info.get('name'),
                'SrcProcPath': source_process_info.get('filePath'),
                'SrcProcCommandline': source_process_info.get('commandline'),
                'SrcProcSHA1': source_process_info.get('fileHashSha1'),
                'SrcProcStartTime': source_process_info.get('pidStarttime'),
                'SrcProcStorylineId': source_process_info.get('storyline'),
                'SrcParentProcName': source_parent_process_info.get('name'),
                'SrcParentProcPath': source_parent_process_info.get('filePath'),
                'SrcParentProcCommandline': source_parent_process_info.get('commandline'),
                'SrcParentProcStartTime': source_parent_process_info.get('pidStarttime'),
                'SrcParentProcUser': source_parent_process_info.get('user'),
                'SrcParentProcSHA1': source_parent_process_info.get('fileHashSha1'),
                'SrcProcSignerIdentity': source_process_info.get('fileSignerIdentity'),
                'SrcParentProcSignerIdentity': source_parent_process_info.get('fileSignerIdentity'),
                'AlertCreatedAt': alert_info.get('createdAt'),
                'AlertId': alert_info.get('alertId'),
                'AnalystVerdict': alert_info.get('analystVerdict'),
                'IncidentStatus': alert_info.get('incidentStatus'),
                'EndpointName': agent_realtime_info.get('name'),
                'AgentId': agent_realtime_info.get('id'),
                'AgentUUID': agent_detection_info.get('uuid'),
                'dvEventId': alert_info.get('dvEventId'),
                'AgentOS': agent_realtime_info.get('os'),
                'AgentVersion': agent_detection_info.get('version'),
                'SiteId': agent_detection_info.get('siteId'),
                'RuleId': rule_info.get('id'),
            })

    return CommandResults(
        readable_output=tableToMarkdown('Sentinel One - Getting Alert List', context_entries, removeNull=True,
                                        metadata='Provides summary information and details for all the alerts'
                                                 ' that matched your search criteria.',
                                        headers=headers, headerTransform=pascalToSpace),
        outputs_prefix='SentinelOne.Alert',
        outputs_key_field='AlertId',
        outputs=context_entries,
        raw_response=alerts)


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


def get_installed_applications(client: Client, args: dict) -> CommandResults:
    """
    Get installed applications from agent.
    """
    context_entries = []
    headers = ['Name', 'Publisher', 'Size', 'Version', 'InstalledOn']
    query_params = assign_params(
        ids=argToList(args.get('agent_ids'))
    )

    applications = client.get_installed_applications_request(query_params)
    if applications:
        for app in applications:
            context_entries.append({
                "Name": app.get("name"),
                "Publisher": app.get("publisher"),
                "Size": app.get("size"),
                "Version": app.get("version"),
                "InstalledOn": app.get("installedDate")
            })
    return CommandResults(
        readable_output=tableToMarkdown('Sentinel One - Getting Installed Applications', context_entries, removeNull=True,
                                        metadata='Provides summary information and details for all installed applications'
                                                 ' that matched your search criteria.',
                                        headers=headers, headerTransform=pascalToSpace),
        outputs_prefix='SentinelOne.Application',
        outputs_key_field='Name',
        outputs=context_entries,
        raw_response=applications)


def initiate_endpoint_scan(client: Client, args: dict) -> CommandResults:
    """
    Initiate the endpoint virus scan on provided agent IDs
    """
    context_entries = []

    agent_ids = argToList(args.get('agent_ids'))
    initiated = client.initiate_endpoint_scan_request(agent_ids)
    if initiated.get('affected') and int(initiated.get('affected')) > 0:
        updated = True
        meta = f'Total of {initiated.get("affected")} provided agents were successfully initiated the scan'
    else:
        updated = False
        meta = 'No agents scan was initiated'
    for agent_id in agent_ids:
        context_entries.append({
            "Agent ID": agent_id,
            "Initiated": updated
        })
    return CommandResults(
        readable_output=tableToMarkdown('Sentinel One - Initiate endpoint scan on provided Agent ID',
                                        context_entries, metadata=meta, removeNull=True),
        outputs_prefix='SentinelOne.Agent',
        outputs_key_field='Agent ID',
        outputs=context_entries,
        raw_response=initiated)


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
    should_include_parent = argToBoolean(args.get('include_parent', False))
    should_include_children = argToBoolean(args.get('include_children', False))

    # Make request and get raw response
    exclusion_items = client.get_exclusions_request(item_ids, os_types, exclusion_type, limit,
                                                    include_parents=should_include_parent,
                                                    include_children=should_include_children)

    # Parse response into context & content entries
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


def get_item_ids_from_whitelist(client: Client, item: str, exclusion_type: str, os_type: str = None) -> list[str | None]:
    """
    Return the IDs of the hash from the white. Helper function for remove_item_from_whitelist
    Limit is set to OS_COUNT here where is OS_COUNT is set to the number of Operating Systems a hash can be blocked.
    Currently there are only three platforms it is acceptable for a hash to be blocked 3 times.
    If more results are returned, an error will be thrown.
    A hash can occur more than once if it is blocked on more than one platform (Windwos, MacOS, Linux)
    """
    item_ids: list = []
    limit = OS_COUNT + 1
    white_list = client.get_exclusions_request(item_ids, os_type, exclusion_type, limit, item, include_children=True,
                                               include_parents=True)
    demisto.debug(f'white_list: {white_list}')

    ret = []

    # Validation check first
    if len(white_list) > limit:
        raise DemistoException("Received more than 3 results when querying by hash. This condition should not occur")

    for entry in white_list:
        # Second validation. E.g. if user passed in a hash value shorter than SHA1 length
        if (value := entry.get('value')) and value.lower() == item.lower():
            ret.append(entry.get('id'))

    return ret


def remove_item_from_whitelist(client: Client, args: dict) -> CommandResults:
    """
    Remove a hash from the blocklist (SentinelOne Term: Blacklist)
    """
    item = args.get('item')
    if not item:
        raise DemistoException("You must specify a valid item to be removed")
    os_type = args.get('os_type', None)
    exclusion_type = args.get('exclusion_type', None)

    item_ids = get_item_ids_from_whitelist(client, item, exclusion_type, os_type)

    if not item_ids:
        status = {
            'item': item,
            'status': "Not on whitelist"
        }
        result = None
    else:
        result = []
        numRemoved = 0
        for item_id in item_ids:
            numRemoved += 1
            result.append(client.remove_exclusion_item_request(item_id=item_id))

        status = {
            'item': item,
            'status': f"Removed {numRemoved} entries from whitelist"
        }

    return CommandResults(
        readable_output=f"{item}: {status['status']}.",
        outputs_prefix='SentinelOne.RemoveItemFromWhitelist',
        outputs_key_field='Value',
        outputs=status,
        raw_response=result)


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

    if not site_ids:
        raise DemistoException("You must provide site_ids.")

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
    unlimited = args.get('unlimited')
    expiration = args.get('expiration')

    if unlimited is not None:
        unlimited = argToBoolean(unlimited)

    # if unlimited and expiration are not passed then error out
    if unlimited is None and expiration is None:
        raise DemistoException("You must provide unlimited argument or expiration argument as required.")

    # if unlimited is not passed but expiration is then set unlimited to False
    if unlimited is None:
        unlimited = False

    # if unlimited is False and no expiration then error out.
    if unlimited is False and expiration is None:
        raise DemistoException("You must provide expiration when unlimited is false")

    # Make request and get raw response
    site = client.reactivate_site_request(site_id, expiration, unlimited)

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
    query_params = {}
    if args.get('params'):
        param_list = argToList(args.get('params', ''))
        for field_value in param_list:
            f = field_value.split('=')[0]
            v = field_value.split('=')[1]
        query_params.update({f: v})
    query_params.update(assign_params(
        active_threats=args.get('min_active_threats'),
        computerName__like=args.get('computer_name'),
        scan_status=args.get('scan_status'),
        osTypes=args.get('os_type'),
        created_at=args.get('created_at'),
        limit=int(args.get('limit', 10)),
    ))

    # Make request and get raw response
    agents = client.list_agents_request(query_params)
    column_to_display = argToList(args.get("columns"))

    # Parse response into context & content entries
    context_entries = list(get_agents_outputs(agents, column_to_display)) if agents else None

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


def get_agent_mac_command(client: Client, args: dict) -> CommandResults:
    """
        Get single agent mac details via ID
    """
    # Set req list
    mac_list = []

    # Get arguments
    agent_ids = argToList(args.get('agent_id'))

    # Make request and get raw response
    agents = client.get_agent_request(agent_ids)

    if agents:
        for agent in agents:
            hostname = agent.get('computerName')
            for interface in agent.get('networkInterfaces'):
                int_dict = {}
                int_dict['hostname'] = hostname
                int_dict['int_name'] = interface.get('name')
                int_dict['agent_id'] = agent.get('id')
                int_dict['ip'] = interface.get('inet')
                int_dict['mac'] = interface.get('physical')

                mac_list.append(int_dict)

    return CommandResults(
        outputs_prefix='SentinelOne.MAC',
        outputs=mac_list,
        readable_output=tableToMarkdown('SentinelOne MAC Address Results', mac_list),
        raw_response=agents
    )


def connect_agent_to_network(client: Client, args: dict) -> Union[CommandResults, str]:
    """
    Sends a "connect to network" command to all agents matching the input filter.
    """
    agent_ids = argToList(args.get('agent_id'))

    # Make request and get raw response
    raw_response = client.connect_to_network_request(agent_ids)
    agents_affected = raw_response.get('affected', 0)

    # Parse response into context & content entries
    agents = client.list_agents_request({'ids': ','.join(agent_ids)})
    contents = [{
        'NetworkStatus': agent.get('networkStatus'),
        'ID': agent.get('id')
    } for agent in agents]
    contents.append({'AgentsAffected': agents_affected})

    return CommandResults(
        readable_output=f'{agents_affected} agent(s) successfully connected to the network.',
        outputs_prefix='SentinelOne.Agent',
        outputs_key_field='ID',
        outputs=contents,
        raw_response=raw_response)


def disconnect_agent_from_network(client: Client, args: dict) -> Union[CommandResults, str]:
    """
    Sends a "disconnect from network" command to all agents matching the input filter.
    """
    agent_ids = argToList(args.get('agent_id'))

    # Make request and get raw response
    raw_response = client.disconnect_from_network_request(agent_ids)
    agents_affected = raw_response.get('affected', 0)

    agents = client.list_agents_request({'ids': ','.join(agent_ids)})
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


def broadcast_message(client: Client, args: dict) -> CommandResults:
    """
    Broadcasts a message to all agents matching the input filter.
    """
    context = {}
    message = args.get('message')
    filters = assign_params(
        isActive=argToBoolean(args.get('active_agent', 'false')),
        groupIds=argToList(args.get('group_id')),
        ids=argToList(args.get('agent_id')),
        domains=argToList(args.get('domain')),
    )

    response = client.broadcast_message_request(message, filters)

    agents_affected = response.get('affected', 0)
    context = {
        "Affected": agents_affected
    }
    if agents_affected > 0:
        meta = 'The message was successfully delivered to the agent(s)'
    else:
        meta = 'No messages were sent. Verify that the inputs are correct.'
    return CommandResults(
        readable_output=tableToMarkdown('Sentinel One - Broadcast Message', context, metadata=meta, removeNull=True),
        outputs_prefix='SentinelOne.BroadcastMessage',
        outputs_key_field='Affected',
        outputs=context,
        raw_response=response)


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


def uninstall_agent(client: Client, args: dict) -> CommandResults:
    """
    Sends an uninstall command to all agents matching the input filter.
    """
    context = {}
    query = args.get('query', '')

    agent_id = argToList(args.get('agent_id'))
    group_id = argToList(args.get('group_id'))
    if not (agent_id or group_id):
        raise DemistoException('Expecting at least one of the following arguments to filter by: agent_id, group_id.')

    response = client.uninstall_agent_request(query, agent_id, group_id)
    affected_agents = response.get('affected', 0)
    context = {
        "Affected": affected_agents
    }
    meta = f"Uninstall was sent to {affected_agents} agent(s)." if affected_agents > 0 else "No agents were affected."

    return CommandResults(
        readable_output=tableToMarkdown('Sentinel One - Uninstall Agent', context, metadata=meta, removeNull=True),
        outputs_prefix='SentinelOne.uninstall',
        outputs_key_field='Affected',
        outputs=context,
        raw_response=response)


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
        raw_response=query_id
    )


def get_dv_query_status(client: Client, args: dict) -> CommandResults:
    query_id = args.get('query_id')
    status = client.create_status_request(query_id)

    status['QueryID'] = query_id

    return CommandResults(
        readable_output=tableToMarkdown('SentinelOne Query Status', [status]),
        outputs_prefix='SentinelOne.Query.Status',
        outputs_key_field='QueryID',
        outputs=status,
        raw_response=status
    )


def get_events(client: Client, args: dict) -> Union[CommandResults, str]:
    """
    Get all Deep Visibility events from query
    """
    contents = []
    event_standards = []
    query_id = args.get('query_id')
    limit = int(args.get('limit', 50))
    cursor = args.get('cursor', None)
    column_to_display = argToList(args.get("columns"))

    events, pagination = client.get_events_request(query_id, limit, cursor)
    context = {}
    if pagination and pagination.get('nextCursor') is not None:
        demisto.results("Use the below cursor value to get the next page events \n {}".format(pagination['nextCursor']))
        context.update({'SentinelOne.Cursor.Event': pagination['nextCursor']})
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
            'FilePath': event.get('fileFullName'),
            'IPAddress': event.get('agentIp'),
            'MD5': event.get('md5'),
            'SHA256': event.get('sha256'),
            'SourceIP': event.get('srcIp'),
            'SourcePort': event.get('srcPort'),
            'DestinationIP': event.get('dstIp'),
            'DestinationPort': event.get('dstPort'),
            'SourceProcessUser': event.get('srcProcUser'),
            'SourceProcessCommandLine': event.get('srcProcCmdLine'),
            'DNSRequest': event.get('dnsRequest'),
            'FileFullName': event.get('fileFullName'),
            'EventTime': event.get('eventTime'),
            'EventID': event.get('id'),
        })

        for c in set(column_to_display).intersection(event.keys()):
            contents[-1][c] = event[c]

        event_standards.append({
            'Type': event.get('eventType'),
            'Name': event.get('processName'),
            'ID': event.get('pid'),
        })

    # using the CommandResults.to_context in order to get the correct outputs key
    context.update(CommandResults(
        outputs_prefix='SentinelOne.Event',
        outputs_key_field=['ProcessID', 'EventID'],
        outputs=contents).to_context().get('EntryContext', {}))

    context.update({'Event(val.ID && val.ID === obj.ID)': event_standards})

    return CommandResults(
        readable_output=tableToMarkdown('SentinelOne Events', contents, removeNull=True),
        outputs=context,
        raw_response=events)


def get_processes(client: Client, args: dict) -> CommandResults:
    """
    Get Deep Visibility events from query by event type - process
    """
    contents = []

    query_id = args.get('query_id')
    limit = int(args.get('limit', 50))

    processes = client.get_processes_request(query_id, limit)
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


# Blocklist commands


def add_hash_to_blocklist(client: Client, args: dict) -> CommandResults:
    """
    Add a hash to the blocklist (SentinelOne Term: Blacklist)
    """
    sha1 = args.get('sha1')
    if not sha1:
        raise DemistoException("You must specify a valid SHA1 hash")

    try:
        if sites := client.block_site_ids:
            demisto.debug(f'Adding sha1 {sha1} to sites {sites}')
            result = client.add_hash_to_blocklists_request(value=sha1, description=args.get('description'),
                                                           os_type=args.get('os_type'), site_ids=sites, source=args.get('source'))
            status = {
                'hash': sha1,
                'status': "Added to scoped blocklist"
            }
        else:
            result = client.add_hash_to_blocklist_request(value=sha1, description=args.get('description'),
                                                          os_type=args.get('os_type'), source=args.get('source'))
            status = {
                'hash': sha1,
                'status': "Added to global blocklist"
            }
    except DemistoException as e:
        # When adding a hash to the blocklist that is already on the blocklist,
        # SentinelOne returns an error code, resuliting in the request raising an exception
        #
        # This section examines the error code returned. If the error is due to the hash
        # already being on the list, it is ignored and the returned status is updated
        js = e.res.json()
        errors = js.get("errors")
        if (errors and len(errors) == 1
            and (error := errors[0]).get('code') == 4000030
                and error.get('title') == "Already Exists Error"):
            status = {
                'hash': sha1,
                'status': "Already on blocklist"
            }
            result = js
        else:
            raise e

    return CommandResults(
        readable_output=f"{sha1}: {status['status']}.",
        outputs_prefix='SentinelOne.AddHashToBlocklist',
        outputs_key_field='Value',
        # `status` instead of `result` because we modify status based on the error/exception comments above
        outputs=status,
        raw_response=result)


def get_hash_ids_from_blocklist(client: Client, sha1: str, os_type: str = None) -> list[str | None]:
    """
    Return the IDs of the hash from the blocklist. Helper function for remove_hash_from_blocklist

    A hash can occur more than once if it is blocked on more than one platform (Windwos, MacOS, Linux)
    """
    ret: list = []
    if client.block_site_ids:
        PAGE_SIZE = 20
        site_ids = ','.join(client.block_site_ids)
        block_list = client.get_blocklist_request(tenant=False, skip=0, limit=PAGE_SIZE, os_type=os_type, site_ids=site_ids,
                                                  sort_by="updatedAt", sort_order="asc", value_contains=sha1)
    else:
        PAGE_SIZE = 4
        block_list = client.get_blocklist_request(tenant=True, skip=0, limit=PAGE_SIZE, os_type=os_type,
                                                  sort_by="updatedAt", sort_order="asc", value_contains=sha1)

        # Validation check first
        if len(block_list) > 3:
            raise DemistoException("Received more than 3 results when querying by hash. This condition should not occur")

    for block_entry in block_list:
        # Second validation. E.g. if user passed in a hash value shorter than SHA1 length
        if (value := block_entry.get('value')) and value.lower() == sha1.lower():
            ret.append(block_entry.get('id'))

    return ret


def remove_hash_from_blocklist(client: Client, args: dict) -> CommandResults:
    """
    Remove a hash from the blocklist (SentinelOne Term: Blacklist)
    """
    sha1 = args.get('sha1')
    if not sha1:
        raise DemistoException("You must specify a valid Sha1 hash")
    os_type = args.get('os_type', None)
    hash_ids = get_hash_ids_from_blocklist(client, sha1, os_type)

    if not hash_ids:
        status = {
            'hash': sha1,
            'status': "Not on blocklist"
        }
        result = None
    else:
        result = []
        numRemoved = 0
        for hash_id in hash_ids:
            numRemoved += 1
            result.append(client.remove_hash_from_blocklist_request(hash_id=hash_id))

        status = {
            'hash': sha1,
            'status': f"Removed {numRemoved} entries from blocklist"
        }

    return CommandResults(
        readable_output=f"{sha1}: {status['status']}.",
        outputs_prefix='SentinelOne.RemoveHashFromBlocklist',
        outputs_key_field='Value',
        outputs=status,
        raw_response=result)


def get_blocklist(client: Client, args: dict) -> CommandResults:
    """
    Retrieve the blocklist (SentinelOne Term: Blacklist)
    """
    tenant_str = args.get('global', 'false')
    tenant = tenant_str.lower() == 'true'

    sort_by = "updatedAt"
    sort_order = "desc"

    offset = arg_to_number(int(args.get('offset', "0")))
    limit = arg_to_number(int(args.get('limit', "100")))
    group_ids = args.get('group_ids', None)
    site_ids = args.get('site_ids', None)
    account_ids = args.get('account_ids', None)
    value = args.get('hash', None)

    contents = []

    block_list = client.get_blocklist_request(tenant=tenant, group_ids=group_ids, site_ids=site_ids,
                                              account_ids=account_ids, skip=offset, limit=limit,
                                              sort_by=sort_by, sort_order=sort_order, value_contains=value)
    for block in block_list:
        contents.append({
            'CreatedAt': block.get('createdAt'),
            'Description': block.get('description'),
            'ID': block.get('id'),
            'OSType': block.get('osType'),
            'ScopeName': block.get('scopeName'),
            'ScopePath': block.get('scopePath'),
            'Source': block.get('source'),
            'Type': block.get('type'),
            'UpdatedAt': block.get('updatedAt'),
            'UserId': block.get('userId'),
            'Value': block.get('value')
        })

    return CommandResults(
        readable_output=tableToMarkdown('SentinelOne Blocklist', contents, removeNull=True),
        outputs_prefix='SentinelOne.Blocklist',
        outputs_key_field='Value',
        outputs=contents,
        raw_response=block_list)


# File Fetch Commands


def fetch_file(client: Client, args: dict) -> str:
    """
    Initiate a file fetch request on an agent
    """
    agent_id = args.get('agent_id')
    file_path = args.get('file_path')
    password = args.get('password')

    client.fetch_file_request(agent_id, file_path, password)
    return f"Intiated fetch-file action for {file_path} on Agent {agent_id}"


def extract_sentinelone_zip_file(zip_file_data: bytes, password: str) -> tuple[str, bytes]:
    """
    Helper funciton for `download_fetched_file`
    """
    file_archive = io.BytesIO(zip_file_data)
    zip_file = zipfile.ZipFile(file_archive)

    # Each .zip file returned by SentinelOne has a manifest.json file. Then it
    # Re-creates the folder paths inside the zip, and stores the collected file
    # (e.g. C/path/to/file.txt inside the zip)
    #
    # We assume only one file was collected, since that's how our integration commands are
    # implemented

    file_names = [name for name in zip_file.namelist() if name != "manifest.json"]
    if len(file_names) < 1:
        raise DemistoException("No file found in upload from agent. Perhaps the path submitted is wrong?")

    file_name = file_names[0]
    file_data = zip_file.read(file_name, password.encode('utf-8'))
    return file_name, file_data


def download_fetched_file(client: Client, args: dict) -> list[CommandResults]:
    """
    Download a file that has been requested by `fetch-file`
    """
    agent_id = args.get('agent_id')
    activity_id = args.get('activity_id')
    password = args.get('password')
    assert isinstance(password, str)

    zip_file_data = client.download_fetched_file_request(agent_id, activity_id)
    path, file_data = extract_sentinelone_zip_file(zip_file_data, password)
    return [CommandResults(readable_output=f"Successfully downloaded file `{path}`",
                           outputs_prefix='SentinelOne.Download',
                           outputs_key_field='Path',
                           outputs={'Path': path}),
            fileResult(f"{path.replace('/', '_')}", file_data)]


def get_accounts(client: Client, args: dict) -> CommandResults:
    """
    Get accounts info (ID, etc).
    """
    account_id = args.get('account_id', None)

    context_entries = []
    # Make request and get raw response
    accounts = client.get_accounts_request(account_id)

    if accounts:
        for account in accounts:
            context_entries.append({
                'AccountType': account.get('accountType'),
                'ActiveAgents': account.get('activeAgents'),
                'NumberOfSites': account.get('numberOfSites'),
                'State': account.get('state'),
                'CreatedAt': account.get('createdAt'),
                'Expiration': account.get('expiration'),
                'ID': account.get('id'),
                'Name': account.get('name')
            })

    return CommandResults(
        readable_output=tableToMarkdown('Sentinel One - Get Accounts Details', context_entries,
                                        headerTransform=pascalToSpace, removeNull=True),
        outputs_prefix='SentinelOne.Accounts',
        outputs_key_field='ID',
        outputs=context_entries,
        raw_response=accounts)


def run_remote_script_command(client: Client, args: dict) -> CommandResults:
    """
    Run a remote script that was uploaded to the SentinelOne Script Library
    """

    headers = ["pendingExecutionId", "pending", "affected", "parentTaskId"]
    # Get arguments
    account_ids = argToList(args.get("account_ids"))
    script_id = args.get("script_id", "")
    output_destination = args.get("output_destination", "")
    task_description = args.get("task_description", "")
    output_directory = args.get("output_directory", "")
    agent_ids = argToList(args.get("agent_ids"))
    singularity_xdr_keyword = args.get("singularity_xdr_Keyword", "")
    singularity_xdr_url = args.get("singularity_xdr_Url", "")
    api_key = args.get("api_key", "")
    input_params = args.get("input_params", "")
    password = args.get("password", "")
    script_runtime_timeout_seconds = int(args.get("script_runtime_timeout_seconds", 3600))
    requires_approval = argToBoolean(args.get("requires_approval", False))

    run_remote_script = client.run_remote_script_request(
        account_ids, script_id, output_destination, task_description, output_directory, agent_ids,
        singularity_xdr_keyword, singularity_xdr_url, api_key, input_params, password, script_runtime_timeout_seconds,
        requires_approval)

    return CommandResults(
        readable_output=tableToMarkdown("SentinelOne - Run Remote Script", run_remote_script, headers=headers, removeNull=True),
        outputs_prefix="SentinelOne.RunRemoteScript",
        outputs=run_remote_script,
        raw_response=run_remote_script)


def get_remote_script_status(client: Client, args: dict) -> CommandResults:
    """
    Get the status of a remote script's tasks.
    """
    headers = ["id", "createdAt", "description", "statusDescription", "parentTaskId", "accountId",
               "accountName", "agentId", "agentIsActive", "agentOsType", "initiatedBy", "initiatedById"]
    remote_script_statuses = client.get_remote_script_status_request(**args)

    return CommandResults(
        readable_output=tableToMarkdown("SentinelOne - Get Remote Scripts Tasks Status",
                                        remote_script_statuses, headers=headers, removeNull=True),
        outputs_prefix="SentinelOne.GetRemoteScript",
        outputs=remote_script_statuses,
        raw_response=remote_script_statuses)


def get_remote_script_results(client: Client, args: dict) -> list[CommandResults]:
    """
    Get the remote script results
    """
    context_entries = []
    headers = ["taskId", "fileName"]
    # Get arguments
    computer_names = argToList(args.get("computer_names"))
    task_ids = argToList(args.get("task_ids"))
    results = client.get_remote_script_results_request(computer_names, task_ids)
    file_results = []
    for result in results:
        if result.get("downloadUrl", ""):
            response = requests.get(url=result.get("downloadUrl"))
            zip_file_data = response.content
            file_results.append(fileResult(filename=result.get('fileName', ''),
                                           data=zip_file_data, file_type=EntryType.ENTRY_INFO_FILE))
            context_entries.append({
                'taskId': result.get("taskId"),
                'fileName': result.get("fileName"),
                'downloadUrl': result.get("downloadUrl")
            })
    return [CommandResults(
        readable_output=tableToMarkdown("SentinelOne - Get Remote Scripts Results", results, headers=headers, removeNull=True),
        outputs_prefix="SentinelOne.RemoteScriptResults",
        outputs_key_field='taskId',
        outputs=context_entries,
        raw_response=results),
        *file_results
    ]


def run_polling_command(client: Client, cmd: str, args: Dict[str, Any]):
    """
    This command is combination of the **Run Remote Script**, **Remote Script Status Check**,
    and **Remote Script Results** commands.
    The polling command continuously polls the data until the status of the executed remote script is marked as complete,
    and then it returns the results of that remote script.
    Args:
        cmd (str): The command name.
        client (Client): SentinelOne API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    ScheduledCommand.raise_error_if_not_supported()
    interval = int(args.get('interval', 60))
    timeout = int(args.get('timeout', 600))
    if 'parent_task_id' not in args:
        command_results = run_remote_script_command(client, args)
        output = command_results.raw_response
        if isinstance(output, dict):
            parent_task_id = output.get("parentTaskId")
            args['parent_task_id'] = parent_task_id
        scheduled_command = ScheduledCommand(command=cmd, next_run_in_seconds=interval, args=args, timeout_in_seconds=timeout)
        command_results.scheduled_command = scheduled_command
        return command_results

    parent_task_id = args.get('parent_task_id')
    status_args = {"parent_task_id": parent_task_id}
    status_check_command_results = get_remote_script_status(client, status_args)
    status_outputs = status_check_command_results.raw_response
    script_completed = False
    task_ids = []
    if status_outputs and isinstance(status_outputs, list):
        for output in status_outputs:
            # Check if the script status is completed, and continue the loop
            if isinstance(output, dict) and output.get("status") == "completed":
                task_ids.append(output.get("id"))
                script_completed = True
            # Check if the script status is not completed, if not completed will break loop.
            # And mark the script_completed flag to False, so that the command rescheduled.
            if isinstance(output, dict) and output.get("status") != "completed":
                script_completed = False
                break
    if script_completed:
        results_args = {"task_ids": task_ids}
        final_command_results = get_remote_script_results(client, results_args)
        return final_command_results
    else:
        scheduled_command = ScheduledCommand(command=cmd, next_run_in_seconds=interval, args=args, timeout_in_seconds=timeout)
        return CommandResults(scheduled_command=scheduled_command)


def remote_script_automate_results(client: Client, args: dict):
    return run_polling_command(client=client, cmd="sentinelone-remote-script-automate-results", args=args)


def get_columns_from_result(columns: list):
    return [column["name"] for column in columns if column.get("name")]


def get_power_query_output(cmd: str, interval: int, timeout: int, args: dict, query_response: dict):
    """
    This method checks if the status of the Power Query results is finished. If it is finished,
    it will return the results; otherwise, it will call the schedule command.
    """
    if query_response.get("status") == "FINISHED" and query_response.get("progress") == 100:
        headers = get_columns_from_result(query_response.get("columns", []))
        context_entries = [dict(zip(headers, row)) for row in query_response.get("data", [])]
        readable_text = f"SentinelOne - Get Power Query Results for ID {query_response.get('queryId', '')}"
        recommendations = query_response.get("recommendations", [])
        if recommendations and len(recommendations) >= 1:
            recommendation = recommendations[0]
            readable_text += f"\nRecommendation: {str(recommendation)}"
        return CommandResults(
            readable_output=tableToMarkdown(readable_text, context_entries, removeNull=True,
                                            metadata='\nSummary information and details about the power query',
                                            headerTransform=pascalToSpace),
            outputs_prefix='SentinelOne.PowerQuery',
            outputs=context_entries,
            raw_response=query_response)
    else:
        scheduled_command = ScheduledCommand(command=cmd, next_run_in_seconds=interval, args=args, timeout_in_seconds=timeout)
        return CommandResults(scheduled_command=scheduled_command)


def poll_power_query_results(client: Client, cmd: str, args: dict) -> CommandResults:
    """
    This command polls the Power Query results when the status is 'finished'. If the status is not 'finished',
    it will continue to schedule the command next time it will ping Power Query
    and return the results once the status is 'finished'.
    Otherwise, it will schedule the command according to the specified interval.
    Args:
        cmd (str): The command name.
        client (Client): SentinelOne API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    ScheduledCommand.raise_error_if_not_supported()
    interval = int(args.get('interval', 10))
    timeout = int(args.get('timeout', 300))

    # Get arguments
    account_ids = argToList(args.get("account_ids"))
    site_ids = account_ids = argToList(args.get("site_ids"))
    limit = args.get('limit')
    query = args.get('query', '')
    from_date = args.get('from_date', '')
    to_date = args.get('to_date', '')
    if 'query_id' not in args:
        power_query_response = client.get_power_query_request(account_ids, site_ids, query, from_date, to_date, limit)
        if isinstance(power_query_response, dict):
            args["query_id"] = power_query_response.get('queryId', '')
            return get_power_query_output(cmd, interval, timeout, args, power_query_response)
    query_id = args.get("query_id", "")
    ping_power_query_response = client.get_ping_power_query_request(query_id)
    return get_power_query_output(cmd, interval, timeout, args, ping_power_query_response)


def get_power_query_results(client: Client, args: dict):
    return poll_power_query_results(client=client, cmd="sentinelone-get-power-query-results", args=args)


def get_mapping_fields_command():
    """
    Returns the list of fields to map in outgoing mirroring, for incidents.
    """
    mapping_response = GetMappingFieldsResponse()

    incident_type_scheme = SchemeTypeMapping(type_name="SentinelOne Incident")
    for argument, description in SENTINELONE_INCIDENT_OUTGOING_ARGS.items():
        incident_type_scheme.add_field(name=argument, description=description)
    mapping_response.add_scheme_type(incident_type_scheme)

    return mapping_response


def update_remote_incident(client: Client, threat_id: str, sentinelone_analyst_verdict: str,
                           sentinelone_threat_status: str, closing_notes: str):
    if sentinelone_analyst_verdict:
        action = ANALYST_VERDICT.get(sentinelone_analyst_verdict, None)
        if action:
            response = client.update_threat_analyst_verdict_request(threat_ids=argToList(threat_id), action=action)
            if response.get("affected") and int(response.get("affected")) > 0:
                demisto.debug(f"Successfully updated the threat analyst verdict of incident"
                              f" with remote ID [{threat_id}] to {action}")
                note = f"XSOAR - Updated the threat analyst verdict to {sentinelone_analyst_verdict}"
                client.write_threat_note_request(threat_ids=argToList(threat_id), note=note)
            else:
                demisto.debug(f"Unable to update the analyst verdict of incident with remote ID [{threat_id}]")
    if sentinelone_threat_status:
        action = THREAT_STATUS.get(sentinelone_threat_status, None)
        if action == "resolved":
            response = client.update_threat_status_request(threat_ids=argToList(threat_id), status=action)
            if response.get("affected") and int(response.get("affected")) > 0:
                demisto.debug(f"Successfully updated the threat status of incident"
                              f" with remote ID [{threat_id}] and marked as resolved")
                note = "XSOAR - Marked as resolved \n" + closing_notes
                client.write_threat_note_request(threat_ids=argToList(threat_id), note=note)
            else:
                demisto.debug(f"Unable to Mark as resolved an incident with remote ID [{threat_id}]")
        if action != "resolved" and action is not None:
            response = client.update_threat_status_request(threat_ids=argToList(threat_id), status=action)
            if response.get("affected") and int(response.get("affected")) > 0:
                demisto.debug(f"Successfully updated the threat status of incident with remote ID [{threat_id}] to {action}")
                note = f"XSOAR - Updated the threat status to {sentinelone_threat_status}"
                client.write_threat_note_request(threat_ids=argToList(threat_id), note=note)
            else:
                demisto.debug(f"Unable to update the threat status of incident with remote ID [{threat_id}]")


def update_remote_system_command(client: Client, args: dict) -> str:
    """update-remote-system command: pushes local changes to the remote system

    :type client: ``Client``
    :param client: XSOAR client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['data']`` the data to send to the remote system
        ``args['entries']`` the entries to send to the remote system
        ``args['incidentChanged']`` boolean telling us if the local incident indeed changed or not
        ``args['remoteId']`` the remote incident id
        args: A dictionary containing the data regarding a modified incident, including: data, entries, incident_changed,
         remote_incident_id, inc_status, delta

    :return:
        ``str`` containing the remote incident id - really important if the incident is newly created remotely

    :rtype: ``str``
    """
    parsed_args = UpdateRemoteSystemArgs(args)
    delta = parsed_args.delta
    remote_incident_id = parsed_args.remote_incident_id
    demisto.debug(f'Got the following data {parsed_args.data}, and delta {delta}.')
    try:
        if parsed_args.incident_changed:
            sentinelone_analyst_verdict = delta.get("sentinelonethreatanalystverdict", None)
            sentinelone_threat_status = delta.get("sentinelonethreatstatus", None)
            closing_notes = delta.get("closeNotes", "")
            update_remote_incident(client, remote_incident_id, sentinelone_analyst_verdict,
                                   sentinelone_threat_status, closing_notes)
    except Exception as e:
        demisto.error(f'Error in SentinelOne outgoing mirror for incident {remote_incident_id}. '
                      f'Error message: {str(e)}')

    return remote_incident_id


def set_xsoar_incident_entries(mirrored_object: dict, entries: list, remote_incident_id: str, close_xsoar_incident: bool):
    demisto.debug("with in the set xsoar incident entries method")
    if mirrored_object.get("threatInfo", {}).get("incidentStatus") == "resolved" and close_xsoar_incident:
        demisto.debug(f"Incident is closed: {remote_incident_id}")
        entries.append(
            {
                "Type": EntryType.NOTE,
                "Contents": {
                    "dbotIncidentClose": True,
                    "closeReason": "Incident was closed on SentinelOne",
                },
                "ContentsFormat": EntryFormat.JSON,
            }
        )
        return entries
    elif mirrored_object.get("threatInfo", {}).get("incidentStatus") in (
        set(INCIDENT_STATUS) - {"resolved"}
    ) and close_xsoar_incident:
        demisto.debug(f"Incident is reopened: {remote_incident_id}")
        entries.append(
            {
                "Type": EntryType.NOTE,
                "Contents": {"dbotIncidentReopen": True},
                "ContentsFormat": EntryFormat.JSON,
            }
        )
        return entries
    else:
        return []


def get_remote_incident_data(client: Client, remote_incident_id: str):
    """
    Called every time get-remote-data command runs on an incident.
    Gets the relevant incident entity from the remote system (SentinelOne). The remote system returns a list with this
    entity in it. We take from this entity only the relevant incoming mirroring fields, in order to do the mirroring.
    """
    mirrored_data_list = client.get_s1_threats_information(
        remote_incident_id
    )  # a list with one dict in it
    mirrored_data = mirrored_data_list[0]

    mirrored_data["incident_type"] = "SentinelOne Incident"
    return mirrored_data


def get_remote_data_command(client: Client, args: dict, params: dict):
    """
    get-remote-data command: Returns an updated remote incident.
    Args:
        args:
            id: incident id to retrieve.
            lastUpdate: when was the last time we retrieved data.

    Returns:
        GetRemoteDataResponse object, which contain the incident data to update.
    """
    remote_args = GetRemoteDataArgs(args)
    remote_incident_id = remote_args.remote_incident_id

    mirrored_data = {}
    entries: list = []
    try:
        demisto.debug(
            f"Performing get-remote-data command with incident id: {remote_incident_id} "
            f"and last_update: {remote_args.last_update}"
        )
        mirrored_data = get_remote_incident_data(client, remote_incident_id)
        if mirrored_data:
            demisto.debug("Successfully fetched the remote incident data")
            close_xsoar_incident = params.get("close_xsoar_incident", False)
            entries = set_xsoar_incident_entries(mirrored_data, entries, remote_incident_id, close_xsoar_incident)
        else:
            demisto.debug(f"No delta was found for incident {remote_incident_id}.")

        return GetRemoteDataResponse(mirrored_object=mirrored_data, entries=entries)

    except Exception as e:
        demisto.debug(
            f"Error in SentinelOne incoming mirror for incident: {remote_incident_id}\n"
            f"Error message: {str(e)}"
        )

        if not mirrored_data:
            mirrored_data = {"id": remote_incident_id}
        mirrored_data["in_mirror_error"] = str(e)

        return GetRemoteDataResponse(mirrored_object=mirrored_data, entries=[])


def get_modified_remote_data_command(client: Client, args: dict):
    """
    Gets the modified remote incidents.
    Args:
        args:
            last_update: the last time we retrieved modified incidents.

    Returns:
        GetModifiedRemoteDataResponse object, which contains a list of the retrieved incidents IDs.
    """

    remote_args = GetModifiedRemoteDataArgs(args)

    last_update_utc = dateparser.parse(
        remote_args.last_update, settings={"TIMEZONE": "UTC"}
    )  # convert to utc format
    assert last_update_utc is not None, f"could not parse{remote_args.last_update}"

    demisto.debug(f"Remote arguments last_update in UTC is {last_update_utc}")
    modified_ids_to_mirror = []
    last_update_utc = last_update_utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    raw_threats = client.get_threats_request(updated_from=last_update_utc, limit=1000, include_resolved_param=False)

    for threat in raw_threats:
        modified_ids_to_mirror.append(threat.get("id"))

    demisto.debug(f"All ids to mirror in are: {modified_ids_to_mirror}")

    return GetModifiedRemoteDataResponse(modified_ids_to_mirror)


def get_mirroring_fields(params):
    """
    Get tickets mirroring.
    """

    return {
        "mirror_direction": MIRROR_DIRECTION.get(params.get("mirror_direction")),
        "mirror_instance": demisto.integrationInstance(),
        "incident_type": "SentinelOne Incident",
    }


def fetch_threats(client: Client, args):
    incidents_threats = []
    current_fetch = args.get('current_fetch')
    incident_statuses = args.get('fetch_threat_incident_statuses')

    threats = client.get_threats_request(limit=args.get('fetch_limit'),
                                         created_after=args.get('last_fetch_date_string'),
                                         site_ids=args.get('fetch_site_ids'),
                                         incident_statuses=','.join(incident_statuses).lower() if incident_statuses else None,
                                         include_resolved_param=False)
    for threat in threats:
        rank = threat.get('rank')
        threat.update(get_mirroring_fields(args))
        try:
            rank = int(rank)
        except TypeError:
            rank = 0
        # If no fetch threat rank is provided, bring everything, else only fetch above the threshold
        if IS_VERSION_2_1 or rank >= args.get('fetch_threat_rank'):
            incident = to_incident('Threat', threat)
            date_occurred_dt = parse(incident['occurred'])
            incident_date = int(date_occurred_dt.timestamp() * 1000)
            if incident_date > int(args.get('last_fetch')):
                incidents_threats.append(incident)

            if incident_date > current_fetch:
                current_fetch = incident_date

    return incidents_threats, current_fetch


def fetch_alerts(client: Client, args):
    incidents_alerts = []
    current_fetch = args.get('current_fetch')

    query_params = assign_params(
        incidentStatus=','.join(args.get('fetch_incidentStatus')),
        createdAt__gte=args.get('last_fetch_date_string'),
        limit=args.get('fetch_limit'),
        siteIds=args.get('fetch_site_ids')
    )

    alerts, pagination = client.get_alerts_request(query_params)
    for alert in alerts:
        severity = alert.get('ruleInfo').get('severity')

        if str(severity) in args.get('fetch_severity'):
            incident = to_incident('Alert', alert)
            date_occurred_dt = parse(incident['occurred'])
            incident_date = int(date_occurred_dt.timestamp() * 1000)
            if incident_date > args.get('last_fetch'):
                incidents_alerts.append(incident)

            if incident_date > current_fetch:
                current_fetch = incident_date

    return incidents_alerts, current_fetch


def fetch_handler(client: Client, args):
    last_run = demisto.getLastRun()
    last_fetch = last_run.get('time')

    if last_fetch is None:
        last_fetch = dateparser.parse(args.get('first_fetch_time'), settings={'TIMEZONE': 'UTC'})
        if not last_fetch:
            raise DemistoException('Please provide an initial First fetch timestamp')
        last_fetch = int(last_fetch.timestamp() * 1000)

    current_fetch = last_fetch
    last_fetch_date_string = timestamp_to_datestring(last_fetch, '%Y-%m-%dT%H:%M:%S.%fZ')

    args['last_fetch'] = last_fetch
    args['last_fetch_date_string'] = last_fetch_date_string
    args['current_fetch'] = current_fetch

    if args.get('fetch_type') == 'Both':
        alert_incidents, alert_current_fetch = fetch_alerts(client, args)
        threat_incidents, threat_current_fetch = fetch_threats(client, args)

        current_fetch = alert_current_fetch if alert_current_fetch > threat_current_fetch else threat_current_fetch

        incidents = alert_incidents + threat_incidents

    elif args.get('fetch_type') == 'Alerts':
        incidents, current_fetch = fetch_alerts(client, args)
    elif args.get('fetch_type') == 'Threats':
        incidents, current_fetch = fetch_threats(client, args)
    else:
        incidents = []
        current_fetch = 0
        demisto.debug(f"{args.get('fetch_type')=} -> {incidents=} {current_fetch=}")

    demisto.setLastRun({'time': current_fetch})
    demisto.incidents(incidents)


def to_incident(type, data):
    incident = {
        'rawJSON': json.dumps(data),
    }

    if type == 'Threat':
        incident_info = data.get('threatInfo', {}) if IS_VERSION_2_1 else data
        incident['name'] = f'Sentinel One {type}: {incident_info.get("classification", "Not classified")}'
        incident['occurred'] = incident_info.get('createdAt')

    elif type == 'Alert':
        incident['name'] = f'Sentinel One {type}: {data.get("ruleInfo").get("name")}'
        incident['occurred'] = data.get('alertInfo').get('createdAt')

    return incident


def main():
    """ PARSE INTEGRATION PARAMETERS """

    global IS_VERSION_2_1

    params = demisto.params()
    token = params.get('token') or params.get('credentials', {}).get('password')
    if not token:
        raise ValueError('The API Token parameter is required.')
    api_version = params.get('api_version', '2.1')
    server = params.get('url', '').rstrip('/')
    base_url = urljoin(server, f'/web/api/v{api_version}/')
    use_ssl = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    IS_VERSION_2_1 = api_version == '2.1'

    fetch_type = params.get('fetch_type', 'Threats')
    first_fetch_time = params.get('fetch_time', '3 days')
    fetch_severity = params.get('fetch_severity', [])
    fetch_incidentStatus = params.get('fetch_incidentStatus', ["UNRESOLVED"])
    fetch_threat_incident_statuses = params.get('fetch_threat_incident_statuses', ["UNRESOLVED"])
    fetch_threat_rank = int(params.get('fetch_threat_rank', 0))
    fetch_limit = int(params.get('fetch_limit', 10))
    fetch_site_ids = params.get('fetch_site_ids', None)
    block_site_ids = argToList(params.get('block_site_ids')) or []
    mirror_direction = params.get('mirror_direction', None)

    headers = {
        'Authorization': 'ApiToken ' + token if token else 'ApiToken',
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    commands: Dict[str, Dict[str, Callable]] = {
        'common': {
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
            'sentinelone-get-agent-mac': get_agent_mac_command,
            'sentinelone-get-groups': get_groups_command,
            'sentinelone-move-agent': move_agent_to_group_command,
            'sentinelone-delete-group': delete_group,
            'sentinelone-connect-agent': connect_agent_to_network,
            'sentinelone-disconnect-agent': disconnect_agent_from_network,
            'sentinelone-broadcast-message': broadcast_message,
            'sentinelone-get-events': get_events,
            'sentinelone-create-query': create_query,
            'sentinelone-get-dv-query-status': get_dv_query_status,
            'sentinelone-get-processes': get_processes,
            'sentinelone-shutdown-agent': shutdown_agents,
            'sentinelone-uninstall-agent': uninstall_agent,
            'sentinelone-expire-site': expire_site,
            'sentinelone-fetch-threat-file': fetch_threat_file,
            'sentinelone-get-installed-applications': get_installed_applications,
            'sentinelone-initiate-endpoint-scan': initiate_endpoint_scan,
            'get-modified-remote-data': get_modified_remote_data_command,
            'get-mapping-fields': get_mapping_fields_command,
            'update-remote-system': update_remote_system_command,
        },
        '2.0': {
            'sentinelone-mark-as-threat': mark_as_threat_command,
            'sentinelone-resolve-threat': resolve_threat_command,
            'sentinelone-agent-processes': get_agent_processes,
        },
        '2.1': {
            'sentinelone-threat-summary': get_threat_summary_command,
            'sentinelone-update-threats-verdict': update_threat_analyst_verdict,
            'sentinelone-update-alerts-verdict': update_alert_analyst_verdict,
            'sentinelone-create-star-rule': create_star_rule,
            'sentinelone-get-star-rules': get_star_rule,
            'sentinelone-update-star-rule': update_star_rule,
            'sentinelone-enable-star-rules': enable_star_rules,
            'sentinelone-disable-star-rules': disable_star_rules,
            'sentinelone-delete-star-rule': delete_star_rule,
            'sentinelone-add-hash-to-blocklist': add_hash_to_blocklist,
            'sentinelone-remove-hash-from-blocklist': remove_hash_from_blocklist,
            'sentinelone-get-blocklist': get_blocklist,
            'sentinelone-fetch-file': fetch_file,
            'sentinelone-download-fetched-file': download_fetched_file,
            'sentinelone-write-threat-note': write_threat_note,
            'sentinelone-get-threat-notes': get_threat_notes,
            'sentinelone-create-ioc': create_ioc,
            'sentinelone-delete-ioc': delete_ioc,
            'sentinelone-get-iocs': get_iocs,
            'sentinelone-create-power-query': create_power_query,
            'sentinelone-ping-power-query': ping_power_query,
            'sentinelone-update-threats-status': update_threat_status,
            'sentinelone-update-alerts-status': update_alert_status,
            'sentinelone-get-alerts': get_alerts,
            'sentinelone-remove-item-from-whitelist': remove_item_from_whitelist,
            'sentinelone-run-remote-script': run_remote_script_command,
            'sentinelone-get-accounts': get_accounts,
            'sentinelone-get-remote-script-task-status': get_remote_script_status,
            'sentinelone-get-remote-script-task-results': get_remote_script_results,
            'sentinelone-remote-script-automate-results': remote_script_automate_results,
            'sentinelone-get-power-query-results': get_power_query_results,
        },
        'commands_with_params': {
            'get-remote-data': get_remote_data_command,
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
            block_site_ids=block_site_ids,
        )

        if command == 'test-module':
            return_results(test_module(client, params.get('isFetch'), first_fetch_time))
        elif command == 'fetch-incidents':
            if fetch_type:
                fetch_dict = {
                    'fetch_type': fetch_type,
                    'fetch_limit': fetch_limit,
                    'first_fetch_time': first_fetch_time,
                    'fetch_threat_rank': fetch_threat_rank,
                    'fetch_site_ids': fetch_site_ids,
                    'fetch_incidentStatus': fetch_incidentStatus,
                    'fetch_threat_incident_statuses': fetch_threat_incident_statuses,
                    'fetch_severity': fetch_severity,
                    'mirror_direction': mirror_direction
                }

                return_results(fetch_handler(client, fetch_dict))
            else:
                return_results('Please define what type to fetch. Alerts or Threats.')

        else:
            if command in commands['common']:
                return_results(commands['common'][command](client, demisto.args()))
            elif command in commands[api_version]:
                return_results(commands[api_version][command](client, demisto.args()))
            elif command in commands['commands_with_params']:
                return_results(commands['commands_with_params'][command](client, demisto.args(), params))
            else:
                raise NotImplementedError(f'The {command} command is not supported for API version {api_version}')

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
