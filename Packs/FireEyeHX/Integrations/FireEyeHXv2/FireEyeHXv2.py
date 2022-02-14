

import demistomock as demisto
from CommonServerPython import *

import base64
import json
import os
import re
import urllib.parse
import requests
import traceback
from typing import Dict, Any, Tuple

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

STANDART_INVESTIGATIVE_DETAILS_OSX = {  # pragma: no cover
    "commands": [
        {
            "name": "sysinfo"
        },
        {
            "name": "disks"
        },
        {
            "name": "volumes"
        },
        {
            "name": "useraccounts"
        },
        {
            "name": "groups"
        },
        {
            "name": "files-api",
            "parameters": [
                {
                    "name": "Path",
                    "value": "/"
                },
                {
                    "name": "Regex",
                    "value": "^(?:Applications|Library|System|User|bin|cores|opt|private|sbin|usr)+"
                },
                {
                    "name": "Include Remote Locations",
                    "value": False
                },
                {
                    "name": "Depth",
                    "value": -1
                },
                {
                    "name": "MD5",
                    "value": True
                },
                {
                    "name": "SHA1",
                    "value": False
                },
                {
                    "name": "SHA256",
                    "value": False
                },
                {
                    "name": "Verify Digital Signatures",
                    "value": False
                },
                {
                    "name": "AND Operator",
                    "value": False
                },
                {
                    "name": "Include Files",
                    "value": True
                },
                {
                    "name": "Include Directories",
                    "value": True
                },
                {
                    "name": "Preserve Times",
                    "value": False
                }
            ]
        },
        {
            "name": "persistence",
            "parameters": [
                {
                    "name": "MD5",
                    "value": True
                },
                {
                    "name": "SHA1",
                    "value": False
                },
                {
                    "name": "SHA256",
                    "value": False
                },
                {
                    "name": "Preserve Times",
                    "value": False
                },
                {
                    "name": "Verify Digital Signatures",
                    "value": False
                }
            ]
        },
        {
            "name": "tasks",
            "parameters": [
                {
                    "name": "MD5",
                    "value": True
                },
                {
                    "name": "SHA1",
                    "value": False
                },
                {
                    "name": "SHA256",
                    "value": False
                },
                {
                    "name": "Verify Digital Signatures",
                    "value": True
                },
                {
                    "name": "Preserve Times",
                    "value": False
                }
            ]
        },
        {
            "name": "processes-api"
        },
        {
            "name": "urlhistory",
            "parameters": [
                {
                    "name": "TargetBrowser",
                    "value": "Chrome"
                },
                {
                    "name": "TargetBrowser",
                    "value": "Firefox"
                },
                {
                    "name": "TargetBrowser",
                    "value": "Safari"
                }
            ]
        },
        {
            "name": "quarantine-events"
        },
        {
            "name": "ports"
        },
        {
            "name": "services",
            "parameters": [
                {
                    "name": "MD5",
                    "value": True
                },
                {
                    "name": "SHA1",
                    "value": False
                },
                {
                    "name": "SHA256",
                    "value": False
                },
                {
                    "name": "Verify Digital Signatures",
                    "value": True
                },
                {
                    "name": "Preserve Times",
                    "value": False
                }
            ]
        },
        {
            "name": "stateagentinspector",
            "parameters": [
                {
                    "name": "eventTypes",
                    "value": []
                }
            ]
        },
        {
            "name": "syslog"
        }
    ]
}
STANDART_INVESTIGATIVE_DETAILS_LINUX = {
    "commands": [
        {
            "name": "sysinfo"
        },
        {
            "name": "files-api",
            "parameters": [
                {
                    "name": "Path",
                    "value": "/"
                },
                {
                    "name": "Regex",
                    "value": "^(?:usr|lib|lib64|opt|home|sbin|bin|etc|root)+"
                },
                {
                    "name": "Include Remote Locations",
                    "value": False
                },
                {
                    "name": "Depth",
                    "value": -1
                },
                {
                    "name": "MD5",
                    "value": True
                },
                {
                    "name": "SHA1",
                    "value": False
                },
                {
                    "name": "SHA256",
                    "value": False
                },
                {
                    "name": "AND Operator",
                    "value": False
                },
                {
                    "name": "Include Files",
                    "value": True
                },
                {
                    "name": "Include Directories",
                    "value": True
                },
                {
                    "name": "Preserve Times",
                    "value": False
                }
            ]
        },
        {
            "name": "processes-api"
        },
        {
            "name": "ports"
        },
        {
            "name": "shell-history",
            "parameters": [
                {
                    "name": "ShellList",
                    "value": [
                        "bash",
                        "zsh",
                        "ksh93"
                    ]
                }
            ]
        }
    ]
}
STANDART_INVESTIGATIVE_DETAILS_WIN = {
    "commands": [
        {
            "name": "sysinfo"
        },
        {
            "name": "disks",
            "parameters": [
                {
                    "name": "Prevent Hibernation",
                    "value": True
                }
            ]
        },
        {
            "name": "volumes",
            "parameters": [
                {
                    "name": "Prevent Hibernation",
                    "value": True
                }
            ]
        },
        {
            "name": "useraccounts",
            "parameters": [
                {
                    "name": "Prevent Hibernation",
                    "value": True
                }
            ]
        },
        {
            "name": "prefetch",
            "parameters": [
                {
                    "name": "Prevent Hibernation",
                    "value": True
                }
            ]
        },
        {
            "name": "files-raw",
            "parameters": [
                {
                    "name": "Prevent Hibernation",
                    "value": True
                },
                {
                    "name": "Active Files",
                    "value": True
                },
                {
                    "name": "Deleted Files",
                    "value": True
                },
                {
                    "name": "Parse NTFS INDX Buffers",
                    "value": True
                },
                {
                    "name": "Path",
                    "value": "%systemdrive%"
                },
                {
                    "name": "Depth",
                    "value": -1
                },
                {
                    "name": "MD5",
                    "value": True
                },
                {
                    "name": "SHA1",
                    "value": False
                },
                {
                    "name": "SHA256",
                    "value": False
                },
                {
                    "name": "Analyze Entropy",
                    "value": False
                },
                {
                    "name": "Enumerate Imports",
                    "value": False
                },
                {
                    "name": "Enumerate Exports",
                    "value": False
                },
                {
                    "name": "Analyze File Anomalies",
                    "value": False
                },
                {
                    "name": "Verify Digital Signatures",
                    "value": False
                },
                {
                    "name": "Strings",
                    "value": False
                },
                {
                    "name": "AND Operator",
                    "value": False
                },
                {
                    "name": "Include Files",
                    "value": True
                },
                {
                    "name": "Include Directories",
                    "value": True
                },
                {
                    "name": "Get Resources",
                    "value": False
                },
                {
                    "name": "Get Resource Data",
                    "value": False
                },
                {
                    "name": "Get Version Info",
                    "value": False
                }
            ]
        },
        {
            "name": "persistence",
            "parameters": [
                {
                    "name": "MD5",
                    "value": True
                },
                {
                    "name": "SHA1",
                    "value": False
                },
                {
                    "name": "SHA256",
                    "value": False
                },
                {
                    "name": "Preserve Times",
                    "value": False
                },
                {
                    "name": "Enumerate Imports",
                    "value": False
                },
                {
                    "name": "Enumerate Exports",
                    "value": False
                },
                {
                    "name": "Verify Digital Signatures",
                    "value": True
                },
                {
                    "name": "Analyze Entropy",
                    "value": False
                },
                {
                    "name": "Analyze File Anomalies",
                    "value": False
                },
                {
                    "name": "Get Resources",
                    "value": False
                },
                {
                    "name": "Get Version Info",
                    "value": False
                },
                {
                    "name": "Prevent Hibernation",
                    "value": True
                }
            ]
        },
        {
            "name": "registry-raw",
            "parameters": [
                {
                    "name": "Prevent Hibernation",
                    "value": True
                },
                {
                    "name": "Type",
                    "value": "All"
                }
            ]
        },
        {
            "name": "tasks",
            "parameters": [
                {
                    "name": "Prevent Hibernation",
                    "value": True
                },
                {
                    "name": "MD5",
                    "value": True
                },
                {
                    "name": "SHA1",
                    "value": False
                },
                {
                    "name": "SHA256",
                    "value": False
                },
                {
                    "name": "Verify Digital Signatures",
                    "value": True
                },
                {
                    "name": "Preserve Times",
                    "value": False
                },
                {
                    "name": "raw mode",
                    "value": False
                }
            ]
        },
        {
            "name": "eventlogs",
            "parameters": [
                {
                    "name": "Prevent Hibernation",
                    "value": True
                }
            ]
        },
        {
            "name": "processes-memory",
            "parameters": [
                {
                    "name": "Preserve Times",
                    "value": False
                },
                {
                    "name": "Prevent Hibernation",
                    "value": True
                },
                {
                    "name": "MD5",
                    "value": True
                },
                {
                    "name": "SHA1",
                    "value": False
                },
                {
                    "name": "SHA256",
                    "value": False
                },
                {
                    "name": "MemD5",
                    "value": False
                },
                {
                    "name": "enumerate imports",
                    "value": True
                },
                {
                    "name": "enumerate exports",
                    "value": True
                },
                {
                    "name": "Verify Digital Signatures",
                    "value": True
                },
                {
                    "name": "sections",
                    "value": True
                },
                {
                    "name": "ports",
                    "value": True
                },
                {
                    "name": "handles",
                    "value": True
                },
                {
                    "name": "detect injected dlls",
                    "value": True
                },
                {
                    "name": "raw mode",
                    "value": False
                },
                {
                    "name": "strings",
                    "value": False
                }
            ]
        },
        {
            "name": "urlhistory",
            "parameters": [
                {
                    "name": "Prevent Hibernation",
                    "value": True
                },
                {
                    "name": "GetThumbnails",
                    "value": False
                },
                {
                    "name": "GetIndexedPageContent",
                    "value": False
                }
            ]
        },
        {
            "name": "ports",
            "parameters": [
                {
                    "name": "Prevent Hibernation",
                    "value": True
                }
            ]
        },
        {
            "name": "services",
            "parameters": [
                {
                    "name": "Prevent Hibernation",
                    "value": True
                },
                {
                    "name": "MD5",
                    "value": True
                },
                {
                    "name": "SHA1",
                    "value": False
                },
                {
                    "name": "SHA256",
                    "value": False
                },
                {
                    "name": "Verify Digital Signatures",
                    "value": True
                },
                {
                    "name": "Preserve Times",
                    "value": False
                },
                {
                    "name": "raw mode",
                    "value": False
                }
            ]
        },
        {
            "name": "stateagentinspector",
            "parameters": [
                {
                    "name": "eventTypes",
                    "value": []
                }
            ]
        }
    ]
}

SYS_SCRIPT_MAP = {
    'osx': STANDART_INVESTIGATIVE_DETAILS_OSX,
    'win': STANDART_INVESTIGATIVE_DETAILS_WIN,
    'linux': STANDART_INVESTIGATIVE_DETAILS_LINUX
}

TABLE_POLLING_COMMANDS = {

    'searching': {
        'type': 'searchId',
        'message': 'Searching... , started polling for id '
    },
    'acquisition': {
        'type': 'acquisition_id',
        'message': 'Acquisition is not yet ready, started polling for id '
    }
}

''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, base_url, verify=True, proxy=False, auth=None):

        headers = {'X-FeApi-Token': self.get_token_request(base_url, auth)}

        super().__init__(base_url, verify=False, proxy=proxy, ok_codes=range(200, 205), headers=headers, auth=auth)

    def get_token_request(self, base_url, auth):
        """
        returns a token on successful request
        """

        url = '{}token'.format(base_url)

        # basic authentication
        try:
            response = requests.request(
                'GET',
                url,
                headers={'Accept': 'application/json'},
                verify=False,
                auth=auth
            )
        except Exception:
            raise ValueError("Server URL incorrect")

        # handle request failure
        if response.status_code not in range(200, 205):
            raise ValueError("User Name or Password incorrect")
        # successful request
        response_headers = response.headers
        token = response_headers.get('X-FeApi-Token')
        return token

    """
    POLICIES REQUEST
    """

    def list_policy_request(self, offset: int, limit: int, policy_id: str = None, name: str = None, enabled: bool = None):

        params = assign_params(_id=policy_id, name=name, offset=offset, limit=limit, enabled=enabled)

        return self._http_request(
            method='GET',
            url_suffix='policies',
            params=params,
        )

    def list_host_set_policy_request(self, offset: int, limit: int, policyId: str = ''):

        params = assign_params(policy_id=policyId, offset=offset, limit=limit)

        return self._http_request(
            method="GET",
            url_suffix="host_set_policies",
            params=params
        )

    def list_host_set_policy_by_hostSetId_request(self, hostSetId):

        return self._http_request(
            method="GET",
            url_suffix=f"host_sets/{hostSetId}/host_set_policies"
        )

    def assign_host_set_policy_request(self, body: Dict[str, Any]):

        return self._http_request(
            method="POST",
            url_suffix="host_set_policies",
            json_data=body,
            return_empty_response=True)

    def delete_host_set_policy_request(self, hostSetId, policyId):

        return self._http_request(
            method="DELETE",
            url_suffix=f'host_sets/{hostSetId}/host_set_policies/{policyId}',
            return_empty_response=True
        )

    """
    HOST INFORMATION REQUEST
    """

    def get_hosts_by_agentId_request(self, agentId: str):

        return self._http_request(
            method="GET",
            url_suffix=f"hosts/{agentId}"
        )

    def get_hosts_request(self, limit=None, offset=None, has_active_threats=None, has_alerts=None,
                          agent_version=None, containment_queued=None, containment_state=None,
                          host_name=None, os_platform=None, reported_clone=None, time_zone=None):

        params = assign_params(
            limit=limit,
            offset=offset,
            has_active_threats=has_active_threats,
            has_alerts=has_alerts,
            agent_version=agent_version,
            containment_queued=containment_queued,
            containment_state=containment_state,
            hostname=host_name,
            reported_clone=reported_clone,
            time_zone=time_zone)

        if os_platform:
            params['os.platform'] = os_platform

        return self._http_request(
            method="GET",
            url_suffix="hosts",
            params=params,
            headers=self._headers
        )

    def get_host_set_information_request(self, body, hostSetId):

        url = f"host_sets/{hostSetId}" if hostSetId else "host_sets"
        return self._http_request(
            method='GET',
            url_suffix=url,
            params=body
        )

    """
    HOST CONTAINMENT REQUESTS
    """

    def host_containmet_request(self, agentId: str):

        self._http_request(
            method="POST",
            url_suffix=f"hosts/{agentId}/containment",
        )

    def approve_containment_request(self, agentId: str):

        return self._http_request(
            method="PATCH",
            url_suffix=f"hosts/{agentId}/containment",
            json_data={"state": "contain"},
            return_empty_response=True
        )

    def cancel_containment_request(self, agentId: str):

        self._http_request(
            method="DELETE",
            url_suffix=f"hosts/{agentId}/containment",
            return_empty_response=True
        )

    def get_list_containment_request(self, offset: int, limit: int, stateUpdateTime: str):

        params = assign_params(offset=offset, limit=limit, stateUpdateTime=stateUpdateTime)

        return self._http_request(
            method="GET",
            url_suffix="containment_states",
            params=params
        )

    """
    ACQUISITION REQUEST
    """

    def data_acquisition_request(self, agentId: str, body: Dict):

        return self._http_request(
            method="POST",
            url_suffix=f"hosts/{agentId}/live",
            json_data=body
        )

    def data_acquisition_information_request(self, acquisition_id):

        return self._http_request(
            method='GET',
            url_suffix=f'acqs/live/{acquisition_id}'
        )["data"]

    def delete_data_acquisition_request(self, acquisitionId):

        self._http_request(
            method="DELETE",
            url_suffix=f"acqs/live/{acquisitionId}",
            return_empty_response=True
        )

    def data_collection_request(self, acquisition_id):

        return self._http_request(
            method='GET',
            url_suffix=f"acqs/live/{acquisition_id}.mans",
            resp_type='content'
        )

    def file_acquisition_request(self, agent_id, file_name, file_path, comment=None, external_id=None, req_use_api=None):

        body = assign_params(req_path=file_path, req_filename=file_name,
                             comment=comment, external_id=external_id, req_use_api=req_use_api)

        return self._http_request(
            method='POST',
            url_suffix=f'hosts/{agent_id}/files',
            json_data=body
        )["data"]

    def file_acquisition_information_request(self, acquisition_id):

        return self._http_request(
            method='GET',
            url_suffix=f'acqs/files/{acquisition_id}'
        )["data"]

    def file_acquisition_package_request(self, acquisition_id):

        return self._http_request(
            method='GET',
            url_suffix=f"acqs/files/{acquisition_id}.zip"
        )["content"]

    def delete_file_acquisition_request(self, acquisition_id):
        """

        no return value on successful request

        """
        self._http_request(
            method='DELETE',
            url_suffix=f"acqs/files/{acquisition_id}",
            return_empty_response=True
        )

    """
    ALERTS REQUEST
    """

    def get_alerts_request(self, has_share_mode=None, resolution=None, agent_id=None,
                           condition_id=None, limit=None, offset=None, sort=None, min_id=None,
                           event_at=None, alert_id=None, matched_at=None, reported_at=None, source=None, filterQuery=None):
        """

        returns the response body on successful request

        """

        params = assign_params(
            has_share_mode=has_share_mode,
            resolution=resolution,
            event_at=event_at,
            min_id=min_id,
            _id=alert_id,
            matched_at=matched_at,
            reported_at=reported_at,
            source=source,
            limit=limit,
            offset=offset,
            sort=sort
        )

        if agent_id:
            params["agent._id"] = agent_id
        if condition_id:
            params["condition._id"] = condition_id

        if filterQuery:
            response = self._http_request(
                'GET',
                url_suffix=f"alerts?filterQuery={filterQuery}",
                params=params,
                headers=self._headers
            )
        else:
            response = self._http_request(
                'GET',
                url_suffix="alerts",
                params=params,
                headers=self._headers
            )
        try:
            return response
        except Exception as e:
            LOG(e)
            raise ValueError('Failed to parse response body')

    def get_alert_request(self, alert_id: int):

        return self._http_request(
            method='GET',
            url_suffix=f'/alerts/{alert_id}',
            headers=self._headers
        )

    def suppress_alert_request(self, alert_id: int):
        """

        no return value on successful request

        """

        return self._http_request(
            method='DELETE',
            url_suffix=f'/alerts/{alert_id}',
            return_empty_response=True
        )

    """
    INDICATORS REQUEST
    """

    def get_indicator_request(self, category, name):
        """
        returns a json object representing an indicator
        """
        try:
            return self._http_request(
                method='GET',
                url_suffix=f"/indicators/{category}/{name}"
            )["data"]
        except Exception as e:
            if '404' in str(e):
                raise ValueError(f"The indecator '{name}' Not Found")
            else:
                raise ValueError(e)

    def get_indicators_request(self, params):

        try:
            return self._http_request(
                method='GET',
                url_suffix="/indicators" if not params.get("category") else f"/indicators/{params.get('category')}",
                params=params,
            )

        except Exception as e:
            LOG(e)
            raise ValueError('Failed to parse response body')

    def get_indicator_conditions_request(self, category, name, offset):
        """
        returns a list of json objects, each representing an indicator condition
        if no results are found- returns None

        """
        params = {'offset': offset, 'enabled': True}

        try:
            return self._http_request(
                method='GET',
                url_suffix=f'/indicators/{category}/{name}/conditions',
                params=params
            )

        except Exception as e:
            LOG(e)
            raise ValueError('Failed to parse response body')

    def append_conditions_request(self, name: str, category: str, body: str):

        self._headers['Content-Type'] = 'text/plain'
        return self._http_request(
            method="PATCH",
            url_suffix=f"/indicators/{category}/{name}/conditions",
            data=body
        )

    def new_indicator_request(self, category):
        """
        Create a new indicator
        """

        try:
            return self._http_request(
                method='POST',
                url_suffix=f"indicators/{category}"
            )
        except Exception as e:
            LOG(e)
            raise ValueError('Failed to parse response body, unexpected response structure from the server.')

    """
    SEARCHES REQUEST
    """

    def get_search_by_id_request(self, searchId: int):

        return self._http_request(
            method="GET",
            url_suffix=f"searches/{searchId}"
        )

    def get_search_list_request(self, offset: int, limit: int, state: str = None, hostSetId: int = None,
                                actorUsername: str = None, sort: str = None):

        params = assign_params(offset=offset, limit=limit, hostSetId=hostSetId,
                               actorUsername=actorUsername, state=state, sort=sort)

        return self._http_request(
            method='GET',
            url_suffix="searches",
            params=params
        )

    def search_stop_request(self, searchId: str):

        return self._http_request(
            method="POST",
            url_suffix=f"searches/{searchId}/actions/stop",
        )

    def delete_search_request(self, search_id):
        """

        no return value on successful request

        """

        self._http_request(
            method='DELETE',
            url_suffix=f"searches/{search_id}",
            return_empty_response=True
        )

    def search_result_get_request(self, searchId: str):

        return self._http_request(
            method="GET",
            url_suffix=f"searches/{searchId}/results",
        )

    def search_request(self, body: Dict):

        return self._http_request(
            method="POST",
            url_suffix="searches",
            json_data=body
        )


''' HELPER FUNCTIONS '''


def get_alerts(client: Client, args: Dict[str, Any]) -> List:

    offset = 0
    alerts = []  # type: List[Dict[str, str]]

    max_records = args.get("limit") or float('inf')

    while len(alerts) < max_records:
        alerts_partial_results = client.get_alerts_request(
            has_share_mode=args.get("hasShareMode"),
            resolution=args.get("resolution"),
            agent_id=args.get("agentId"),
            condition_id=args.get("conditionId"),
            event_at=args.get("eventAt"),
            alert_id=args.get("alertId"),
            matched_at=args.get("matchedAt"),
            reported_at=args.get("reportedAt"),
            source=args.get("source"),
            offset=offset,
            limit=args.get("limit") or 100,
            sort=args.get("sort"),
            filterQuery=args.get("filterQuery")
        )
        # empty list
        if len(alerts_partial_results['data']['entries']) == 0:
            break
        alerts.extend(alerts_partial_results['data']['entries'])
        offset = len(alerts)

    # remove access results
    if len(alerts) > max_records:
        alerts[int(max_records) - 1: -1] = []

    return alerts


def get_agent_id_by_host_name(client: Client, hostName: str):

    return client.get_hosts_request(host_name=hostName, limit=1)["data"]["entries"][0]["_id"]


def host_set_entry(host_sets: List[Dict]) -> List[Dict]:
    return [{
        'Name': host_set.get('name'),
        'ID': host_set.get('_id'),
        'Type': host_set.get('type')
    } for host_set in host_sets]


def general_context_from_event(alert: Dict):

    def file_context(values: Dict):
        dbot = Common.DBotScore(values.get('fileWriteEvent/md5'), DBotScoreType.FILE,
                                integration_name="FireEye-HX", score=Common.DBotScore.NONE)
        return Common.File(
            dbot,
            name=values.get('fileWriteEvent/fileName'),
            md5=values.get('fileWriteEvent/md5'),
            extension=values.get('fileWriteEvent/fileExtension'),
            path=values.get('fileWriteEvent/fullPath')
        )

    def ip_context(values: Dict):

        dbot = Common.DBotScore(
            values.get("ipv4NetworkEvent/remoteIP"),
            DBotScoreType.IP,
            integration_name="FireEye-HX",
            score=Common.DBotScore.NONE
        )
        return Common.IP(values.get("ipv4NetworkEvent/remoteIP"), dbot_score=dbot)

    context_map = {
        'fileWriteEvent': file_context,
        'ipv4NetworkEvent': ip_context
    }

    if context_map.get(alert['event_type']) is not None:
        f = context_map[alert['event_type']]
        return f(alert['event_values'])
    return None


def oneFromList(listOfArgs, **args):

    checker = 0
    for arg in listOfArgs:
        if args.get(arg):
            checker += 1
            result = (arg, args.get(arg))

    return result if checker == 1 else False


def organize_search_body_host(client: Client, arg: Tuple, body: Dict):
    if arg[0] == "hostsNames":
        hostsNames = arg[1].split(",")
        agentsIds = []
        for hostName in hostsNames:
            try:
                agentsIds.append({"_id": get_agent_id_by_host_name(client, hostName)})
            except Exception:
                raise ValueError(f"Host Name {hostName} is not valid")

        body["hosts"] = agentsIds

    elif arg[0] == "agentsIds":
        agentsIds = arg[1].split(",")
        agentsIds = [{"_id": agentId} for agentId in agentsIds]
        body["hosts"] = agentsIds

    elif arg[0] == "hostSetName":
        hostSet = {"_id": client.get_host_set_information_request({"name": arg[1]}, None)["data"]["entries"][0]["_id"]}
        body["host_set"] = hostSet

    elif arg[0] == "hostSet":
        hostSet = {"_id": int(arg[1])}
        body["host_set"] = hostSet

    return body


def organize_search_body_query(argForQuery: Tuple, **args):

    query = []
    if argForQuery[0] == "fieldSearchName":
        if not args.get("fieldSearchOperator") or not args.get("fieldSearchValue"):
            raise ValueError("fieldSearchOperator and fieldSearchValue are required arguments")

        fieldSearchValue = args.get("fieldSearchValue", "").split(",")
        for searchValue in fieldSearchValue:
            query.append(assign_params(field=argForQuery[1], operator=args.get("fieldSearchOperator"), value=searchValue))

    else:
        if not args.get(f"{argForQuery[0]}Operator"):
            raise ValueError(f"{argForQuery[0]}Operator is required argument")

        arg_to_query_field_map = {
            'dnsHostname': 'DNS Hostname',
            'fileFullPath': 'File Full Path',
            'fileMD5Hash': 'File MD5 Hash',
            'ipAddress': 'IP Address'
        }

        for searchValue in argForQuery[1].split(","):
            query.append(assign_params(field=arg_to_query_field_map[argForQuery[0]],
                                       operator=args.get(f"{argForQuery[0]}Operator"),
                                       value=searchValue)
                         )

    return query


def collect_endpoint_contxt(host: Dict):

    return {
        'Hostname': host.get('hostname'),
        'ID': host.get('_id'),
        'IPAddress': host.get('primary_ip_address'),
        'Domain': host.get('domain'),
        'MACAddress': host.get('primary_mac'),
        'OS': host.get('os', {}).get('platform'),
        'OSVersion': host.get('os', {}).get('product_name')
    }


def data_acquisition(client: Client, args: Dict[str, Any]) -> Dict:

    hostName = args.get("hostName", "")
    agentId = args.get("agentId")
    script = args.get("script", "")
    scriptName = args.get("scriptName")
    defaultSystemScript = args.get("defaultSystemScript")

    if not hostName and not agentId:
        raise ValueError('Please provide either agentId or hostName')

    if not defaultSystemScript and not script:
        raise ValueError('If the script is not provided, defaultSystemScript must be specified')

    if script and not scriptName:
        raise ValueError('If the script is provided, script name must be specified as well')

    if not agentId:
        agentId = get_agent_id_by_host_name(client, hostName)

    # determine whether to use the default script
    sys = defaultSystemScript
    if sys:
        script = json.dumps(SYS_SCRIPT_MAP[sys])
        scriptName = f'{sys}DefaultScript'

    body = {
        'name': scriptName,
        'script': {'b64': base64.b64encode(bytes(script, 'utf-8')).decode()}
    }

    return client.data_acquisition_request(agentId, body)["data"]


def alert_entry(alert: Dict):

    alert_entry = {
        'Alert ID': alert.get('_id'),
        'Reported': alert.get('reported_at'),
        'Event Type': alert.get('event_type'),
        'Agent ID': alert.get('agent', {}).get('_id')
    }

    return alert_entry


def indicator_entry(indicator: Dict):

    indicator_entry = {
        'OS': ', '.join(indicator.get('platforms', [])),
        'Name': indicator.get('name'),
        'Created By': indicator.get('created_by'),
        'Active Since': indicator.get('active_since'),
        'Category': indicator.get('category', {}).get('name'),
        'Signature': indicator.get('signature'),
        'Active Condition': indicator.get('stats', {}).get('active_conditions'),
        'Hosts With Alerts': indicator.get('stats', {}).get('alerted_agents'),
        'Source Alerts': indicator.get('stats', {}).get('source_alerts')
    }
    return indicator_entry


def organization_of_indicator(alert: Dict[str, Any]) -> CommandResults:

    if alert.get("event_type") == 'fileWriteEvent':
        indicator = general_context_from_event(alert)
        event_values: Dict[str, Any] = alert.get('event_values', {})
        md_table = tableToMarkdown(
            name="File",
            t={'Name': event_values.get('fileWriteEvent/fileName'),
                'md5': event_values.get('fileWriteEvent/md5'),
                'Extension': event_values.get('fileWriteEvent/fileExtension'),
                 'Path': event_values.get('fileWriteEvent/fullPath')},
            headers=['Name', 'md5', 'Extension', 'Path']
        )
        return CommandResults(
            outputs_prefix="File",
            indicator=indicator,
            readable_output=md_table
        )

    else:
        indicator = general_context_from_event(alert)
        event_values = alert.get('event_values', {})
        md_table = tableToMarkdown(
            name="File",
            t={'Ipv4': event_values.get('ipv4NetworkEvent/remoteIP')}
        )
        return CommandResults(
            outputs_prefix="Ip",
            indicator=indicator,
            readable_output=md_table
        )


def condition_entry(condition: Dict):

    indicator_entry = {
        'Event Type': condition.get('event_type'),
        'Operator': condition.get('tests', {})[0].get('operator'),
        'Value': condition.get('tests', {})[0].get('value'),

    }
    return indicator_entry


def get_all_indicators(client: Client, category=None, search=None, share_mode=None,
    sort=None, created_by=None, alerted=None, limit=None):

    max_records = limit or float('inf')
    indicators = []   # type: List[Dict[str, str]]

    params = assign_params(category=category, search=search, sort=sort, created_by=created_by, offset=0, limit=limit or 100)

    if share_mode:
        params["category.share_mode"] = share_mode

    if alerted:
        params["stats.alerted_agents"] = share_mode

    # get all results
    while len(indicators) < max_records:
        indicators_partial_results = client.get_indicators_request(params)["data"]["entries"]
        if not indicators_partial_results:
            break
        indicators.extend(indicators_partial_results)
        params["offset"] = len(indicators)

    # remove access results
    if len(indicators) > max_records:
        indicators[int(max_records) - 1: -1] = []

    return indicators


def get_all_enabled_conditions(client: Client, indicator_category, indicator_name):

    offset = 0
    conditions = []   # type: List[Dict[str, str]]

    # get all results
    while True:
        conditions_partial_results = client.get_indicator_conditions_request(
            indicator_category,
            indicator_name,
            offset=offset
        )['data']['entries']
        if not conditions_partial_results:
            break
        conditions.extend(conditions_partial_results)
        offset = len(conditions)
    return conditions


def get_indicator_conditions(client: Client, args: Dict[str, Any]) -> CommandResults:
    """

    returns a list of enabled conditions assosiated with a specific indicator to the war room

    """

    conditions = get_all_enabled_conditions(
        client,
        args.get('category'),
        args.get('name')
    )

    conditions_entries = [condition_entry(condition) for condition in conditions]

    md_table = tableToMarkdown(
        name=f"Indicator '{args.get('name')}' Alerts on",
        t=conditions_entries
    )

    return CommandResults(
        outputs_prefix="FireEyeHX.Conditions",
        outputs_key_field="_id",
        outputs=conditions,
        readable_output=md_table
    )


"""helper fetch-incidents"""


def organize_reportedAt(reported_at):

    milisecond = int(reported_at[-4:-1]) + 1
    if milisecond == 1000:
        reported_at = date_to_timestamp(reported_at[:-5], date_format="%Y-%m-%dT%H:%M:%S") + 1000
        reported_at = timestamp_to_datestring(reported_at, date_format="%Y-%m-%dT%H:%M:%S") + ".000Z"
    else:
        if milisecond < 10:
            reported_at = reported_at[:-4] + '00' + str(milisecond) + reported_at[-1]
        if milisecond < 100:
            reported_at = reported_at[:-4] + '0' + str(milisecond) + reported_at[-1]
        reported_at = reported_at[:-4] + str(milisecond) + reported_at[-1]

    return reported_at


def query_fetch(reported_at=None, first_fetch: str = None):

    query = '{"operator":"between","arg":['
    if reported_at:
        query += '"' + reported_at + '"' + ','
    else:
        query += '"' + timestamp_to_datestring(parse_date_range(first_fetch, to_timestamp=True, utc=False)[0]) + '"' + ','
    query += '"' + timestamp_to_datestring(parse_date_range("1 days", to_timestamp=True,
                                                            utc=False)[1]) + '"' + '],"field":"reported_at"}'

    return query


def parse_alert_to_incident(alert: Dict) -> Dict:

    event_type = alert.get('event_type')
    event_type = 'NewEvent' if not event_type else event_type
    event_values = alert.get('event_values', {})
    event_indicators_map = {
        'fileWriteEvent': 'fileWriteEvent/fileName',
        'ipv4NetworkEvent': 'ipv4NetworkEvent/remoteIP',
        'dnsLookupEvent': 'dnsLookupEvent/hostname',
        'regKeyEvent': 'regKeyEvent/valueName'
    }
    event_indicator = event_indicators_map.get(event_type)
    event_indicator = 'No Indicator' if not event_indicator else event_indicator

    indicator = ''
    if isinstance(event_values, dict):
        indicator = event_values.get(event_indicator, '')

    incident_name = u'{event_type_parsed}: {indicator}'.format(
        event_type_parsed=re.sub("([a-z])([A-Z])", "\g<1> \g<2>", event_type).title(),
        indicator=indicator
    )

    incident = {
        'name': incident_name,
        'occurred': alert.get("event_at"),
        'rawJSON': json.dumps(alert)
    }
    return incident


''' COMMAND FUNCTIONS '''


"""
POLICIES
"""


def list_policy_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    offset = args.get('offset')
    limit = args.get('limit')
    name = args.get('policyName')
    policy_id = args.get('policyId')
    enabled = args.get('enabled')

    if name and policy_id:
        raise ValueError("Enter a name or ID but not both")

    if not limit:
        limit = 50  # default value
    if not offset:
        offset = 0  # default value

    response = client.list_policy_request(offset=offset, limit=limit, policy_id=policy_id, name=name, enabled=enabled)

    for_table = []
    for entry in response['data']["entries"]:
        for_table.append({"Policy Id": entry["_id"],
                          "Policy Name": entry["name"],
                          "Description": entry["description"],
                          "Priority": entry["priority"],
                          "Enabled": entry["enabled"]})
    headers_for_table = ["Policy Name", "Policy Id", "Description", "Priority", "Enabled"]

    md = tableToMarkdown(name="FireEye HX List Policies", t=for_table, headers=headers_for_table)

    command_results = CommandResults(

        outputs_prefix='FireEyeHX.Policy',
        outputs_key_field='_id',
        outputs=response,
        raw_response=response,
        readable_output=md
    )

    return command_results


def list_host_set_policy_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    offset = args.get("offset")
    limit = args.get("limit")
    hostSetId = args.get("hostSetId")
    policyId = args.get("policyId", "")

    if hostSetId and policyId:
        raise ValueError("Enter a Policy Id or Host Set Id but not both")

    if not offset:
        offset = 0
    if not limit:
        limit = 50

    if hostSetId:
        response = client.list_host_set_policy_by_hostSetId_request(hostSetId)
    else:
        response = client.list_host_set_policy_request(offset, limit, policyId)

    for_table = []
    for entry in response["data"]["entries"]:
        for_table.append({
            "Policy Id": entry["policy_id"],
            "Host Set Id": entry["persist_id"]
        })
    headers_for_table = ["Policy Id", "Host Set Id"]
    md = tableToMarkdown(name="FireEye HX Host Set Policies", t=for_table, headers=headers_for_table)

    return CommandResults(
        outputs_prefix="FireEyeHX.HostSets.Policy",
        outputs_key_field="_id",
        outputs=response["data"]["entries"],
        readable_output=md
    )


def assign_host_set_policy_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    hostSetId = args.get("hostSetId")
    policyId = args.get("policyId")

    if not policyId or not hostSetId:
        raise ValueError("policy ID and hostSetId are required")

    message = ""
    response = None
    try:
        response = client.assign_host_set_policy_request({
            "persist_id": hostSetId,
            "policy_id": policyId})
        message = "Success"
    except Exception as e:
        if '400' in str(e):
            message = "This hostset may already be included in this policy"
        else:
            raise ValueError(e)

    return CommandResults(
        readable_output=message,
        outputs_prefix="FireEyeHX.Policy",
        outputs=response
    )


def delete_host_set_policy_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    hostSetId = int(args.get('hostSetId', ''))
    policyId = args.get('policyId')

    message = ''
    try:
        client.delete_host_set_policy_request(hostSetId, policyId)
        message = 'Success'
    except Exception as e:
        if '404' in str(e):
            message = f'polisy ID - {policyId} or Host Set ID - {hostSetId} Not Found'
        else:
            raise ValueError(e)

    return CommandResults(readable_output=message)


"""
HOST INFORMAITION
"""


def get_all_hosts_information_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    offset = 0
    hosts = []

    while True:
        hosts_partial = client.get_hosts_request(offset=offset, limit=1000)
        if not hosts_partial["data"]["entries"]:
            break
        hosts.extend(hosts_partial["data"]["entries"])
        offset = len(hosts)

    outputs = []
    for host in hosts:
        outputs.append({
            'Host Name': host.get('hostname'),
            'Last Poll': host.get('last_poll_timestamp'),
            'Agent ID': host.get('_id'),
            'Agent Version': host.get('agent_version'),
            'Host IP': host.get('primary_ip_address'),
            'OS': host.get('os', {}).get('platform'),
            'Containment State': host.get('containment_state'),
            'Domain': host.get('domain'),
            'Last Alert': host.get('last_alert')
        })

    headers_for_table = ['Host Name', 'Host IP', 'Agent ID', 'Agent Version',
                         'OS', 'Last Poll', 'Containment State', 'Domain', 'Last Alert']
    md = tableToMarkdown(
        name="FireEye HX Get Hosts Information",
        t=outputs,
        headers=headers_for_table
    )

    return CommandResults(
        outputs_prefix="FireEyeHX.Hosts",
        outputs_key_field="_id",
        outputs=outputs,
        raw_response=hosts,
        readable_output=md
    )


def get_host_information_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    agentId = args.get("agentId")
    hostName = args.get("hostName")

    if not agentId and not hostName:
        raise ValueError("Please provide either agentId or hostName")

    host: Dict
    if agentId:
        try:
            host = client.get_hosts_by_agentId_request(agentId)["data"]
        except Exception:
            raise ValueError(f"agentId {agentId} is not correct")

    else:
        try:
            host = client.get_hosts_request(limit=1, host_name=hostName)["data"]["entries"][0]
        except Exception:
            raise ValueError(f"{hostName} is not found")

    headers_for_table = ['Host Name', 'Host IP', 'Agent ID', 'Agent Version',
                         'OS', 'Last Poll', 'Containment State', 'Domain', 'Last Alert']
    for_table = [{
        'Host Name': host.get('hostname'),
        'Last Poll': host.get('last_poll_timestamp'),
        'Agent ID': host.get('_id'),
        'Agent Version': host.get('agent_version'),
        'Host IP': host.get('primary_ip_address'),
        'OS': host.get('os', {}).get('platform'),
        'Containment State': host.get('containment_state'),
        'Domain': host.get('domain'),
        'Last Alert': host.get('last_alert')
    }]

    md = tableToMarkdown(
        name="FireEye HX Get Host Information",
        t=for_table,
        headers=headers_for_table
    )

    return CommandResults(
        outputs_prefix="FireEyeHX.Hosts",
        outputs_key_field="_id",
        outputs=host,
        readable_output=md
    )


def get_host_set_information_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    return host set information to the war room according to given id or filters

    """
    hostSetID = args.get('hostSetID')

    body = assign_params(
        limit=args.get('limit'),
        offset=args.get('offset'),
        search=args.get('search'),
        sort=args.get('sort'),
        name=args.get('name'),
        type=args.get('type')
    )

    response = client.get_host_set_information_request(body, hostSetID)

    host_set = []  # type: List[Dict[str, str]]
    try:
        if hostSetID:
            data = response['data']
            host_set = [data]
        else:
            data = response['data']
            host_set = data.get('entries', [])
    except Exception as e:
        LOG(e)
        raise ValueError('Failed to get host set information - unexpected response from the server.\n' + response.text)

    md_table = "No host sets found"
    if len(host_set) > 0:
        md_table = tableToMarkdown(
            name='FireEye HX Get Host Sets Information',
            t=host_set_entry(host_set),
            headers=['Name', 'ID', 'Type']
        )

    return CommandResults(
        outputs_prefix="FireEyeHX.HostSets",
        outputs_key_field="_id",
        outputs=host_set,
        readable_output=md_table
    )


"""
HOST CONTAINMENT
"""


def get_list_containment_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    stateUpdateTime = args.get("state_update_time", "")
    offset = args.get("offset")
    limit = args.get("limit")

    if not offset:
        offset = 0
    if not limit:
        limit = 50

    response = client.get_list_containment_request(offset, limit, stateUpdateTime)["data"]["entries"]

    for_table = []
    for entry in response:

        for_table.append({
            "Id": entry["_id"],
            "State": entry["state"],
            "Request Origin": entry["requested_by_actor"],
            "Request Date": entry["requested_on"],
            "Containment Origin": entry["contained_by_actor"],
            "Containment Date": entry["contained_on"],
            "Last System information date": entry["last_sysinfo"]
        })

    headers_for_table = ["Id", "State", "Request Origin", "Request Date",
                         "Containment Origin", "Containment Date", "Last System information date"]
    md = tableToMarkdown(name="List Containment", t=for_table, headers=headers_for_table)

    return CommandResults(
        outputs_prefix="FireEyeHX.Hosts",
        outputs_key_field="_id",
        outputs=response,
        readable_output=md
    )


def host_containment_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:

    agentId = args.get("agentId")
    hostName = args.get("hostName", "")

    if not agentId and not hostName:
        raise ValueError("Please provide either agentId or hostName")

    if not agentId:
        agentId = get_agent_id_by_host_name(client, hostName)

    try:
        client.host_containmet_request(agentId)
    except Exception:

        pass

    message = ""
    try:
        client.approve_containment_request(agentId)
        message = "Containment request for the host was sent and approved successfully"
    except Exception as e:
        if '422' in str(e):
            message = "You do not have the required permissions for containment approve\nThe containment request sent, but it is not approve."
        elif '409' in str(e):
            message = "This host may already in containment"
        else:
            raise ValueError(e)

    host = client.get_hosts_by_agentId_request(agentId)

    return [CommandResults(outputs_prefix="FireEyeHX.Hosts", outputs=host, readable_output=message),
            CommandResults(outputs_prefix="Endpoint", outputs=collect_endpoint_contxt(host["data"]))]


def approve_containment_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    agentId = args.get("agentId")

    if not agentId:
        raise ValueError("Agent ID is required")
    message = "Containment for the host was approved successfully"
    try:
        client.approve_containment_request(agentId)
    except Exception as e:
        if '409' in str(e):
            message = "This host may already in containment"
        else:
            message = "Containment for the host failed, check if you have the necessary permissions"

    return CommandResults(
        outputs_prefix="FireEyeHX.Hosts",
        readable_output=message
    )


def cancel_containment_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    agentId = args.get("agentId")
    hostName = args.get("hostName", "")

    if not agentId and not hostName:
        raise ValueError("One of the following arguments is required -> [agentId, hostName]")

    if not agentId:
        agentId = get_agent_id_by_host_name(client, hostName)

    message = "Success"
    try:
        client.cancel_containment_request(agentId)
    except Exception as e:
        if '409' in str(e):
            message = "This host may already in uncontain"
        else:
            raise ValueError(e)

    return CommandResults(readable_output=message)


"""
ACQUISITION
"""


def data_acquisition_command(client: Client, args: Dict[str, Any]) -> Tuple[CommandResults, bool, str]:

    if 'acquisition_id' not in args:
        acquisition_info = data_acquisition(client, args)
        acquisition_id = acquisition_info.get('_id')
        LOG('Acquisition request was successful. Waiting for acquisition process to be complete.')

    acquisition_id = args.get('acquisition_id') if args.get('acquisition_id') else acquisition_id
    acquisition_info = client.data_acquisition_information_request(acquisition_id)

    if acquisition_info.get('state') != 'COMPLETE':
        return CommandResults(
            readable_output=f'Acquisition request was successful\nAcquisition ID: {acquisition_id}'), False, str(acquisition_id)

    args['acquisition_info'] = acquisition_info
    return CommandResults(
        readable_output=f'Acquisition request was successful\nAcquisition ID: {acquisition_id}'), True, str(acquisition_id)


def data_acquisition_with_polling_command(client: Client, args: Dict[str, Any]):

    return run_polling_command(
        client,
        args,
        'fireeye-hx-data-acquisition',
        data_acquisition_command,
        result_data_acquisition,
        'acquisition')


def result_data_acquisition(client: Client, args: Dict[str, Any]) -> List:

    LOG('Acquisition process has been complete. Fetching mans file.')

    message = f'{args.get("fileName")} acquired successfully'
    if args.get('acquisition_info', {}).get('error_message'):
        message = args.get('acquisition_info', {}).get('error_message', '')

    # output file and acquisition information to the war room
    data = client.data_collection_request(args.get('acquisition_id'))

    return [CommandResults(
        outputs_prefix="FireEyeHX.Acquisitions.Data",
        outputs=args.get('acquisition_info', {}),
        readable_output=f'{message}\nacquisition ID: {args.get("acquisition_id")}'),
        fileResult(f'agent_{args.get("agentId")}_data.mans', data)]


def delete_data_acquisition_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    if "acquisitionId" not in args:
        raise ValueError("Acquisition Id is required")

    client.delete_data_acquisition_request(args.get("acquisitionId"))

    return CommandResults(
        readable_output=f"data acquisition {args.get('acquisitionId')} deleted successfully"
    )


def file_acquisition_command(client: Client, args: Dict[str, Any]) -> Tuple[CommandResults, bool, str]:

    if "acquisition_id" not in args:
        if not args.get('hostName') and not args.get('agentId'):
            raise ValueError('Please provide either agentId or hostName')

        if args.get('hostName'):
            args['agentId'] = get_agent_id_by_host_name(client, args.get('hostName', ""))

        use_api = args.get('acquireUsing') == 'API'

        acquisition_info = client.file_acquisition_request(
            args.get('agentId'),
            args.get('fileName'),
            args.get('filePath'),
            req_use_api=use_api
        )

        acquisition_id = acquisition_info.get('_id')

    LOG('acquisition request was successful. Waiting for acquisition process to be complete.')

    acquisition_id = args.get('acquisition_id') if args.get('acquisition_id') else str(acquisition_id)
    acquisition_info = client.file_acquisition_information_request(acquisition_id)
    state = acquisition_info.get('state')
    if state not in ['COMPLETE', 'ERROR', 'FAILED']:
        return CommandResults(
            readable_output=f'acquisition request was successful, Acquisition Id: {acquisition_id}'), False, acquisition_id

    args['acquisition_info'] = acquisition_info
    return CommandResults(
        readable_output=f'acquisition request was successful, Acquisition Id: {acquisition_id}'), True, acquisition_id


def file_acquisition_with_polling_command(client: Client, args: Dict[str, Any]):

    return run_polling_command(
        client,
        args,
        'fireeye-hx-file-acquisition',
        file_acquisition_command,
        result_file_acquisituon,
        'acquisition')


def result_file_acquisituon(client: Client, args: Dict[str, Any]) -> List:

    LOG('acquisition process has been complete. Fetching zip file.')

    acquired_file = client.file_acquisition_package_request(args.get('acquisition_id'))

    message = f"{args.get('fileName')} acquired successfully"
    if args.get('acquisition_info', {}).get('error_message'):
        message = args.get('acquisition_info', {}).get('error_message')

    return [CommandResults(
        outputs_prefix="FireEyeHX.Acquisitions.Files",
        outputs_key_field="_id",
        outputs=args.get('acquisition_info'),
        readable_output=f"{message}\nacquisition ID: {args.get('acquisition_id')}"
    ), fileResult(f"{os.path.splitext(args.get('fileName',''))[0]}.zip", acquired_file)]


def get_data_acquisition_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """
    Wait for acquisition process to complete and fetch the data
    """

    # validate the acquisitionId was passed
    if not args.get('acquisitionId'):
        raise ValueError('Please provide acquisitionId')

    acquisition_id = args.get("acquisitionId")

    acquisition_info = client.data_acquisition_information_request(acquisition_id)

    agent_id = acquisition_info.get('host').get('_id')
    host_info = client.get_hosts_by_agentId_request(agent_id)["data"]
    hostname = host_info.get('hostname')

    # Add hostname to the host info of acquisition_info
    acquisition_info["host"]["hostname"] = hostname
    # Add Integration Instance to the acquisition_info
    acquisition_info["instance"] = demisto.integrationInstance()

    # if `state` equals to 'COMPLETE'
    if acquisition_info.get('state') == 'COMPLETE':

        message = 'Acquisition completed successfully.'
        if acquisition_info.get('error_message'):
            message = acquisition_info.get('error_message')

        # output file and acquisition information to the war room
        data = client.data_collection_request(acquisition_id)

        return [CommandResults(
            outputs_prefix="FireEyeHX.Acquisitions.Data",
            outputs_key_field="_id",
            outputs=acquisition_info,
            readable_output=f"{message}\nacquisition ID: {acquisition_id}"
        ), fileResult('{}_agent_{}_data.mans'.format(acquisition_id, agent_id), data)]

    # else return message for states in [ NEW, ERROR, QUEUED, RUNNING, FAILED ]
    state = acquisition_info.get('state')

    message = "Acquisition process not yet completed."
    if acquisition_info.get('error_message'):
        message = acquisition_info.get('error_message')

    return [CommandResults(
        outputs_prefix="FireEyeHX.Acquisitions.Data",
        outputs_key_field="_id",
        outputs=acquisition_info,
        readable_output=f"{message}\nacquisition ID: {acquisition_id}\nstate: {state}"
    )]


def initiate_data_acquisition_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    acquisition_info: Dict = data_acquisition(client, args)

    # Add hostname to the host info of acquisition_info
    acquisition_info["host"]["hostname"] = args.get("hostName")

    # Add Integration Instance to the acquisition_info
    acquisition_info["instance"] = demisto.integrationInstance()

    return CommandResults(
        outputs_prefix="FireEyeHX.Acquisitions.Data",
        outputs=acquisition_info,
        readable_output=f'Acquisition ID: {acquisition_info.get("_id")} on Instance: {acquisition_info.get("instance")}'
    )


def delete_file_acquisition_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """

    returns a success message to the war room

    """
    acquisition_id = args.get('acquisitionId')
    client.delete_file_acquisition_request(acquisition_id)
    # successful request

    return CommandResults(readable_output=f'file acquisition {acquisition_id} deleted successfully')


"""
ALERTS
"""


def get_all_alerts_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """

    returns a list of alerts, all results up to limit

    """
    source = []
    # add source type
    if args.get('MALsource'):
        source.append('mal')
    if args.get('EXDsource'):
        source.append('exd')
    if args.get('IOCsource'):
        source.append('ioc')

    sort_map = {
        'agentId': 'agent._id',
        'conditionId': 'condition._id',
        'eventAt': 'event_at',
        'alertId': '_id',
        'matchedAt': 'matched_at',
        'id': '_id',
        'reportedAt': 'reported_at'
    }

    if args.get('sort'):
        args['sort'] = f"{sort_map.get(args['sort'])}+{args.get('sortOrder', 'ascending')}"

    if args.get('hostName'):
        args['agentId'] = get_agent_id_by_host_name(client, args.get('hostName', ''))

    if args.get('limit'):
        args['limit'] = int(args['limit'])
    else:
        args['limit'] = 50

    alerts = get_alerts(client, args)

    # parse each alert to a record displayed in the human readable table
    alerts_entries = [alert_entry(alert) for alert in alerts]

    headers_for_table = ['Alert ID', 'Reported', 'Event Type', 'Agent ID']
    md_table = tableToMarkdown(
        name='FireEye HX Get Alerts',
        t=alerts_entries,
        headers=headers_for_table
    )

    registry_key = []
    indicators = []
    for alert in alerts:
        if alert["event_type"] == 'regKeyEvent':
            registry_key.append({
                'Path': alert.get("event_values").get('regKeyEvent/path'),
                'Name': alert.get("event_values").get('regKeyEvent/valueName'),
                'Value': alert.get("event_values").get('regKeyEvent/value')
            })
        else:
            indicators.append(general_context_from_event(alert))

    results_outputs = assign_params(FireEyeHX={"Alerts": alerts}, RegistryKey=registry_key)

    return CommandResults(

        outputs_key_field="_id",
        outputs=results_outputs,
        readable_output=md_table,
        indicators=indicators
    )


def get_alert_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:

    alert_id = int(args.get('alertId', ""))
    alert: Dict = client.get_alert_request(alert_id)["data"]

    alertEntry = alert_entry(alert)
    headers_for_table = ['Alert ID', 'Reported', 'Event Type', 'Agent ID']

    alert_table = tableToMarkdown(
        name=f'FireEye HX Get Alert # {alert_id}',
        t=alertEntry,
        headers=headers_for_table
    )

    event_type = alert.get('event_type')
    event_type = 'NewEvent' if not event_type else event_type
    event_type = re.sub("([a-z])([A-Z])", "\g<1> \g<2>", event_type).title()
    event_table = tableToMarkdown(
        name=event_type,
        t=alert.get('event_values')
    )

    result = [CommandResults(
        outputs_prefix="FireEyeHX.Alerts",
        outputs_key_field="_id",
        outputs=alert,
        readable_output=f'{alert_table}\n{event_table}'
    )]

    indicator = organization_of_indicator(alert)
    if indicator:
        result.append(indicator)

    return result


def suppress_alert_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """

    returns a success message to the war room

    """

    alert_id = int(args.get('alertId', ''))

    try:
        client.suppress_alert_request(alert_id)
    except Exception as e:
        if '404' in str(e):
            raise ValueError(f"Alert {alert_id} Not Found")
        else:
            raise ValueError(e)

    # no exceptions raised->successful request
    return CommandResults(
        readable_output=f'Alert {alert_id} suppressed successfully.'
    )


"""
INDICATORS
"""


def get_indicators_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    sort_map = {
        'category': 'category',
        'activeSince': 'active_since',
        'createdBy': 'created_by',
        'alerted': 'stats.alerted_agents'
    }

    if args.get('limit'):
        args['limit'] = int(args['limit'])
    if args.get('alerted'):
        args['alerted'] = args['alerted'] == 'yes'
    if args.get('sort'):
        args['sort'] = sort_map.get(args.get('sort', ''))

    # get all results
    indicators = get_all_indicators(
        client=client,
        category=args.get('category'),
        search=args.get('searchTerm'),
        share_mode=args.get('shareMode'),
        sort=args.get('sort'),
        created_by=args.get('createdBy'),
        alerted=args.get('alerted'),
        limit=args.get('limit')
    )

    for_table = [indicator_entry(indicator) for indicator in indicators]

    headers_for_table = ['OS', 'Name', 'Created By', 'Active Since', 'Category', 'Signature', 'Active Condition',
                         'Hosts With Alerts', 'Source Alerts']

    md_table = tableToMarkdown(
        name=f"FireEye HX Get Indicator- {args.get('name')}",
        t=for_table,
        headers=headers_for_table
    )

    return CommandResults(
        outputs_prefix="FireEyeHX.Indicators",
        outputs_key_field="_id",
        outputs=indicators,
        readable_output=md_table
    )


def get_indicator_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:

    if not args.get("category") or not args.get("name"):
        raise ValueError("The category and name arguments are required")

    indicator = client.get_indicator_request(
        args.get('category'),
        args.get('name')
    )

    headers_for_table = ['OS', 'Name', 'Created By', 'Active Since', 'Category', 'Signature',
                         'Active Condition', 'Hosts With Alerts', 'Source Alerts']

    md_table = tableToMarkdown(
        name=f"FireEye HX Get Indicator- {args.get('name')}",
        t=indicator_entry(indicator),
        headers=headers_for_table
    )

    return [CommandResults(
        outputs_prefix="FireEyeHX.Indicators",
        outputs_key_field="_id",
        outputs=indicator,
        readable_output=md_table
    ), get_indicator_conditions(client, args)]


def append_conditions_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Append conditions to indicator
    no return value on successfull request
    """
    name = args.get('name')
    category = args.get('category')
    body = args.get('condition')

    if not name or not category or not body:
        raise ValueError("All of the following arguments are required -> ['name','category','condition']")

    body = body.replace(',', '\n')

    response = client.append_conditions_request(name, category, body)

    md = tableToMarkdown(name="The conditions were added successfully", t={
        'Name': name,
        'Category': category,
        'Conditions': body
    })

    return CommandResults(
        outputs_prefix="FireEyeHX.Conditions",
        outputs=response,
        readable_output=md
    )


def create_indicator_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Get new indicator details
    returns a success message to the war room
    """

    category = args.get('category')

    response = client.new_indicator_request(category)["data"]

    md_table = tableToMarkdown('FireEye HX New Indicator created successfully', {'ID': response.get('_id')})

    return CommandResults(
        outputs_prefix="FireEyeHX.Indicators",
        outputs_key_field="_id",
        outputs=response,
        readable_output=md_table
    )


"""
SEARCHES
"""


def start_search_command(client: Client, args: Dict[str, Any]) -> Tuple[CommandResults, bool, str]:

    if 'searchId' not in args:
        listOfArgs = ["agentsIds", "hostsNames", "hostSet", "hostSetName"]
        arg = oneFromList(listOfArgs=listOfArgs, **args)
        if arg is False:
            raise ValueError("One of the following arguments is required -> [agentsIds, hostsNames, hostSet, hostSetName]")

        # orgenized the search body, the function checks if provided only one argument,
        # and returns dict with key of Host_name or Hosts
        body = organize_search_body_host(client, arg, {})

        # checking if provided only one of these following arguments
        listOfArgs = ['dnsHostname', 'fileFullPath', 'fileMD5Hash', 'ipAddress', 'fieldSearchName']
        argForQuery = oneFromList(listOfArgs=listOfArgs, **args)
        if argForQuery is False:
            raise ValueError("One of the following arguments is required -> [dnsHostname, fileFullPath, fileMD5Hash, ipAddress, fieldSearchName]")

        # this function organize the query of the request body, and returns list of queries
        body["query"] = organize_search_body_query(argForQuery, **args)
        body["exhaustive"] = False if args.get("exhaustive") == "false" else True

        try:
            searchId = client.search_request(body)["data"]["_id"]
        except Exception as e:
            raise ValueError(e)

    if not args.get("limit"):
        args['limit'] = 1000

    searchId = str(args.get('searchId')) if args.get('searchId') else str(searchId)
    searchInfo = client.get_search_by_id_request(searchId)["data"]
    matched = searchInfo.get('stats', {}).get('search_state', {}).get('MATCHED', 0)
    pending = searchInfo.get('stats', {}).get('search_state', {}).get('PENDING', 0)

    if searchInfo.get("state") != "STOPPED" and matched < int(args.get('limit', '')) and pending != 0:

        return CommandResults(readable_output=f"Search started,\nSearch ID: {searchId}"), False, searchId

    return CommandResults(readable_output=f"Search started,\nSearch ID: {searchId}"), True, searchId


def start_search_with_polling_command(client: Client, args: Dict[str, Any]) -> Union[CommandResults, List[CommandResults]]:

    return run_polling_command(
        client,
        args,
        'fireeye-hx-search',
        start_search_command,
        search_result_get_command,
        'searching')


def get_search_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    if args.get("searchId"):

        searchesIds = sorted(args.get("searchId", "").split(","), reverse=True)
        response = []
        for searchId in searchesIds:
            response.append(client.get_search_by_id_request(searchId)["data"])

    else:

        offset = args.get("offset") or 0
        limit = args.get("limit") or 50
        state = args.get("state")
        hostSetId = args.get("hostSetId")
        actorUsername = args.get("actorUsername")
        sort = args.get("sort")

        response = client.get_search_list_request(
            offset=offset,
            limit=limit,
            state=state,
            hostSetId=hostSetId,
            actorUsername=actorUsername,
            sort=sort
        )["data"]["entries"]

    for_table = []
    for search in response:
        host_set = None
        if search.get("host_set"):
            host_set = search["host_set"].copy()
            del host_set["url"]
        for_table.append(
            {
                "Id": search.get("_id"),
                "State": search.get("state"),
                "Host Set": host_set,
                "Created By": search.get("create_actor"),
                "Created At": search.get("create_time"),
                "Updated By": search.get("update_actor"),
                "Updated At": search.get("update_time")
            }
        )

    headers_for_table = ["Id", "State", "Host Set", "Created By", "Created At", "Updated By", "Updated At"]
    md = tableToMarkdown(
        name="",
        t=for_table,
        headers=headers_for_table
    )

    return CommandResults(
        outputs_prefix="FireEyeHX.Search",
        outputs_key_field="_id",
        outputs=response,
        readable_output=md
    )


def search_stop_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    if not args.get("searchId"):
        raise ValueError("Search Id is must be")

    searchesIds = str(args.get("searchId")).split(",")
    responses = []
    md = ""
    for searchId in searchesIds:
        try:
            response = client.search_stop_request(searchId)
            md += f"\n{searchId} : Success"
            responses.append(response["data"])
        except Exception:
            md += f"\n{searchId} : Not Found"

    return CommandResults(
        outputs_prefix="FireEyeHX.Search",
        outputs_key_field="_id",
        outputs=responses,
        readable_output=md
    )


def search_result_get_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:

    if not args.get("searchId"):
        raise ValueError("Search Id is must be")

    searchesIds = str(args.get("searchId")).split(",")

    results: List[List[Dict]] = []
    for searchId in searchesIds:
        result = client.search_result_get_request(searchId)["data"]["entries"]
        if result:
            results.append(result)

    commandsResults: List = []
    for result in results:
        for entry in result:
            Title = f"Host Id {entry.get('host', {}).get('_id')}\nHost Name {entry.get('host', {}).get('hostname')}"
            for_table = []
            for res in entry.get("results", []):
                for_table.append({
                    "Item Type": res.get("type"),
                    "Summary": [f"**{k}:** {v}" for k, v in res.get("data", {}).items()]
                })

            md = tableToMarkdown(
                name=Title,
                t=for_table,
                headers=["Item Type", "Summary"]
            )

            commandsResults.append(CommandResults(
                outputs_prefix="FireEyeHX.Search",
                outputs_key_field="_id",
                outputs=entry,
                readable_output=md
            ))

    if 'stopSearch' in args:
        try:
            if args.get('stopSearch') == 'stop':
                message = 'Failed to stop search'
                client.search_stop_request(searchesIds[0])
                message = "The search was stopped successfully"
            # no need to stop a search before deleting it.
            if args.get('stopSearch') == 'stopAndDelete':
                message = 'Failed to delete search'
                client.delete_search_request(searchesIds[0])
                message = "The search was deleted successfully"
        except Exception as e:
            LOG('{}\n{}'.format(message, e))
        commandsResults[0].readable_output += f"\n\n{message}"

    return commandsResults if commandsResults else [CommandResults(readable_output="No Results")]


def search_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    searchIds = str(args.get('searchId')).split(',')

    message = 'Results'
    for searchId in searchIds:

        try:
            client.delete_search_request(searchId)
            message += f'\nSearch Id {searchId}: Deleted successfully'
        except Exception as e:
            if '404' in str(e):
                message += f'\nSearch Id {searchId}: Not Found'
            else:
                message += f'\nSearch Id {searchId}: Failed to delete search'

    return CommandResults(readable_output=message)


"""
FETCH INCIDENT
"""


def fetch_incidents(client: Client, args: Dict[str, Any]) -> List:

    last_run = demisto.getLastRun()
    alerts = []  # type: List[Dict[str, str]]
    fetch_limit = int(args.get('max_fetch') or '50')

    args["sort"] = "reported_at+ascending"
    args["limit"] = fetch_limit

    # Checks if this is the first call to a function or not
    if last_run and last_run.get('reported_at'):

        # Design the filterQuery argument with last reported_at, and convert it to urlEncoding
        query = query_fetch(reported_at=organize_reportedAt(last_run.get('reported_at')))
        args["filterQuery"] = urllib.parse.quote_plus(query)

        # Get all alerts with reported_at greater than last reported_at
        alerts = get_alerts(client, args)

        # Results are sorted in ascending order - the last alert holds the greatest time *********
        reported_at = alerts[-1].get("reported_at") if alerts else None

    else:
        # Design the filterQuery argument, and convert it to urlEncoding
        first_fetch = args.get("first_fetch") if args.get("first_fetch") else "3 days"
        query = query_fetch(first_fetch=first_fetch)
        args["filterQuery"] = urllib.parse.quote_plus(query)

        # Receive alerts from last 3 days - if they are more than 50 return the 50 older alerts
        alerts = get_alerts(client, args)

        # Results are sorted in ascending order - the last alert holds the greatest time
        reported_at = alerts[-1].get("reported_at") if alerts else None

    # Parse the alerts as the incidents
    incidents = [parse_alert_to_incident(alert) for alert in alerts]

    # Keeps the last reported_at for next time
    if reported_at is not None:
        demisto.setLastRun({'reported_at': reported_at})

    return incidents


''' POLLING '''


def run_polling_command(client, args, cmd, post_func, get_func, t):

    _, is_ready, item_id = post_func(client, args)
    if not is_ready:
        type_id = TABLE_POLLING_COMMANDS[t]['type']
        readable_output = f"{TABLE_POLLING_COMMANDS[t]['message']}{item_id}" if type_id not in args else None
        if not args.get(type_id):
            args[type_id] = item_id
        scheduled_command = ScheduledCommand(
            command=cmd,
            next_run_in_seconds=60,
            args=args,
            timeout_in_seconds=1800)
        # result with scheduled_command only - no update to the war room
        return CommandResults(readable_output=readable_output, scheduled_command=scheduled_command)

    return get_func(client, args)


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    polling_commands = {
        "fireeye-hx-search": start_search_with_polling_command,
        "fireeye-hx-data-acquisition": data_acquisition_with_polling_command,
        "fireeye-hx-file-acquisition": file_acquisition_with_polling_command
    }

    commands = {

        "fireeye-hx-get-host-information": get_host_information_command,
        "fireeye-hx-get-all-hosts-information": get_all_hosts_information_command,
        "fireeye-hx-host-containment": host_containment_command,
        "fireeye-hx-cancel-containment": cancel_containment_command,
        "fireeye-hx-get-host-set-information": get_host_set_information_command,
        "fireeye-hx-search": start_search_command,
        "fireeye-hx-search-list": get_search_list_command,
        "fireeye-hx-search-stop": search_stop_command,
        "fireeye-hx-search-result-get": search_result_get_command,
        "fireeye-hx-search-delete": search_delete_command,
        "fireeye-hx-append-conditions": append_conditions_command,
        "fireeye-hx-get-indicators": get_indicators_command,
        "fireeye-hx-get-indicator": get_indicator_command,
        "fireeye-hx-create-indicator": create_indicator_command,
        "fireeye-hx-data-acquisition": data_acquisition_command,
        "fireeye-hx-delete-data-acquisition": delete_data_acquisition_command,
        "fireeye-hx-file-acquisition": file_acquisition_command,
        "fireeye-hx-delete-file-acquisition": delete_file_acquisition_command,
        "fireeye-hx-get-data-acquisition": get_data_acquisition_command,
        "fireeye-hx-initiate-data-acquisition": initiate_data_acquisition_command,
        "fireeye-hx-get-alert": get_alert_command,
        "fireeye-hx-get-alerts": get_all_alerts_command,
        "fireeye-hx-suppress-alert": suppress_alert_command,
        "fireeye-hx-list-policy": list_policy_command,
        "fireeye-hx-list-host-set-policy": list_host_set_policy_command,
        "fireeye-hx-assign-host-set-policy": assign_host_set_policy_command,
        "fireeye-hx-delete-host-set-policy": delete_host_set_policy_command,
        "fireeye-hx-approve-containment": approve_containment_command,
        "fireeye-hx-list-containment": get_list_containment_command

    }

    params = demisto.params()
    userName = params.get("userName").get('identifier')
    password = params.get("userName").get('password')
    if not userName or not password:
        raise ValueError("User Name and Password are required")

    # get the service API url
    base_url = urljoin(params.get('server'), '/hx/api/v3/')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get('proxy', False)
    command = demisto.command()
    args = demisto.args()

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            auth=(userName, password))

        if command == 'test-module':
            get_alerts(client, {"limit": 1})
            return_results('ok')
        elif command == 'fetch-incidents':
            incidents = fetch_incidents(client, params)
            demisto.incidents(incidents)
        elif args.get('polling', 'false') == 'true':
            result = polling_commands[command](client, args)
            return_results(result)
        elif command in ["fireeye-hx-search", "fireeye-hx-data-acquisition", "fireeye-hx-file-acquisition"]:
            result, _, _ = commands[command](client, args)
            return_results(result)
        else:
            result = commands[command](client, args)
            return_results(result)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):

    main()
