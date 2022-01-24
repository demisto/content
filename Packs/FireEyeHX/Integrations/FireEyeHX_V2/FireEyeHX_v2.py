"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS ""

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""

# from Tests.demistomock.demistomock import args, command, params

# from os import name
# from sys import _OptExcInfo


from xml.dom import ValidationErr
from requests.adapters import Response
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
# from CommonServerUserPython import *  # noqa

import base64
import json
import os
import re
import time

import requests
import traceback
from typing import Dict, Any, Tuple

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

STANDART_INVESTIGATIVE_DETAILS_OSX = {
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


''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """
    def __init__(self, base_url, verify=True, proxy=False, ok_codes=..., auth=None):
            
        headers={'X-FeApi-Token':self.get_token_request(base_url,verify,auth)}

        super().__init__(base_url, verify=False, proxy=proxy, ok_codes=range(200,205), headers=headers, auth=auth)
    
    
    def get_token_request(self,base_url,verify,auth):
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
        except:
            
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

    def list_policy_request(self, offset:int, limit:int, policy_id:str=None, name:str=None,  enabled:bool = None):
        
        params=assign_params(_id=policy_id, name=name, offset=offset, limit=limit, enabled=enabled)

        return self._http_request(
            method='GET',
            url_suffix='policies',
            params=params,
            )


    def list_host_set_policy_request(self, offset:int, limit:int, policyId:str=''):
              
        params=assign_params(_policy_id=policyId, offset=offset, limit=limit)

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


    def assign_host_set_policy_request(self, body:Dict[str,Any]):

        return self._http_request(
            method="POST",
            url_suffix="host_set_policies",
            json_data=body,
            return_empty_response=True)

    """
    HOST INFORMATION REQUEST
    """

    def get_hosts_by_agentId_request(self, agentId:str):

        return self._http_request(
            method="GET",
            url_suffix=f"hosts/{agentId}",
            
        )


    def get_hosts_request(self, limit=None, offset=None, has_active_threats=None, has_alerts=None,
                      agent_version=None, containment_queued=None, containment_state=None,
                      host_name=None, os_platform=None, reported_clone=None, time_zone=None):

        params =assign_params(
            limit = limit,
            offset = offset,
            has_active_threats = has_active_threats,
            has_alerts = has_alerts,
            agent_version = agent_version,
            containment_queued = containment_queued,
            containment_state = containment_state,
            hostname = host_name,
            reported_clone = reported_clone,
            time_zone = time_zone)

        if os_platform:
            params['os.platform'] =  os_platform

        return self._http_request(
            method="GET",
            url_suffix="hosts",
            params=params,
            headers=self._headers
            )
    

    def get_host_set_information_request(self, body, hostSetId):

        url= f"host_sets/{hostSetId}" if hostSetId else "host_sets"
        return self._http_request(
            method ='GET',
            url_suffix=url,
            params=body
        )
        
    """
    HOST CONTAINMENT REQUESTS
    """

    def host_containmet_request(self, agentId:str):
 
        self._http_request(
            method="POST",
            url_suffix=f"hosts/{agentId}/containment",
            )
        

    def approve_containment_request(self,agentId:str):

        return self._http_request(
            method="PATCH",
            url_suffix=f"hosts/{agentId}/containment",
            json_data={"state": "contain"},
            return_empty_response=True
        )
    

    def cancel_containment_request(self, agentId:str):

        self._http_request(
            method="DELETE",
            url_suffix=f"hosts/{agentId}/containment",
            return_empty_response=True
        )
        

    def get_list_containment_request(self, offset:int, limit:int, stateUpdateTime:str):

        params=assign_params(offset=offset,limit=limit,stateUpdateTime=stateUpdateTime)

        return self._http_request(
            method="GET",
            url_suffix="containment_states",
            params=params
        )
        
    """
    ACQUISITION REQUEST
    """

    def data_acquisition_request(self, agentId:str, body:Dict):

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

        body = assign_params(req_path = file_path, req_filename = file_name,
                             comment = comment, external_id = external_id, req_use_api = req_use_api)

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
                       event_at=None, alert_id=None, matched_at=None, reported_at=None, source=None):
        """

        returns the response body on successful request

        """

        params =assign_params( 
            has_share_mode = has_share_mode,
            resolution = resolution,
            event_at = event_at,
            min_id = min_id,
            _id = alert_id,
            matched_at = matched_at,
            reported_at = reported_at,
            source = source,
            limit = limit,
            offset = offset,
            sort = sort
            )

        if agent_id:
            params["agent._id"] = agent_id
        if condition_id:
            params["condition._id"] = condition_id

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


    def get_alert_request(self, alert_id:int):

        return self._http_request(
            method='GET',
            url_suffix=f'/alerts/{alert_id}',
            headers=self._headers
        )
        

    def suppress_alert_request(self, alert_id:int):
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
            raise ValueError(f"The indecator '{name}' {e.res.reason}")


    def get_indicators_request(self, params):

        response = self._http_request(
            method='GET',
            url_suffix="/indicators" if not params.get("category") else f"/indicators/{params.get('category')}",
            params=params,
            )
        try:
            
            data = response['data']
            # no results found
            if data['total'] == 0:
                return None
            return data['entries']
        except Exception as e:
            LOG(e)
            raise ValueError('Failed to parse response body')


    def get_indicator_conditions_request(self, category, name, offset):
        
        """
        returns a list of json objects, each representing an indicator condition
        if no results are found- returns None

        """
        url = f'/indicators/{category}/{name}/conditions'
        params = {'offset': offset, 'enabled': True}

        
        try:
            return self._http_request(
                method='GET',
                url_suffix=f'/indicators/{category}/{name}/conditions',
                params=params
                )['data']['entries']
        
        except Exception as e:
            LOG(e)
            raise ValueError('Failed to parse response body')


    def append_conditions_request(self, name:str, category:str, body:str):

        return self._http_request(
            method="PATCH",
            url_suffix=f"/indicators/{category}/{name}/conditions",
            data=body,
            return_empty_response=True
            )

    """
    SEARCHES REQUEST
    """

    def get_search_by_id_request(self, searchId: int):

        return self._http_request(
            method="GET",
            url_suffix=f"searches/{searchId}"  
        )
        

    def get_search_list_request(self, offset: int, limit: int, state: str = None, hostSetId : int = None, actorUsername : str = None, sort : str = None):

        params = assign_params(offset=offset, limit= limit, hostSetId= hostSetId, actorUsername= actorUsername, state= state, sort=sort)

        return self._http_request(
            method='GET',
            url_suffix="searches",
            params=params
        )


    def search_stop_request(self, searchId : str):

        
        return self._http_request(
            method="POST",
            url_suffix=f"searches/{searchId}/actions/stop",   
            )


    def delete_search_request(self, search_id):
        """

        no return value on successful request

        """
        
        self._http_request(
            method = 'DELETE',
            url_suffix = f"searches/{search_id}",
            return_empty_response = True
        )


    def search_result_get_request(self, searchId : str):

        return self._http_request(
            method="GET",
            url_suffix=f"searches/{searchId}/results",
            )


    def search_request(self, body:Dict):

        return self._http_request(
                method="POST",
                url_suffix="searches",
                json_data=body
                )
        


''' HELPER FUNCTIONS '''

def get_alerts(client:Client, args:Dict[str,Any])->List:

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
            sort=args.get("sort")
        )
        # empty list
        if not alerts_partial_results['data']['entries']:
            break
        alerts.extend(alerts_partial_results['data']['entries'])
        offset = len(alerts)

    # remove access results
    if len(alerts) > max_records:
        alerts[int(max_records) - 1: -1] = []

    return alerts


def get_agent_id_by_host_name(client:Client, hostName:str):

    return client.get_hosts_request(host_name=hostName,limit=1)["data"]["entries"][0]["_id"]


def host_set_entry(host_sets: List[Dict])->List[Dict]:
    return [{
        'Name': host_set.get('name'),
        'ID': host_set.get('_id'),
        'Type': host_set.get('type')
    } for host_set in host_sets]


def general_context_from_event(alert:Dict):

    def file_context(values:Dict):

        return {
            'Name': values.get('fileWriteEvent/fileName'),
            'MD5': values.get('fileWriteEvent/md5'),
            'Extension': values.get('fileWriteEvent/fileExtension'),
            'Path': values.get('fileWriteEvent/fullPath')
        }

    def ip_context(values:Dict):

        return {
            'Address': values.get('ipv4NetworkEvent/remoteIP')
        }

    def registry_key_context(values:Dict):

        return {
            'Path': values.get('regKeyEvent/path'),
            'Name': values.get('regKeyEvent/valueName'),
            'Value': values.get('regKeyEvent/value')
        }
    context_map = {
        'fileWriteEvent': file_context,
        'ipv4NetworkEvent': ip_context,
        'regKeyEvent': registry_key_context
    }

    if context_map.get(alert['event_type']) is not None:
        f = context_map[alert['event_type']]
        return f(alert['event_values'])
    return None


def parse_alert_to_incident(alert:Dict):#******************

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
        'occurred': alert.get("event_at").replace('T',' ').replace('Z',' '),
        'rawJSON': json.dumps(alert)
    }
    return incident


def oneFromList(listOfArgs,**args):

        checker = 0
        for arg in listOfArgs:
            if args.get(arg):
                checker += 1
                result = (arg, args.get(arg))

        return result if checker == 1 else False


def organize_search_body_host(client: Client, arg: Tuple, body:Dict):
        if arg[0] == "hostsNames":
            hostsNames = arg[1].split(",")
            agentsIds = []
            for hostName in hostsNames:
                try:
                    agentsIds.append({"_id": get_agent_id_by_host_name(client,hostName)})
                except:
                    raise ValueError(f"Host Name {hostName} is not valid")

            body["hosts"] = agentsIds

        elif arg[0] == "agentsIds":
            agentsIds = arg[1].split(",")
            agentsIds = [{"_id": agentId} for agentId in agentsIds]
            body["hosts"] = agentsIds

        elif arg[0] == "hostSetName":
            hostSet = {"_id": client.get_host_set_information_request({"name":arg[1]}, None)["data"]["entries"][0]["_id"]}
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
            
            for searchValue in args.get("fieldSearchValue").split(","):
                query.append(assign_params(field= argForQuery[1], operator= args.get("fieldSearchOperator"), value = searchValue))

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
                query.append(assign_params(field= arg_to_query_field_map[argForQuery[0]],
                                            operator= args.get(f"{argForQuery[0]}Operator"),
                                            value = searchValue)
                            )

        return query
    

def collect_context(alerts:List[Dict]):

    # collect_context
    files = []
    ips = []
    registry_keys = []

    for alert in alerts:
        event_type = alert.get('event_type')
        context = general_context_from_event(alert)
        if event_type == 'fileWriteEvent':
            files.append(context)
        elif event_type == 'ipv4NetworkEvent':
            ips.append(context)
        elif event_type == 'regKeyEvent':
            registry_keys.append(context)
    return (files, ips, registry_keys)


def collect_endpoint_contxt(host:Dict):

    return {
        'Hostname': host.get('hostname'),
        'ID': host.get('_id'),
        'IPAddress': host.get('primary_ip_address'),
        'Domain': host.get('domain'),
        'MACAddress': host.get('primary_mac'),
        'OS': host.get('os', {}).get('platform'),
        'OSVersion': host.get('os', {}).get('product_name')
    }


def data_acquisition(client:Client, args:Dict[str,Any])->Dict:

    hostName=args.get("hostName")
    agentId=args.get("agentId")
    script=args.get("script")
    scriptName=args.get("scriptName")
    defaultSystemScript=args.get("defaultSystemScript")

    if not hostName and not agentId:
        raise ValueError('Please provide either agentId or hostName')
    
    if not defaultSystemScript and not script:
        raise ValueError('If the script is not provided, defaultSystemScript must be specified.')

    if script and not scriptName:
        raise ValueError('If the script is provided, script name must be specified as well.')
    
    if not agentId:
        agentId=get_agent_id_by_host_name(client,hostName)
    
    # determine whether to use the default script
    sys = defaultSystemScript
    if sys:
        script = json.dumps(SYS_SCRIPT_MAP[sys])
        scriptName = f'{sys}DefaultScript'
    
    body = {
        'name': scriptName,
        'script': {'b64': base64.b64encode(bytes(script, 'utf-8')).decode()}
    }
    
    return client.data_acquisition_request(agentId,body)["data"]


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


def condition_entry(condition):

    indicator_entry = {
        'Event Type': condition.get('event_type'),
        'Operator': condition.get('tests', {})[0].get('operator'),
        'Value': condition.get('tests', {})[0].get('value'),

    }
    return indicator_entry


def get_all_indicators(client:Client, category=None, search=None, share_mode=None, sort=None, created_by=None, alerted=None, limit=None):

    max_records = limit or float('inf')
    indicators = []   # type: List[Dict[str, str]]

    params = assign_params(category=category, search=search,sort=sort, created_by=created_by,offset=0, limit=limit or 100)

    if share_mode:
        params["category.share_mode"] = share_mode

    if alerted:
        params["stats.alerted_agents"] = share_mode

    # get all results
    while len(indicators) < max_records:
        indicators_partial_results = client.get_indicators_request(params)
        if not indicators_partial_results:
            break
        indicators.extend(indicators_partial_results)
        params["offset"] = len(indicators)

    # remove access results
    if len(indicators) > max_records:
        indicators[int(max_records) - 1: -1] = []

    return indicators


def get_all_enabled_conditions(client:Client, indicator_category, indicator_name):

    offset = 0
    conditions = []   # type: List[Dict[str, str]]

    # get all results
    while True:
        conditions_partial_results = client.get_indicator_conditions_request(
            indicator_category,
            indicator_name,
            offset=offset
        )
        if not conditions_partial_results:
            break
        conditions.extend(conditions_partial_results)
        offset = len(conditions)
    return conditions


def get_indicator_conditions(client:Client, args:Dict[str,Any])->CommandResults:
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
        name = f"Indicator '{args.get('name')}' Alerts on",
        t=conditions_entries
    )

    return CommandResults(
        outputs_prefix="FireEyeHX.Conditions",
        outputs_key_field="_id",
        outputs=conditions,
        readable_output= md_table
    )
    

''' COMMAND FUNCTIONS '''

"""
POLICIES
"""

def list_policy_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    
    offset = args.get('offset')
    limit = args.get('limit')
    name = args.get('policyName')
    policy_id = args.get('policyId')
    enabled=args.get('enabled')

    if name and policy_id:
        raise ValueError("Enter a name or ID but not both")

    if not limit:
        limit = 50 # default value
    if not offset:
        offset = 0 # default value

    
    response = client.list_policy_request(offset=offset, limit=limit, policy_id=policy_id, name=name, enabled=enabled )
    
    for_table=[]
    for entry in response['data']["entries"]:
        for_table.append({"Policy Id":entry["_id"],
                        "Policy Name":entry["name"],
                        "Description":entry["description"],
                        "Priority":entry["priority"],
                        "Enabled":entry["enabled"]})
    headers_for_table=["Policy Id","Policy Name","Description","Priority","Enabled"]

    md=tableToMarkdown(name="FireEye HX List Policies",t=for_table,headers=headers_for_table)

    command_results = CommandResults(

        outputs_prefix='FireEyeHX.Policy',
        outputs_key_field='_id',
        outputs=response,
        raw_response=response,
        readable_output=md   
       )

    return command_results


def list_host_set_policy_command(client:Client, args:Dict[str,Any])->CommandResults:#*************not finished**********
    

    offset=args.get("offset")
    limit=args.get("limit")
    hostSetId=args.get("hostSetId")
    policyId=args.get("policyId")

    if hostSetId and policyId:
        raise("Enter a Policy Id or Host Set Id but not both")

    if not offset:
        offset=0
    if not limit:
        limit=50
    
    if hostSetId:
        response=client.list_host_set_policy_by_hostSetId_request(hostSetId)
    else:
        response=client.list_host_set_policy_request(offset, limit, policyId)

    for_table=[]
    for entry in response["data"]["entries"]:
        for_table.append({
            "Policy Id":entry["persist_id"],
            "Host Set Id":entry["policy_id"]
        })
    headers_for_table=["Policy Id","Host Set Id"]
    md=tableToMarkdown(name="FireEye HX Host Set Policies",t=for_table,headers=headers_for_table)

    return CommandResults(
        outputs_prefix="FireEyeHX.HostSets.Policy",
        #***what is key field***********
        outputs=response["data"]["entries"],
        readable_output=md
    )

    
def assign_host_set_policy_command(client:Client, args:Dict[str,Any])->CommandResults:

    hostSetId=args.get("hostSetId")
    policyId=args.get("policyId")

    if not policyId or not hostSetId:
        raise ValueError("policy ID and hostSetId are required")
    
    response=client.assign_host_set_policy_request({
        "persist_id":hostSetId,
         "policy_id":policyId})

    return CommandResults(
        readable_output="Success" if response['message']=="OK" else f"Failure \n {response['message']}",
        outputs_prefix="FireEyeHX.Policy",
        outputs=response
    )
    

def get_list_containment_command(client:Client,args:Dict[str,Any])->CommandResults:

    stateUpdateTime=args.get("state_update_time")
    offset=args.get("offset")
    limit=args.get("limit")

    if not offset:
        offset=0
    if not limit:
        limit=50
    
    response=client.get_list_containment_request(offset,limit,stateUpdateTime)["data"]["entries"]

    for_table=[]
    for entry in response:

        for_table.append({
            "Id":entry["_id"],
            "State":entry["state"],
            "Request Origin":entry["requested_by_actor"],
            "Request Date":entry["requested_on"],
            "Containment Origin":entry["contained_by_actor"],
            "Containment Date":entry["contained_on"],
            "Last System information date":entry["last_sysinfo"]
            })
    
    headers_for_table=["Id","State","Request Origin","Request Date","Containment Origin","Containment Date","Last System information date"]
    md=tableToMarkdown(name="List Containment", t=for_table, headers=headers_for_table)

    return CommandResults(
        outputs_prefix="FireEyeHX.Hosts",
        outputs_key_field="_id",
        outputs=response,
        readable_output=md
    )

"""
HOST INFORMAITION
"""

def get_all_hosts_information_command(client:Client,args:Dict[str,Any])->CommandResults:


    offset = 0
    hosts = []

    while True:
        hosts_partial=client.get_hosts_request(offset=offset,limit=1000)
        if not hosts_partial["data"]["entries"]:
            break
        hosts.extend(hosts_partial["data"]["entries"])
        offset=len(hosts)
    
    outputs=[]
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
    
    headers_for_table=['Host Name', 'Host IP', 'Agent ID', 'Agent Version', 'OS', 'Last Poll', 'Containment State', 'Domain', 'Last Alert']
    md=tableToMarkdown(
        name = "FireEye HX Get Hosts Information",
        t = outputs,
        headers = headers_for_table
    )

    return CommandResults(
        outputs_prefix="FireEyeHX.Hosts",
        outputs_key_field="",#**************
        outputs=outputs,
        readable_output=md
    )
    

def get_host_information_command(client:Client, args:Dict[str,Any])->CommandResults:

    agentId=args.get("agentId")
    hostName=args.get("hostName")


    if not agentId and not hostName:
        raise ValueError("Please provide either agentId or hostName")#**********
    
    if agentId:
        try:
            host=client.get_hosts_by_agentId_request(agentId)["data"]
        except:
            raise ValueError(f"agentId {agentId} is not correct")#*************

    else: 
        try:
            host:Dict=client.get_hosts_request(limit=1, host_name=hostName)["data"]["entries"][0]
        except:
            raise ValueError(f"{hostName} is not found")#*****************

    headers_for_table=['Host Name', 'Host IP', 'Agent ID', 'Agent Version', 'OS', 'Last Poll', 'Containment State', 'Domain', 'Last Alert']
    for_table=[{
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

    md=tableToMarkdown(
        name="FireEye HX Get Host Information",
        t=for_table,
        headers=headers_for_table
    )

    return CommandResults(
        outputs_prefix="FireEyeHX.Host",
        outputs_key_field="",#***********
        outputs=host,
        readable_output=md
    )
    

def get_host_set_information_command(client:Client, args:Dict[str, Any])->CommandResults:

    """
    return host set information to the war room according to given id or filters

    """
    hostSetID = args.get('hostSetID')
    
    body =assign_params( 
        limit =  args.get('limit'),
        offset = args.get('offset'),
        search = args.get('search'),
        sort = args.get('sort'),
        name = args.get('name'),
        type = args.get('type')
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
            name = 'FireEye HX Get Host Sets Information',
            t = host_set_entry(host_set),
            headers=['Name', 'ID', 'Type']
        )

    return CommandResults(
        outputs_prefix="FireEyeHX.HostSets",
        outputs_key_field="_id",
        outputs=host_set,
        readable_output = md_table
        )
    
"""
HOST CONTAINMENT
"""

def host_containment_command(client:Client,args:Dict[str,Any])->CommandResults:

    agentId=args.get("agentId")
    hostName=args.get("hostName")

    if not agentId and not hostName:
        raise("Enter Agent ID or Host Name")#***************
    
    if not agentId:
        agentId=get_agent_id_by_host_name(client,hostName)#**********

    client.host_containmet_request(agentId)

    host=client.get_hosts_by_agentId_request(agentId)
    return [CommandResults(outputs_prefix="FireEyeHX.Hosts",outputs=host, readable_output="Containment rquest for the host was sent and approved successfully"),
            CommandResults(outputs_prefix="Endpoint",outputs=collect_endpoint_contxt(host["data"]))]#************************    
    

def approve_containment_command(client:Client,args:Dict[str,Any])->CommandResults:

    agentId=args.get("agentId")

    if not agentId:
        raise("Agent ID is required")#**********
    
    try:
        response=client.approve_containment_request(agentId)

    except Exception as e:
        raise ValueError(e)

    return CommandResults(
        outputs_prefix="FireEyeHX.Hosts",
        readable_output="Containment for the host was approved successfully" 
    )
    

def cancel_containment_command(client:Client,args:Dict[str,Any])->CommandResults:

    agentId=args.get("agentId")
    hostName=args.get("hostName")

    if not agentId and not hostName:
        raise("One of the following arguments is required -> [agentId, hostName]")
    
    if not agentId:
        agentId=get_agent_id_by_host_name(client, hostName)
    
    client.cancel_containment_request(agentId)

    
    return CommandResults(readable_output="Success")

"""
ACQUISITION
"""
'''

fe-tst
    args:
        - a
        - b
        - c
    
    args = {
        "a": 1,
        "b": 2,
        "c": 3
    }
    
    fe_tst_command(client, args)
    def fe_tst_command(client, args):
        a = args.get('a')
        b = args.get('b')
        c = args.get('c')
        return a == b == c


    fe_tst_command(client, **args)
    def fe_tst_command(client, a, b, c):
        return a == b == c

'''

def data_acquisition_command(client:Client, args:Dict[str,Any])->CommandResults:
    # TODO: need to add in the yaml command polling: true (see autofocus v2 for example)
    # TODO: Add support for new arg "acquisition_id" - if provided, will return the acquisition without creating a new data acquistion request (can be hidden via deprecated: true)
    
    acquisition_id = args.get("acquisition_id")
    if 'acquisition_id' not in args:
        acquisition_info:Dict = data_acquisition(client, args)
        acquisition_id = acquisition_info.get('_id')
        LOG('Acquisition request was successful. Waiting for acquisition process to be complete.')

    acquisition_info = client.data_acquisition_information_request(acquisition_id)

    if acquisition_info.get('state') != 'COMPLETE':
        readable_output = f'Acquisition is not yet ready, started polling for id {acquisition_id}' if 'acquisition_id' not in args else None
        if not args.get("acquisition_id"):
            args['acquisition_id'] = acquisition_id
        scheduled_command = ScheduledCommand(
            command='fireeye-hx-data-acquisition',
            next_run_in_seconds = 30,
            args=args,
            timeout_in_seconds= 600)

        # result with scheduled_command only - no update to the war room
        return CommandResults(readable_output=readable_output, scheduled_command=scheduled_command)
    
    LOG('Acquisition process has been complete. Fetching mans file.')

    message = f'{args.get("fileName")} acquired successfully'
    if acquisition_info.get('error_message'):
        message = acquisition_info.get('error_message')

    # output file and acquisition information to the war room
    data = client.data_collection_request(acquisition_id)

    return [CommandResults(
        outputs_prefix="FireEyeHX.Acquisitions.Data",
        outputs=acquisition_info,
        readable_output=f'{message}\nacquisition ID: {acquisition_id}'),
        fileResult(f'agent_{args.get("agentId")}_data.mans', data)]
    

def delete_data_acquisition_command(client:Client, args:Dict[str,Any])->CommandResults:

    if "acquisitionId" not in args:
        raise ValueError("Acquisition Id is required")
    
    client.delete_data_acquisition_request(args.get("acquisitionId"))

    return CommandResults(
        readable_output=f"data acquisition {args.get('acquisitionId')} deleted successfully"
    )
    

def file_acquisition_command(client:Client,args:Dict[str,Any])->CommandResults:
    
    if "acquisition_id" not in args:
        if not args.get('hostName') and not args.get('agentId'):
            raise ValueError('Please provide either agentId or hostName')

        if args.get('hostName'):
            args['agentId'] = get_agent_id_by_host_name(args.get('hostName'))

        use_api = args.get('acquireUsing') == 'API'

        acquisition_info = client.file_acquisition_request(
            args.get('agentId'),
            args.get('fileName'),
            args.get('filePath'),
            req_use_api=use_api
        )

        args["acquisition_id"] = acquisition_info.get('_id')

    LOG('acquisition request was successful. Waiting for acquisition process to be complete.')
    
    acquisition_info = client.file_acquisition_information_request(args["acquisition_id"])
    state = acquisition_info.get('state')
    if state not in ['COMPLETE', 'ERROR', 'FAILED']:
        scheduled_command = ScheduledCommand(
                command='fireeye-hx-search',
                next_run_in_seconds = 10,
                args=args,
                timeout_in_seconds=600)
        return CommandResults(readable_output="", scheduled_command=scheduled_command)
        
    LOG('acquisition process has been complete. Fetching zip file.')

    acquired_file = client.file_acquisition_package_request(args.get('acquisition_id'))

    message = f"{args.get('fileName')} acquired successfully"
    if acquisition_info.get('error_message'):
        message = acquisition_info.get('error_message')

    return [CommandResults(
        outputs_prefix="FireEyeHX.Acquisitions.Files",
        outputs_key_field="_id",
        outputs=acquisition_info,
        readable_output=f"{message}\nacquisition ID: {args.get('acquisition_id')}"
    ),fileResult(f"{os.path.splitext(args.get('fileName'))[0]}.zip", acquired_file)]
    

def get_data_acquisition_command(client:Client, args:Dict[str,Any])->CommandResults:#*********************
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

        result = [CommandResults(
            outputs_prefix="FireEyeHX.Acquisitions.Data",
            outputs_key_field="_id",
            outputs=acquisition_info,
            readable_output=f"{message}\nacquisition ID: {acquisition_id}"
        ),fileResult('{}_agent_{}_data.mans'.format(acquisition_id, agent_id), data)]

        return result

    # else return message for states in [ NEW, ERROR, QUEUED, RUNNING, FAILED ]
    state = acquisition_info.get('state')

    message = "Acquisition process not yet completed."
    if acquisition_info.get('error_message'):
        message = acquisition_info.get('error_message')

    return CommandResults(
        outputs_prefix="FireEyeHX.Acquisitions.Data",
        outputs_key_field="_id",
        outputs=acquisition_info,
        readable_output=f"{message}\nacquisition ID: {acquisition_id}\nstate: {state}"
        )
    

def initiate_data_acquisition_command(client:Client, args:Dict[str,Any])->CommandResults:

    acquisition_info:Dict = data_acquisition(client, args)

    # Add hostname to the host info of acquisition_info
    acquisition_info["host"]["hostname"]=args.get("hostName")

    # Add Integration Instance to the acquisition_info
    acquisition_info["instance"] = demisto.integrationInstance()

    return CommandResults(
        outputs_prefix="FireEyeHX.Acquisitions.Data",
        outputs=acquisition_info,
        readable_output=f'Acquisition ID: {acquisition_info.get("_id")} on Instance: {acquisition_info.get("instance")}'
    )


def delete_file_acquisition_command(client:Client, args:Dict[str,Any])->CommandResults:
    """

    returns a success message to the war room

    """
    acquisition_id = demisto.args().get('acquisitionId')
    client.delete_file_acquisition_request(acquisition_id)
    # successful request

    return CommandResults(readable_output= f'file acquisition {acquisition_id} deleted successfully')
        
"""
ALERTS
"""

def get_all_alerts_command(client:Client, args:Dict[str,Any])->CommandResults:
    """

    returns a list of alerts, all results up to limit

    """
    source=[]
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
        args['agentId'] = get_agent_id_by_host_name(args.get('hostName'))#*******i need implement this function

    if args.get('limit'):
        args['limit'] = int(args['limit'])
    
    #****
    alerts=get_alerts(client,args)

    # parse each alert to a record displayed in the human readable table
    alerts_entries = [alert_entry(alert) for alert in alerts]

    files, ips, registry_keys = collect_context(alerts)#*******need to find out*********

    headers_for_table=['Alert ID', 'Reported', 'Event Type', 'Agent ID']
    md_table = tableToMarkdown(
        name='FireEye HX Get Alerts',
        t=alerts_entries,
        headers=headers_for_table
    )


    return CommandResults(
        outputs_prefix="FireEyeHX.Alerts",
        outputs_key_field="",
        outputs=alerts,
        readable_output=md_table
        )


def get_alert_command(client:Client,args:Dict[str,Any])->CommandResults:

    alert_id = args.get('alertId')
    alert: Dict = client.get_alert_request(alert_id)["data"]

    alertEntry=alert_entry(alert)
    headers_for_table=['Alert ID', 'Reported', 'Event Type', 'Agent ID']

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

    return CommandResults(
        outputs_prefix="FireEyeHX.Alerts",
        outputs_key_field="_id",
        outputs=alert,
        readable_output=f'{alert_table}\n{event_table}'
    )
    

def suppress_alert_command(client:Client, args:Dict[str,Any])->CommandResults:
    """

    returns a success message to the war room

    """

    alert_id = args.get('alertId')

    try:
        client.suppress_alert_request(alert_id)
    except Exception as e:
        raise ValueError(f"Alert {alert_id} {e.res.reason}")

    # no exceptions raised->successful request
    return CommandResults(
        readable_output= f'Alert {alert_id} suppressed successfully.'
    )

"""
INDICATORS
"""

def get_indicators_command(client:Client, args:Dict[str,Any])->CommandResults:

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
        args['sort'] = sort_map.get(args.get('sort'))

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
        outputs_prefix = "FireEyeHX.Indicators",
        outputs_key_field = "_id",
        outputs = indicators,
        readable_output = md_table
    )


def get_indicator_command(client:Client, args:Dict[str,Any])->CommandResults:

    args = demisto.args()

    indicator = client.get_indicator_request(
        args.get('category'),
        args.get('name')
    )

    headers_for_table = ['OS', 'Name', 'Created By', 'Active Since', 'Category', 'Signature',
                         'Active Condition', 'Hosts With Alerts', 'Source Alerts']
    
    md_table = tableToMarkdown(
        name = f"FireEye HX Get Indicator- {args.get('name')}",
        t = indicator_entry(indicator),
        headers=headers_for_table
        )

    return [CommandResults(
        outputs_prefix="FireEyeHX.Indicators",
        outputs_key_field="_id",
        outputs=indicator,
        readable_output=md_table
        ),get_indicator_conditions(client,args)]
    

def append_conditions_command(client:Client,args:Dict[str,Any])->CommandResults:
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

    md = tableToMarkdown(name="The conditions were added successfully",t={
        'Name': name,
        'Category': category,
        'Conditions': body
    })

    return CommandResults(
        outputs=response,
        readable_output=md
        )

"""
SEARCHES
"""

def start_search_command(client:Client, args:Dict[str,Any])->CommandResults:

    if not args.get("searchId"):
        # checking if provided only one of these following arguments
        listOfArgs = ["agentsIds", "hostsNames", "hostSet", "hostSetName"]
        arg = oneFromList(listOfArgs = listOfArgs, **args)
        if arg == False:
            raise ValueError("One of the following arguments is required -> [agentsIds, hostsNames, hostSet, hostSetName]")

        # orgenized the search body, the function checks if provided only one argument,
        # and returns dict with key of Host_name or Hosts
        body = organize_search_body_host(client, arg, {})
        
        # checking if provided only one of these following arguments
        listOfArgs=['dnsHostname', 'fileFullPath', 'fileMD5Hash', 'ipAddress', 'fieldSearchName']
        argForQuery = oneFromList(listOfArgs = listOfArgs, **args)
        if argForQuery == False:
            raise ValueError("One of the following arguments is required -> [dnsHostname, fileFullPath, fileMD5Hash, ipAddress, fieldSearchName]")
        
        # this function organize the query of the request body, and returns list of queries
        body["query"] = organize_search_body_query(argForQuery, **args)
        body["exhaustive"] = False if args.get("exhaustive") == "false" else True

        try:
            searchId = client.search_request(body)["data"]["_id"]
        except Exception as e:
            raise ValueError(e)

    if not args.get("limit"):
        limit = 1000

    searchId = searchId if not args.get("searchId") else args.get("searchId")
    searchInfo = client.get_search_by_id_request(searchId)["data"]
    matched = searchInfo.get('stats', {}).get('search_state', {}).get('MATCHED', 0)
    pending = searchInfo.get('stats', {}).get('search_state', {}).get('PENDING', 0)

    if searchInfo.get("state") !="STOPPED" and matched < limit and pending != 0:

        readable_output = f'Searche is not STOPPED, started polling for id {searchId}' if 'searchId' not in args else None
        if not args.get("searchId"):
            args["searchId"] = searchId
        scheduled_command = ScheduledCommand(
                command='fireeye-hx-search',
                next_run_in_seconds = 60,
                args=args,
                timeout_in_seconds=600)
        # result with scheduled_command only - no update to the war room
        return CommandResults(readable_output=readable_output, scheduled_command=scheduled_command)
    
    commandResult = search_result_get_command(client, {"searchId":str(searchId)})

    message = None
    try:
        if args.get('stopSearch') == 'stop':
            message = 'Failed to stop search'
            client.search_stop_request(str(searchId))
            message = "The search was stopped successfully"
        # no need to stop a search before deleting it.
        if args.get('stopSearch') == 'stopAndDelete':
            message = 'Failed to delete search'
            client.delete_search_request(str(searchId))
            message = "The search was deleted successfully"
    except Exception as e:
        LOG('{}\n{}'.format(message, e))
        pass
    
    commandResult[0].readable_output += f"\n\n {message}"
    return commandResult


def get_search_list_command(client:Client, args:Dict[str,Any])->CommandResults:

    if args.get("searchId"):

        searchesIds=sorted(args.get("searchId").split(","),reverse=True)
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

        response: List[Dict] = client.get_search_list_request(
            offset=offset,
            limit=limit, 
            state=state, 
            hostSetId=hostSetId,
            actorUsername=actorUsername,
            sort=sort
            )["data"]["entries"]


    for_table=[]
    for search in response:
        if search["host_set"]:
            host_set = search["host_set"].copy()
            del host_set["url"]
        for_table.append(
            {
                "Id":search["_id"],
                "State":search["state"],
                "Host Set":host_set,
                "Created By":search["create_actor"],
                "Created At":search["create_time"],
                "Updated By":search["update_actor"],
                "Updated At":search["update_time"]
            }
        )

    headers_for_table=["Id","State","Host Set","Created By","Created At","Updated By","Updated At"]
    md= tableToMarkdown(
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


def search_stop_command(client:Client, args:Dict[str, Any])->CommandResults:

    if not args.get("searchId"):
        raise ValueError("Search Id is must be")

    searchesIds = args.get("searchId").split(",")
    responses = []
    md = ""
    for searchId in searchesIds:
        try:
            response = client.search_stop_request(searchId)
            md += f"\n{searchId} : Success"
            responses.append(response["data"])
        except:
            md += f"\n{searchId} : Not Found"
    

    return CommandResults(
        outputs_prefix="FireEyeHX.Search",
        outputs_key_field="_id",
        outputs=responses,
        readable_output=md
        )


def search_result_get_command(client:Client, args:Dict[str,Any])->CommandResults:

    if not args.get("searchId"):
        raise ValueError("")
    
    searchesIds = args.get("searchId").split(",")

    results : List[List[Dict]] = []
    for searchId in searchesIds:
        results.append(client.search_result_get_request(searchId)["data"]["entries"])

    commandsResults = []
    for result in results:
        for entry in result:
            Title = f"Host Id {entry.get('host').get('_id')}\nHost Name {entry.get('host').get('hostname')}"
            for_table = []
            for res in entry.get("results"):
                for_table.append({
                    "Item Type": res.get("type"),
                    "Summery": [f"**{k}:** {v}" for k,v in res.get("data").items()]
                })


            md = tableToMarkdown(
                name = Title,
                t = for_table,
                headers=["Item Type","Summery"]
            )

            commandsResults.append(CommandResults(
                outputs_prefix="FireEyeHX.Search",
                outputs_key_field= "",
                outputs= entry,
                readable_output= md
                ))
    return commandsResults

"""
FETCH INCIDENT
"""

def fetch_incident(client:Client,args:Dict[str,Any])->List:

    last_run = demisto.getLastRun()
    alerts = []  # type: List[Dict[str, str]]
    fetch_limit = int(args.get('fetch_limit') or '50')

    args={"sort":"event_at+ascending","limit":fetch_limit}

    if last_run and last_run.get('last_fetch'):
        # get all alerts with id greater than min_id
        args["eventAt"] = last_run.get('last_fetch')
        alerts = get_alerts(client, args)

        #results are sorted in ascending order - the last alert holds the greatest time *********
        last_fetch = alerts[-1].get("event_at") if alerts else None

    else:
        args["eventAt"] = timestamp_to_datestring(datetime_to_string( parse_date_string("3 day")))
        # get the last 100 alerts
        alerts = get_alerts(client, args)

        # results are sorted in descending order - the first alert holds the greatest id
        last_fetch = alerts[0].get("event_at") if alerts else None

    incidents = [parse_alert_to_incident(alert) for alert in alerts]
    
    # if lastId is not None:
    #     demisto.setLastRun({'lastId': lastId})
    if last_fetch is not None:
        demisto.setLastRun({'last_fetch':last_fetch})

    return incidents


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    
    commands={
        
        "fireeye-hx-get-host-information":get_host_information_command,
        "fireeye-hx-get-all-hosts-information":get_all_hosts_information_command,
        "fireeye-hx-host-containment":host_containment_command,
        "fireeye-hx-cancel-containment":cancel_containment_command,
        "fireeye-hx-get-host-set-information":get_host_set_information_command,
        "fireeye-hx-search":start_search_command,
        "fireeye-hx-search-list":get_search_list_command,
        "fireeye-hx-search-stop":search_stop_command,
        "fireeye-hx-search-result-get":search_result_get_command,
        "fireeye-hx-append-conditions":append_conditions_command,
        "fireeye-hx-get-indicators":get_indicators_command,
        "fireeye-hx-get-indicator":get_indicator_command,
        "fireeye-hx-create-indicator":"",
        "fireeye-hx-data-acquisition":data_acquisition_command,
        "fireeye-hx-delete-data-acquisition":delete_data_acquisition_command,
        "fireeye-hx-file-acquisition":file_acquisition_command,
        "fireeye-hx-delete-file-acquisition":delete_file_acquisition_command,
        "fireeye-hx-get-data-acquisition":get_data_acquisition_command,
        "fireeye-hx-initiate-data-acquisition":initiate_data_acquisition_command,
        "fireeye-hx-get-alert":get_alert_command,
        "fireeye-hx-get-alerts":get_all_alerts_command,
        "fireeye-hx-suppress-alert":suppress_alert_command,
        "fireeye-hx-list-policy":list_policy_command,
        "fireeye-hx-list-host-set-policy":list_host_set_policy_command,
        "fireeye-hx-assign-host-set-policy":assign_host_set_policy_command,
        "fireeye-hx-approve-containment":approve_containment_command,
        "fireeye-hx-list-containment":get_list_containment_command

    }
    
    params=demisto.params()
    userName=params.get("credentials").get('identifier')
    password=params.get("credentials").get('password')
    if not userName or not password:
        raise("User Name and Password are required")
    

    # get the service API url
    base_url = urljoin(params.get('server'), '/hx/api/v3/')
    
    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get('proxy', False)
    command=demisto.command()
    args=demisto.args()

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        # TODO: Make sure you add the proper headers for authentication
        # (i.e. "Authorization": {api key})
        headers: Dict = {}

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            auth=(userName,password))
        if command == 'test-module':
            return_results('ok')
        if command == 'fetch-incident':
            incidents=fetch_incident(client,params)
            demisto.incidents(incidents)
        
        else:
            result=commands[command](client,args)
            return_results(result)


    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):    
    main()
