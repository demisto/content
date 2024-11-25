"""Base Integration for Cortex XSOAR (aka Demisto)"""
from typing import (
    Any,
    Dict
)

import urllib3
import json

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

class GwRequests():
    """Allows to easily interact with HTTP server.

    Class features:
      - Get requests package wrapper.
      - Put requests package wrapper.
      - Post requests package wrapper.
      - Delete requests package wrapper.
    """

    PROXIES = {
        "http": "",
        "https": ""
    }

    def __init__(self, ip: str, headers: dict = {}, check_cert: bool = False,
                 proxies: dict = None) -> None:
        """Init.

        Disable urllib3 warning. Allow unsecure ciphers.

        Args:
            ip: IP address of the HTTP server.
            check_cert: True to validate server certificate and False instead.
            proxies: Requests proxies. Default to no proxies.
        """
        self.index_values = [
            "suricata",
            "codebreaker",
            "malware",
            "netdata",
            "syslog",
            "machine_learning",
            "retrohunt",
            "iocs"
        ]
        self.ip = ip
        self.headers = headers
        self.check_cert = check_cert
        if proxies is not None:
            self.PROXIES = proxies

    def _gen_request_kwargs(self,
                            endpoint: str,
                            data: dict,
                            json_data: dict,
                            params: dict,
                            headers: dict,
                            cookies: dict,
                            redirects: bool,
                            files: dict = None) -> dict:
        """Generate requests arguments.

        Args:
            endpoint: URL endpoint in format /XX/YY/ZZ.
            data: request data.
            json_data: Set to True if data is in json_data format and False instead.
            params: Set to True if data need to be send with the url and False instead.
            headers: Set to True if redirection is allowed and False instead.
            cookies: Set to True if redirection is allowed and False instead.
            redirects: Set to True if redirection is allowed and False instead.
            files: files to upload in multipart/form-data

        Returns:
            Return requests arguments in dictionnary format.
        """
        kwargs = {
            "url": f"https://{self.ip}{endpoint}",
            "headers": headers if headers else self.headers,
            "cookies": cookies,
            "verify": self.check_cert,
            "proxies": self.PROXIES,
            "allow_redirects": redirects,
            "data": data,
            "json": json_data,
            "params": params,
            "files": files
        }
        return kwargs

    def _get(self, endpoint: str,
             data: dict = None,
             json_data: dict = None,
             params: dict = None,
             headers: dict = None,
             cookies: dict = None,
             redirects: bool = True) -> requests.Response:
        """Wrap the get requests.

        Same arguments as _gen_request_kwargs functions.

        Returns:
            Return a requests object with properties:

            - status_code
            - reason
            - headers
            - text
        """
        kwargs = self._gen_request_kwargs(
            endpoint=endpoint,
            data=data,  # type: ignore
            json_data=json_data,  # type: ignore
            params=params,  # type: ignore
            headers=headers,  # type: ignore
            cookies=cookies,  # type: ignore
            redirects=redirects
        )
        return requests.get(**kwargs)

    def _post(self, endpoint: str,
              data: dict = None,
              json_data: dict = None,
              params: dict = None,
              headers: dict = None,
              cookies: dict = None,
              redirects: bool = True,
              files: dict = None) -> requests.Response:
        """Wrap the post requests.

        Same arguments as _gen_request_kwargs functions.

        Returns:
            Return a requests object with properties:

            - status_code
            - reason
            - headers
            - text
        """
        kwargs = self._gen_request_kwargs(
            endpoint=endpoint,
            data=data,  # type: ignore
            json_data=json_data,  # type: ignore
            params=params,  # type: ignore
            headers=headers,  # type: ignore
            cookies=cookies,  # type: ignore
            redirects=redirects,
            files=files
        )
        return requests.post(**kwargs)

    def _put(self, endpoint: str,
             data: dict = None,
             json_data: dict = None,
             params: dict = None,
             headers: dict = None,
             cookies: dict = None,
             redirects: bool = True,
             files: dict = None) -> requests.Response:
        """Wrap the put requests.

        Same arguments as _gen_request_kwargs functions.

        Returns:
            Return a requests object with properties:

            - status_code
            - reason
            - headers
            - text
        """
        kwargs = self._gen_request_kwargs(
            endpoint=endpoint,
            data=data,  # type: ignore
            json_data=json_data,  # type: ignore
            params=params,  # type: ignore
            headers=headers,  # type: ignore
            cookies=cookies,  # type: ignore
            redirects=redirects,
            files=files
        )
        return requests.put(**kwargs)

    def _delete(self, endpoint: str,
                data: dict = None,
                json_data: dict = None,
                params: dict = None,
                headers: dict = None,
                cookies: dict = None,
                redirects: bool = True) -> requests.Response:
        """Wrap the delete requests.

        Same arguments as _gen_request_kwargs functions.

        Returns:
            Return a requests object with properties:

            - status_code
            - reason
            - headers
            - text
        """
        kwargs = self._gen_request_kwargs(
            endpoint=endpoint,
            data=data,  # type: ignore
            json_data=json_data,  # type: ignore
            params=params,  # type: ignore
            headers=headers,  # type: ignore
            cookies=cookies,  # type: ignore
            redirects=redirects
        )
        return requests.delete(**kwargs)


class GwClient(GwRequests):
    """Client class to interact with the service API."""

    def auth(self, user: str = None, password: str = None, token: str = None) -> None:
        """Authentication through the GCenter API.

        Args:
            user: GCenter WEBui username.
            password: GCenter WEBui password.
            token: GCenter API token.

        Raises:
            GwAPIException: If status_code != 200.
        """
        if user is None and password is None and token is None:
            raise AttributeError("A user/password or an API token must be provided: [ERROR]")
        elif ((user is None and password is not None)
                or (user is not None and password is None)):
            raise AttributeError("A user and a password must be provided: [ERROR]")
        if user is not None and password is not None:
            response = self._post(
                endpoint="/api/v1/auth/login",
                json_data={
                    "username": user,
                    "password": password
                }
            )
            if response.status_code == 200:
                demisto.info(
                    f"Authentication on GCenter {self.ip} with user {user}: [OK]"
                )
                self.headers["API-KEY"] = response.json()["token"]
            else:
                raise GwAPIException(
                    f"Authentication on GCenter {self.ip} with"
                    f" user {user}: [FAILED]",
                    response.text, response.status_code, response.reason
                )
        else:
            self.headers["API-KEY"] = token

    def is_authenticated(self) -> bool:
        """Return True if authenticated and False instead.

        Raises:
            GwAPIException: If status_code != 200.
        """
        response = self._get(
            endpoint="/api/status/healthchecks/"
        )
        if response.status_code == 200:
            demisto.info(
                f"Get healthchecks on GCenter {self.ip}: [OK]"
            )
            return True
        else:
            demisto.error(
                f"Get healthchecks on GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )
            return False

def test_module(client: GwClient) -> str:  # noqa: E501
    """Tests API connectivity and authentication command.

    Args:
        client: Client to interact with the GCenter.

    Returns:
        'Authentication successful' when the GCenter connection works.
        'Authentication error' when the GCenter connection doesn't works.
    """
    if client.is_authenticated():
        return "ok"
    else:
        return "Authentication error, please check ip/user/password/token: [ERROR]"

def fetch_incidents():

    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    ip = params.get("ip")
    token = params.get("token", None)
    user = params.get("credentials", {}).get("identifier", None)
    password = params.get("credentials", {}).get("password", None)
    check_cert = params.get("check_cert", False)

    demisto.debug(f"Command being called is {command}")
    client = GwClient(ip=ip, check_cert=check_cert)
    client.auth(
        user=user if user != "" else None,
        password=password if password != "" else None,
        token=token
    )

    first_fetch = params.get('first_fetch', '1 day')
    first_fetch_dt = arg_to_datetime(arg=first_fetch, arg_name='First fetch', required=True)
    max_fetch = arg_to_number(args.get('max_fetch')) or params.get('max_fetch', '200')

    last_run = demisto.getLastRun()
    # Fetch was never runned
    if last_run == {}:
        first_fetch_dt_str = first_fetch_dt.isoformat(sep='T', timespec='milliseconds')+"Z"

        now = datetime.today()
        now_str = now.isoformat(sep='T', timespec='milliseconds')+"Z"
        queryRange = {'query': {
                        'range': {
                            '@timestamp': {
                                'gte': str(first_fetch_dt_str),
                                'lte': str(now_str)
                                }
                            }
                        }
                    }
    else:
        last_fetch = last_run.get('start_time')

        now = datetime.today()
        now_str = now.isoformat(sep='T', timespec='milliseconds')+"Z"
        queryRange = {'query': {
                        'range': {
                            '@timestamp': {
                                'gt': str(last_fetch),
                                'lt': str(now_str)
                                }
                            }
                        }
                    }

    # Alert events
    ret = client._post(endpoint="/api/v1/data/es/search/", params={"index": "engines_alerts"}, json_data=queryRange)

    results = ret.json()
    gwAlerts = results['hits']['hits']

    incidents = []

	for i in range(0, len(gwAlerts)):

        incident = {'name': "Gatewatcher Alert: " + gwAlerts[i]['_source']['event']['module'],
                    'occurred': str(gwAlerts[i]['_source']['@timestamp']),
                    'dbotMirrorId': str(gwAlerts[i]['_source']['event']['id']),
                    'labels': [{"value": str(gwAlerts[i]['_source']['source']['ip']), "type": "IP"},
                               {"value": str(gwAlerts[i]['_source']['destination']['ip']), "type": "IP"}],
                    'rawJSON': json.dumps(gwAlerts[i]['_source']),
                    'severity': gwAlerts[i]['_source']['event']['severity'],
                    'CustomFields': {'flowIdGatewatcher': gwAlerts[i]['_source']['network']['flow_id'],
                                     'GCenterGatewatcher': str(gwAlerts[i]['_source']['observer']['hostname']),
                                     'GCapGatewatcher': str(gwAlerts[i]['_source']['observer']['gcap']['hostname']),
                                     'rawEventGatewatcher': json.dumps(gwAlerts[i]['_source'])
                                     }
                    }

        # IP and port fields
        if 'port' in gwAlerts[i]['_source']['source'].keys() and gwAlerts[i]['_source']['destination'].keys():
            incident['details'] = "Source IP: "+str(gwAlerts[i]['_source']['source']['ip'])+"\n"+"Source port: "+str(gwAlerts[i]['_source']['source']['port'])+"\n"+"Destination IP: "+str(gwAlerts[i]['_source']['destination']['ip'])+"\n"+"Destination port: "+str(gwAlerts[i]['_source']['destination']['port'])
        else:
            incident['details'] = "Source IP: "+str(gwAlerts[i]['_source']['source']['ip'])+"\n"+"Destination IP: "+str(gwAlerts[i]['_source']['destination']['ip'])

        # Network protocol and transport fields
        if 'protocol' in gwAlerts[i]['_source']['network'].keys():
            incident['details'] += "\nProtocol: "+str(gwAlerts[i]['_source']['network']['protocol']).upper()
        if 'transport' in gwAlerts[i]['_source']['network'].keys():
            incident['details'] += "\nTransport: "+str(gwAlerts[i]['_source']['network']['transport']).upper()

        # Incident type malicious powershell detect
        if gwAlerts[i]['_source']['event']['module'] == "malicious_powershell_detect":
            incident['type'] = "Review Indicators Manually"

        # Incident type shellcode detect
        if gwAlerts[i]['_source']['event']['module'] == "shellcode_detect":
            incident['type'] = "Exploit"

        # Incident type sigflow_alert
        if gwAlerts[i]['_source']['event']['module'] == "sigflow_alert":
            incident['type'] = "Network"

        # Incident type malcore
        if gwAlerts[i]['_source']['event']['module'] == "malcore":
            incident['type'] = "Malware"

        # Incident type dga
        if gwAlerts[i]['_source']['event']['module'] == "dga_detect":
            incident['type'] = "C2Communication"
        
        # Sigflow alert signature
        if 'sigflow' in gwAlerts[i]['_source'].keys():
            if 'signature' in gwAlerts[i]['_source']['sigflow'].keys():
                incident['name'] = "Gatewatcher Alert: " + str(gwAlerts[i]['_source']['sigflow']['signature'])
                if "CnC" in str(gwAlerts[i]['_source']['sigflow']['signature']):
                    incident['type'] = "C2Communication"

        # NBA alert signature
        if 'nba' in gwAlerts[i]['_source'].keys():
            if 'signature' in gwAlerts[i]['_source']['nba'].keys():
                incident['name'] = "Gatewatcher Alert: " + str(gwAlerts[i]['_source']['nba']['signature'])
                if "C&C" in str(gwAlerts[i]['_source']['nba']['signature']):
                    incident['type'] = "C2Communication"

        incidents.append(incident)
    
    # Metadata events
    ret = client._post(endpoint="/api/v1/data/es/search/", params={"index": "engines_metadata"}, json_data=queryRange)

    results = ret.json()
    gwMeta = results['hits']['hits']

    for i in range(0, len(gwMeta)):

        incident = {'name': "Gatewatcher Metadata: " + gwMeta[i]['_source']['event']['module'],
                    'occurred': str(gwMeta[i]['_source']['@timestamp']),
                    'dbotMirrorId': str(gwMeta[i]['_source']['event']['id']),
                    'labels': [{"value": str(gwMeta[i]['_source']['source']['ip']), "type": "IP"},
                               {"value": str(gwMeta[i]['_source']['destination']['ip']), "type": "IP"}],
                    'rawJSON': json.dumps(gwMeta[i]['_source']),
                    'severity': 1,
                    'sourceBrand': "Gatewatcher",
                    'sourceInstance': str(gwMeta[i]['_source']['observer']['hostname'])+" | "+str(gwMeta[i]['_source']['observer']['gcap']['hostname']),
                    'type': "Network",
                    'CustomFields': {'flowIdGatewatcher': gwMeta[i]['_source']['network']['flow_id'],
                                     'GCenterGatewatcher': str(gwMeta[i]['_source']['observer']['hostname']),
                                     'GCapGatewatcher': str(gwMeta[i]['_source']['observer']['gcap']['hostname']),
                                     'rawEventGatewatcher': json.dumps(gwMeta[i]['_source'])
                                     }
                    }

        # IP and port fields
        if 'port' in gwMeta[i]['_source']['source'].keys() and gwMeta[i]['_source']['destination'].keys():
            incident['details'] = "Source IP: "+str(gwMeta[i]['_source']['source']['ip'])+"\n"+"Source port: "+str(gwMeta[i]['_source']['source']['port'])+"\n"+"Destination IP: "+str(gwMeta[i]['_source']['destination']['ip'])+"\n"+"Destination port: "+str(gwMeta[i]['_source']['destination']['port'])
        else:
            incident['details'] = "Source IP: "+str(gwMeta[i]['_source']['source']['ip'])+"\n"+"Destination IP: "+str(gwMeta[i]['_source']['destination']['ip'])

        # Network protocol and transport fields
        if 'protocol' in gwMeta[i]['_source']['network'].keys():
            incident['details'] += "\nProtocol: "+str(gwMeta[i]['_source']['network']['protocol']).upper()
        if 'transport' in gwMeta[i]['_source']['network'].keys():
            incident['details'] += "\nTransport: "+str(gwMeta[i]['_source']['network']['transport']).upper()

        incidents.append(incident)

    if len(incidents) > 0:
        incidents = sorted(incidents, key=lambda d: d['occurred'])
        last_incident = incidents[len(incidents)-1]
        demisto.setLastRun({'start_time': str(last_incident['occurred'])})

    demisto.incidents(incidents)

def main() -> None:
    """Main function, parses params and runs command functions."""

    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    ip = params.get("ip")
    token = params.get("token", None)
    user = params.get("credentials", {}).get("identifier", None)
    password = params.get("credentials", {}).get("password", None)
    check_cert = params.get("check_cert", False)

    demisto.debug(f"Command being called is {command}")
    try:
        client = GwClient(ip=ip, check_cert=check_cert)
        client.auth(
            user=user if user != "" else None,
            password=password if password != "" else None,
            token=token
        )
        if command == "test-module":
            return_results(
                test_module(client=client)
            )
        elif command == "fetch-incidents":
            return_results(
                fetch_incidents()
            )
    except Exception as e:
        return_error(
            f"Failed to execute {command} command.\nError: {str(e)}"
        )

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

