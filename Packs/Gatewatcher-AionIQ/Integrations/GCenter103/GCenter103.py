from typing import (
    Any
)

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401, F403
import urllib3
import json
import requests
from datetime import datetime

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member


class GwAPIException(Exception):
    """A base class from which all other exceptions inherit.

    If you want to catch all errors that the gwapi_benedictine package might raise,
    catch this base exception.
    """


class GwRequests:
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
                 proxy: bool = False) -> None:
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

        if proxy:

            d = handle_proxy(proxy_param_name='proxy')
            self.PROXIES["http"] = d['http']
            self.PROXIES["https"] = d['https']

    def _gen_request_kwargs(self,
                            endpoint: str,
                            data: dict,
                            json_data: dict,
                            params: dict,
                            headers: dict,
                            cookies: dict,
                            redirects: bool,
                            files: dict | None = None) -> dict:
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
             data: dict | None = None,
             json_data: dict | None = None,
             params: dict | None = None,
             headers: dict | None = None,
             cookies: dict | None = None,
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
            data=data,  # type: ignore[arg-type]
            json_data=json_data,  # type: ignore[arg-type]
            params=params,  # type: ignore[arg-type]
            headers=headers,  # type: ignore[arg-type]
            cookies=cookies,  # type: ignore[arg-type]
            redirects=redirects
        )
        return requests.get(**kwargs)

    def _post(self, endpoint: str,
              data: dict | None = None,
              json_data: dict | None = None,
              params: dict | None = None,
              headers: dict | None = None,
              cookies: dict | None = None,
              redirects: bool = True,
              files: dict | None = None) -> requests.Response:
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
            data=data,  # type: ignore[arg-type]
            json_data=json_data,  # type: ignore[arg-type]
            params=params,  # type: ignore[arg-type]
            headers=headers,  # type: ignore[arg-type]
            cookies=cookies,  # type: ignore[arg-type]
            redirects=redirects,
            files=files
        )
        return requests.post(**kwargs)

    def _put(self, endpoint: str,
             data: dict | None = None,
             json_data: dict | None = None,
             params: dict | None = None,
             headers: dict | None = None,
             cookies: dict | None = None,
             redirects: bool = True,
             files: dict | None = None) -> requests.Response:
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
            data=data,  # type: ignore[arg-type]
            json_data=json_data,  # type: ignore[arg-type]
            params=params,  # type: ignore[arg-type]
            headers=headers,  # type: ignore[arg-type]
            cookies=cookies,  # type: ignore[arg-type]
            redirects=redirects,
            files=files
        )
        return requests.put(**kwargs)

    def _delete(self, endpoint: str,
                data: dict | None = None,
                json_data: dict | None = None,
                params: dict | None = None,
                headers: dict | None = None,
                cookies: dict | None = None,
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
            data=data,  # type: ignore[arg-type]
            json_data=json_data,  # type: ignore[arg-type]
            params=params,  # type: ignore[arg-type]
            headers=headers,  # type: ignore[arg-type]
            cookies=cookies,  # type: ignore[arg-type]
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
            endpoint="/api/v1/status/gcenter/"
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


def convert_event_severity(gw_sev: int) -> float:

    severity_map = {
        0: 0.5,
        1: 4,
        2: 2,
        3: 1
    }
    return severity_map.get(gw_sev, 0)


def gw_client_auth(params: dict) -> GwClient:

    ip = params.get("ip")
    token = params.get("token", None)
    user = params.get("credentials", {}).get("identifier", None)
    password = params.get("credentials", {}).get("password", None)
    check_cert = params.get("check_cert", False)

    client = GwClient(ip=ip, check_cert=check_cert)  # type: ignore[arg-type]
    client.auth(
        user=user if user != "" else None,
        password=password if password != "" else None,
        token=token
    )

    return client


def last_run_range(params: dict[str, Any]) -> list[str]:

    from_to: list[str] = ["", ""]
    first_fetch = params.get('first_fetch', '1 day')
    first_fetch_dt = arg_to_datetime(arg=first_fetch, arg_name='First fetch', required=True)  # noqa: F405

    last_run = demisto.getLastRun()
    now = datetime.today()
    now_str = now.isoformat(sep='T', timespec='milliseconds') + "Z"

    if last_run == {}:

        first_fetch_dt_str = first_fetch_dt.isoformat(sep='T', timespec='milliseconds') + "Z"  # type: ignore[union-attr]

        from_to[0] = str(first_fetch_dt_str)
        from_to[1] = str(now_str)

        return from_to

    else:

        last_fetch = last_run.get('start_time')
        from_to[0] = str(last_fetch)
        from_to[1] = str(now_str)

        return from_to


def query_es_alerts(client: GwClient,
                    query: dict[str, Any]) -> dict[Any, Any]:

    ret: requests.Response = client._post(endpoint="/api/v1/data/es/search/", params={"index": "engines_alerts"}, json_data=query)
    res: dict[Any, Any] = ret.json()

    if len(res['hits']['hits']) > 0:
        return res['hits']['hits']

    return {}


def query_es_metadata(client: GwClient,
                      query: dict[str, Any]) -> dict[Any, Any]:

    ret: requests.Response = client._post(endpoint="/api/v1/data/es/search/",
                                          params={"index": "engines_metadata"}, json_data=query)
    res: dict[Any, Any] = ret.json()

    if len(res['hits']['hits']) > 0:
        return res['hits']['hits']

    return {}


def handle_big_fetch_selected_engines(client: GwClient,
                                      query: dict[str, Any],
                                      engine_selection: list[str],
                                      max_fetch: int,
                                      fetch_type: str):

    gw_alerts = []  # type: ignore[var-annotated]
    search_after_id_a: int = -1

    if fetch_type in ("Alerts", "Both"):

        query['size'] = 10000
        query['query']['bool']['must'][0]['match']['event.module'] = str(engine_selection[0])

        res_a = query_es_alerts(client=client, query=query)
        gw_alerts = res_a  # type: ignore[assignment]
        search_after_id_a = gw_alerts[-1]['sort'][0]

        nb_req: int = max_fetch // 10000
        nb_req = nb_req + 1

        while nb_req > 0:

            query['search_after'] = [search_after_id_a]
            res_a = query_es_alerts(client=client, query=query)
            gw_alerts += res_a
            search_after_id_a = gw_alerts[-1]['sort'][0]

            nb_req = nb_req - 1

    for i in range(1, len(engine_selection)):

        query['query']['bool']['must'][0]['match']['event.module'] = str(engine_selection[i])
        res_a = query_es_alerts(client=client, query=query)
        gw_alerts += res_a
        search_after_id_a = gw_alerts[-1]['sort'][0]

        nb_req = max_fetch // 10000
        nb_req = nb_req + 1

        while nb_req > 0:

            query['search_after'] = [search_after_id_a]
            res_a = query_es_alerts(client=client, query=query)
            gw_alerts += res_a
            search_after_id_a = gw_alerts[-1]['sort'][0]

            nb_req = nb_req - 1

        query['search_after'] = []

    return gw_alerts


def handle_big_fetch_empty_selected_engines(client: GwClient,
                                            query: dict[str, Any],
                                            max_fetch: int,
                                            fetch_type: str):

    query['size'] = 10000
    search_after_id_a: int = -1
    gw_alerts = []  # type: ignore[var-annotated]

    if fetch_type in ("Alerts", "Both"):

        res_a = query_es_alerts(client=client, query=query)
        gw_alerts = res_a  # type: ignore[assignment]
        search_after_id_a = gw_alerts[-1]['sort'][0]

    nb_req: int = max_fetch // 10000
    nb_req = nb_req + 1

    while nb_req > 0:

        query['search_after'] = [search_after_id_a]
        res_a = query_es_alerts(client=client, query=query)
        gw_alerts += res_a
        search_after_id_a = gw_alerts[-1]['sort'][0]

        nb_req = nb_req - 1

    query['search_after'] = []

    return gw_alerts


def handle_big_fetch_metadata(client: GwClient,
                              query: dict[str, Any],
                              max_fetch: int,
                              fetch_type: str):

    query['size'] = 10000

    search_after_id_m: int = -1
    gw_metadata = []  # type: ignore[var-annotated]

    if fetch_type in ("Metadata", "Both"):

        res_m = query_es_metadata(client=client, query=query)
        gw_metadata = res_m  # type: ignore[assignment]
        search_after_id_m = gw_metadata[-1]['sort'][0]

    nb_req: int = max_fetch // 10000
    nb_req = nb_req + 1

    while nb_req > 0:

        query['search_after'] = [search_after_id_m]
        res_m = query_es_metadata(client=client, query=query)
        gw_metadata += res_m
        search_after_id_m = gw_metadata[-1]['sort'][0]

        nb_req = nb_req - 1

    return gw_metadata


def handle_little_fetch_alerts(client: GwClient,
                               fetch_type: str,
                               engine_selection: list[str],
                               query: dict[str, Any]):

    gw_alerts = []  # type: ignore[var-annotated]

    for i in range(0, len(engine_selection)):

        if fetch_type in ("Alerts", "Both"):

            query['query']['bool']['must'][0]['match']['event.module'] = str(engine_selection[i])
            res_a = query_es_alerts(client=client, query=query)
            gw_alerts += res_a

    return gw_alerts


def handle_little_fetch_empty_selected_engines(client: GwClient,
                                               fetch_type: str,
                                               query: dict[str, Any]):
    gw_alerts = {}
    if fetch_type in ("Alerts", "Both"):

        res_a = query_es_alerts(client=client, query=query)
        gw_alerts = res_a

    return gw_alerts


def handle_little_fetch_metadata(client: GwClient,
                                 fetch_type: str,
                                 query: dict[str, Any]):

    gw_metadata = []  # type: ignore[var-annotated]

    if fetch_type in ("Metadata", "Both"):

        res_m = query_es_metadata(client=client, query=query)
        gw_metadata = res_m  # type: ignore[assignment]

    return gw_metadata


def index_alerts_incidents(to_index,
                           incidents,
                           params: dict[str, Any]):

    webui_link: str = "https://" + str(params['ip']) + "/ui/alerts?drawer=alert&drawer_uuid="

    for i in range(0, len(to_index)):

        webui_link += str(to_index[i]['_source']['event']['id'])

        incident = {
            'name': "Gatewatcher Alert: " + to_index[i]['_source']['event']['module'],
            'occurred': str(to_index[i]['_source']['@timestamp']),
            'dbotMirrorId': str(to_index[i]['_source']['event']['id']),
            'labels': [
                {
                    "value": str(to_index[i]['_source']['source']['ip']),
                    "type": "IP"
                },
                {
                    "value": str(to_index[i]['_source']['destination']['ip']),
                    "type": "IP"
                }
            ],
            'rawJSON': json.dumps(to_index[i]['_source']),
            'type': "Gatewatcher Incident",
            'CustomFields': {
                'GatewatcherRawEvent': json.dumps(to_index[i]['_source']),
                'GatewatcherGCenterWebUI': webui_link
            }
        }

        webui_link = webui_link.rstrip(str(to_index[i]['_source']['event']['id']))

        # XSOAR Severity
        if 'severity' in to_index[i]['_source']['event']:
            incident['severity'] = convert_event_severity(to_index[i]['_source']['event']['severity'])

        else:
            incident['severity'] = convert_event_severity(-1)

        # Sigflow alert signature
        if 'sigflow' in to_index[i]['_source'] and 'signature' in to_index[i]['_source']['sigflow']:
            incident['name'] = "Gatewatcher Alert: " + str(to_index[i]['_source']['sigflow']['signature'])

        # NBA alert signature
        if 'nba' in to_index[i]['_source'] and 'signature' in to_index[i]['_source']['nba']:
            incident['name'] = "Gatewatcher Alert: " + str(to_index[i]['_source']['nba']['signature'])

        incidents.append(incident)

    return incidents


def index_metadata_incidents(to_index,
                             incidents):

    for i in range(0, len(to_index)):

        incident = {'name': "Gatewatcher Metadata: " + to_index[i]['_source']['event']['module'],
                    'occurred': str(to_index[i]['_source']['@timestamp']),
                    'dbotMirrorId': str(to_index[i]['_source']['event']['id']),
                    'labels': [{"value": str(to_index[i]['_source']['source']['ip']), "type": "IP"},
                               {"value": str(to_index[i]['_source']['destination']['ip']), "type": "IP"}],
                    'rawJSON': json.dumps(to_index[i]['_source']),
                    'type': "Gatewatcher Incident"
                    }

        # XSOAR Severity
        if 'severity' in to_index[i]['_source']['event']:
            incident['severity'] = convert_event_severity(to_index[i]['_source']['event']['severity'])

        else:
            incident['severity'] = convert_event_severity(-1)

        incidents.append(incident)

    return incidents


def query_selected_engines_builder(max_fetch: int, engine_selection: list, from_to: list) -> dict[str, Any]:

    query: dict[str, Any] = {
        "size": max_fetch,
        "query": {
            "bool": {
                "must": [
                    {
                        "match": {
                            "event.module": str(engine_selection[0])
                        }
                    },
                    {
                        "range": {
                            "@timestamp": {
                                "gt": str(from_to[0]),
                                "lt": str(from_to[1])
                            }
                        }
                    }
                ]
            }
        },
        "sort": [
            {
                "@timestamp": "asc"
            }
        ]
    }

    return query


def query_empty_selected_engines_builder(from_to: list, max_fetch: int) -> dict[str, Any]:

    query: dict[str, Any] = {
        "size": max_fetch,
        "query": {
            "range": {
                "@timestamp": {
                    "gt": str(from_to[0]),
                    "lt": str(from_to[1])
                }
            }
        },
        "sort": [
            {
                "@timestamp": "asc"
            }
        ]
    }

    return query


def fetch_selected_engines(client: GwClient,
                           engine_selection: list[str],
                           params: dict[str, Any],
                           max_fetch: int,
                           fetch_type: str,
                           incidents):

    from_to: list[str] = last_run_range(params=params)
    query: dict[str, Any] = query_selected_engines_builder(max_fetch=max_fetch,
                                                           engine_selection=engine_selection,
                                                           from_to=from_to)

    if max_fetch > 10000:

        gw_alerts = handle_big_fetch_selected_engines(client=client,
                                                      query=query,
                                                      engine_selection=engine_selection,
                                                      max_fetch=max_fetch,
                                                      fetch_type=fetch_type)
        incidents_a = index_alerts_incidents(to_index=gw_alerts,
                                             incidents=incidents,
                                             params=params)

        query = query_empty_selected_engines_builder(from_to=from_to, max_fetch=max_fetch)
        gw_metadata = handle_big_fetch_metadata(client=client, query=query, max_fetch=max_fetch, fetch_type=fetch_type)
        incidents_m = index_metadata_incidents(to_index=gw_metadata, incidents=incidents)

        return incidents_a + incidents_m

    else:

        gw_alerts = handle_little_fetch_alerts(
            client=client, query=query, engine_selection=engine_selection, fetch_type=fetch_type)
        incidents_a = []
        if len(gw_alerts) > 0:
            incidents_a = index_alerts_incidents(to_index=gw_alerts, incidents=incidents, params=params)

        query = query_empty_selected_engines_builder(from_to=from_to, max_fetch=max_fetch)
        gw_metadata = handle_little_fetch_metadata(client=client, query=query, fetch_type=fetch_type)
        incidents_m = []
        if len(gw_metadata) > 0:
            incidents_m = index_metadata_incidents(to_index=gw_metadata, incidents=incidents)

        return incidents_a + incidents_m


def fetch_empty_selected_engines(client: GwClient,
                                 max_fetch: int,
                                 fetch_type: str,
                                 incidents,
                                 params: dict[str, Any]):

    from_to: list[str] = last_run_range(params=params)
    query: dict[str, Any] = query_empty_selected_engines_builder(from_to=from_to, max_fetch=max_fetch)

    if max_fetch > 10000:

        gw_alerts = handle_big_fetch_empty_selected_engines(
            client=client, query=query, max_fetch=max_fetch, fetch_type=fetch_type)
        incidents_a = index_alerts_incidents(to_index=gw_alerts, incidents=incidents, params=params)

        query = query_empty_selected_engines_builder(from_to=from_to, max_fetch=max_fetch)
        gw_metadata = handle_big_fetch_metadata(client=client, query=query, max_fetch=max_fetch, fetch_type=fetch_type)
        incidents_m = index_metadata_incidents(to_index=gw_metadata, incidents=incidents)

        return incidents_a + incidents_m

    else:

        gw_alerts = handle_little_fetch_empty_selected_engines(client=client, query=query, fetch_type=fetch_type)
        incidents_a = []
        if len(gw_alerts) > 0:
            incidents_a = index_alerts_incidents(to_index=gw_alerts, incidents=incidents, params=params)

        query = query_empty_selected_engines_builder(from_to=from_to, max_fetch=max_fetch)
        gw_metadata = handle_little_fetch_metadata(client=client, query=query, fetch_type=fetch_type)
        incidents_m = []
        if len(gw_metadata) > 0:
            incidents_m = index_metadata_incidents(to_index=gw_metadata, incidents=incidents)

        return incidents_a + incidents_m


def fix_broken_list(params: Dict[str, Any]) -> List[str]:

    if 'engine_selection' not in params or not isinstance(params['engine_selection'], str | list):

        raise ValueError("Invalid 'engine_selection' parameter")

    bdl = params['engine_selection']
    known_engines = {
        "malcore", "shellcode_detect", "malicious_powershell_detect",
        "sigflow_alert", "dga_detect", "active_cti", "retrohunt",
        "ransomware_detect", "beacon_detect"
    }
    e_s = []

    if isinstance(bdl, str):
        e_s = [engine for engine in known_engines if engine in bdl]

    elif isinstance(bdl, list):
        e_s = [engine for engine in known_engines if engine in bdl]

    return e_s


def fetch_incidents():

    params: dict[str, Any] = demisto.params()
    demisto.args()

    max_fetch: int = int(params.get('max_fetch', '200'))

    fetch_type: str = str(params['fetch_type'])

    if fetch_type == "":
        fetch_type = "Alerts"

    engine_selection: list[str] = fix_broken_list(params=params)

    client: GwClient = gw_client_auth(params=params)

    incidents: list = []

    if len(engine_selection) > 0:

        incidents = fetch_selected_engines(client=client,
                                           engine_selection=engine_selection,
                                           params=params,
                                           max_fetch=max_fetch,
                                           fetch_type=fetch_type,
                                           incidents=incidents)

    else:

        incidents = fetch_empty_selected_engines(client=client, max_fetch=max_fetch,
                                                 fetch_type=fetch_type, incidents=incidents, params=params)

    if len(incidents) > 0:
        incidents_s = sorted(incidents, key=lambda d: d['occurred'])
        last_incident = incidents_s[len(incidents_s) - 1]
        demisto.setLastRun({'start_time': str(last_incident['occurred'])})

    demisto.incidents(incidents=incidents)


def main() -> None:
    """Main function, parses params and runs command functions."""

    params = demisto.params()
    command = demisto.command()
    demisto.args()

    ip = params.get("ip")
    token = params.get("token", None)
    user = params.get("credentials", {}).get("identifier", None)
    password = params.get("credentials", {}).get("password", None)
    check_cert = params.get("check_cert", False)
    proxy = params.get("proxy", False)

    demisto.debug(f"Command being called is {command}")
    try:
        client = GwClient(ip=ip, check_cert=check_cert, proxy=proxy)
        client.auth(
            user=user if user != "" else None,
            password=password if password != "" else None,
            token=token
        )
        if command == "test-module":
            return_results(  # noqa: F405
                test_module(client=client)
            )
        elif command == "fetch-incidents":
            return_results(  # noqa: F405
                fetch_incidents()
            )
    except Exception as e:
        return_error(  # noqa: F405
            f"Failed to execute {command} command.\nError: {str(e)}"
        )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
