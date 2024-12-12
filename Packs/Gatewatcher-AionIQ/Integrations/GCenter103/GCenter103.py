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
            self.PROXIES["http"] = os.getenv("http_proxy", "")
            self.PROXIES["https"] = os.getenv("https_proxy", "")

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


def convertEventSeverity(gwSev: int) -> int:

    if gwSev == 0:
        return 0.5
    if gwSev == 1:
        return 4
    if gwSev == 2:
        return 2
    if gwSev == 3:
        return 1

    return 0

def return_empty_incidents():

    empty = []
    demisto.incidents(empty)

def gw_client_auth(params: dict) -> GwClient:

    ip = params.get("ip")
    token = params.get("token", None)
    user = params.get("credentials", {}).get("identifier", None)
    password = params.get("credentials", {}).get("password", None)
    check_cert = params.get("check_cert", False)

    client = GwClient(ip=ip, check_cert=check_cert)
    client.auth(
        user=user if user != "" else None,
        password=password if password != "" else None,
        token=token
    )

    return client

"""
    Return a list containing the range of time query
    Args: params - demisto params
    Returns: from_to: list
"""
def last_run_range(params: dict) -> list:

    from_to = ["", ""]
    first_fetch = params.get('first_fetch', '1 day')
    first_fetch_dt = arg_to_datetime(arg=first_fetch, arg_name='First fetch', required=True)

    last_run = demisto.getLastRun()
    now = datetime.today()
    now_str = now.isoformat(sep='T', timespec='milliseconds') + "Z"

    if last_run == {}:

        first_fetch_dt_str = first_fetch_dt.isoformat(sep='T', timespec='milliseconds') + "Z"

        from_to[0] = str(first_fetch_dt_str)
        from_to[1] = str(now_str)
        
        return from_to
    
    else:

        last_fetch = last_run.get('start_time')
        from_to[0] = str(last_fetch)
        from_to[1] = str(now_str)

        return from_to

def query_es_alerts(client: GwClient, query: dict) -> dict:
    
    ret = client._post(endpoint="/api/v1/data/es/search/", params={"index": "engines_alerts"}, json_data=query)
    res = ret.json()
    
    if len(res['hits']['hits']) > 0:
        return res

    return_empty_incidents()
    return

def query_es_metadata(client: GwClient, query: dict) -> dict:
    
    ret = client._post(endpoint="/api/v1/data/es/search/", params={"index": "engines_metadata"}, json_data=query)
    res = ret.json()
    
    if len(res['hits']['hits']) > 0:
        return res

    return_empty_incidents()
    return

def handle_big_fetch_selected_engines(client: GwClient, query: dict, engine_selection: list, max_fetch: int, fetch_type: str) -> list:

    gw_alerts = []

    for i in range(0,len(engine_selection) - 1):

        query['size'] = 10000

        if fetch_type == "Alerts" or fetch_type == "Both":

            res_a = query_es_alerts(client=client,query=query)
            gw_alerts += res_a['hits']['hits']
            search_after_id_a = gw_alerts[-1]['sort'][0]
        
        else: 
            return_empty_incidents()

        nb_req = max_fetch // 10000
        nb_req = nb_req + 1

        while nb_req > 0:

            query['search_after'] = [search_after_id_a]
            res_a = query_es_alerts(client=client,query=query)
            gw_alerts += res_a['hits']['hits']
            search_after_id_a = gw_alerts[-1]['sort'][0]

            nb_req = nb_req - 1

        query['query']['bool']['must'][0]['match']['event.module'] = str(engine_selection[i])
        query['search_after'] = []

    return gw_alerts

def handle_big_fetch_empty_selected_engines(client: GwClient, query: dict, max_fetch: int, fetch_type: str) -> list:

    query['size'] = 10000

    if fetch_type == "Alerts" or fetch_type == "Both":

        res_a = query_es_alerts(client=client,query=query)
        gw_alerts = res_a['hits']['hits']
        search_after_id_a = gw_alerts[-1]['sort'][0]
    
    else: 
        return_empty_incidents()

    nb_req = max_fetch // 10000
    nb_req = nb_req + 1

    while nb_req > 0:

        query['search_after'] = [search_after_id_a]
        res_a = query_es_alerts(client=client,query=query)
        gw_alerts += res_a['hits']['hits']
        search_after_id_a = gw_alerts[-1]['sort'][0]

        nb_req = nb_req - 1

    query['search_after'] = []

    return gw_alerts

def handle_big_fetch_metadata(client: GwClient, query: dict, engine_selection: list, max_fetch: int, fetch_type: str) -> list:

    query['size'] = 10000

    if fetch_type == "Metadata" or fetch_type == "Both":

        res_m = query_es_metadata(client=client,query=query)
        gw_metadata = res_m['hits']['hits']
        search_after_id_m = gw_metadata[-1]['sort'][0]
    
    else: 
        return_empty_incidents()

    nb_req = max_fetch // 10000
    nb_req = nb_req + 1

    while nb_req > 0:

        query['search_after'] = [search_after_id_m]
        res_m = query_es_metadata(client=client,query=query)
        gw_metadata += res_m['hits']['hits']
        search_after_id_m = gw_metadata[-1]['sort'][0]

        nb_req = nb_req - 1

    return gw_metadata

def handle_little_fetch_alerts(client: GwClient, fetch_type: str, engine_selection: list, query: dict) -> list:

    gw_alerts = []

    for i in range(0,len(engine_selection) - 1):

        if fetch_type == "Alerts" or fetch_type == "Both":

            res_a = query_es_alerts(client=client,query=query)
            gw_alerts.append(res_a['hits']['hits'])
        
        else: 
            return_empty_incidents()

        query['query']['bool']['must'][0]['match']['event.module'] = str(engine_selection[i])

    return gw_alerts

def handle_little_fetch_empty_selected_engines(client: GwClient, fetch_type: str, query: dict) -> list:

    gw_alerts = []

    if fetch_type == "Alerts" or fetch_type == "Both":

        res_a = query_es_alerts(client=client,query=query)
        gw_alerts = res_a['hits']['hits']
    
    return gw_alerts

def handle_little_fetch_metadata(client: GwClient, fetch_type: str, query: dict) -> list:

    gw_metadata = []

    if fetch_type == "Metadata" or fetch_type == "Both":

        res_m = query_es_metadata(client=client,query=query)
        gw_metadata = res_m['hits']['hits']
    
    return gw_metadata

def index_alerts_incidents(incidents_dict: list, incidents: list) -> list:

    for i in range(0, len(incidents_dict)):

        incident = {'name': "Gatewatcher Alert: " + incidents_dict[i]['_source']['event']['module'],
                    'occurred': str(incidents_dict[i]['_source']['@timestamp']),
                    'dbotMirrorId': str(incidents_dict[i]['_source']['event']['id']),
                    'labels': [{"value": str(incidents_dict[i]['_source']['source']['ip']), "type": "IP"},
                               {"value": str(incidents_dict[i]['_source']['destination']['ip']), "type": "IP"}],
                    'rawJSON': json.dumps(incidents_dict[i]['_source']),
                    'type': "Gatewatcher Incident"
                    }

        # XSOAR Severity
        if 'severity' in incidents_dict[i]['_source']['event'].keys():
            incident['severity'] = convertEventSeverity(incidents_dict[i]['_source']['event']['severity'])

        else:
            incident['severity'] = convertEventSeverity(-1)

        # Sigflow alert signature
        if 'sigflow' in incidents_dict[i]['_source'].keys():
            if 'signature' in incidents_dict[i]['_source']['sigflow'].keys():
                incident['name'] = "Gatewatcher Alert: " + str(incidents_dict[i]['_source']['sigflow']['signature'])

        # NBA alert signature
        if 'nba' in incidents_dict[i]['_source'].keys():
            if 'signature' in incidents_dict[i]['_source']['nba'].keys():
                incident['name'] = "Gatewatcher Alert: " + str(incidents_dict[i]['_source']['nba']['signature'])

        incidents.append(incident)

    return incidents

def index_metadata_incidents(incidents_dict: list, incidents: list) -> list:

    for i in range(0, len(incidents_dict)):

        incident = {'name': "Gatewatcher Metadata: " + incidents_dict[i]['_source']['event']['module'],
                    'occurred': str(incidents_dict[i]['_source']['@timestamp']),
                    'dbotMirrorId': str(incidents_dict[i]['_source']['event']['id']),
                    'labels': [{"value": str(incidents_dict[i]['_source']['source']['ip']), "type": "IP"},
                               {"value": str(incidents_dict[i]['_source']['destination']['ip']), "type": "IP"}],
                    'rawJSON': json.dumps(incidents_dict[i]['_source']),
                    'type': "Gatewatcher Incident"
                    }

        # XSOAR Severity
        if 'severity' in incidents_dict[i]['_source']['event'].keys():
            incident['severity'] = convertEventSeverity(incidents_dict[i]['_source']['event']['severity'])

        else:
            incident['severity'] = convertEventSeverity(-1)

        incidents.append(incident)

    return incidents

def query_selected_engines_builder(max_fetch: int, engine_selection: list, from_to: list) -> dict:
    
    query = {'size': max_fetch,
             'query': {
               'bool': {
                  'must': [
                  {
                    'match': {
                      'event.module': str(engine_selection[0])
                    }
                  },
                  {
                    'range': {
                      '@timestamp': {
                        'gte': str(from_to[0]),
                        'lte': str(from_to[1])
                      }
                    }
                  }
                 ]
               }
             },
             'sort': [
             {"@timestamp": "asc"}
             ]
           }

    return query

def query_empty_selected_engines_builder(from_to: list, max_fetch: int) -> dict:

    query = {'size': max_fetch,
             'query': {
               'range': {
                 '@timestamp': {
                   'gt': str(from_to[0]),
                   'lt': str(from_to[1])
                 }
               }
             },
             'sort': [
               {"@timestamp": "asc"}
             ]
            }

    return query

def fetch_selected_engines(client: GwClient, engine_selection: list, params: dict, max_fetch: int, fetch_type: str, incidents: list) -> list:

    from_to = last_run_range(params=params)
    query = query_selected_engines_builder(max_fetch=max_fetch, engine_selection=engine_selection, from_to=from_to)

    if max_fetch > 10000:

        gw_alerts = handle_big_fetch_selected_engines(client=client, query=query, engine_selection=engine_selection, max_fetch=max_fetch, fetch_type=fetch_type)
        incidents = index_alerts_incidents(incidents_dict=gw_alerts, incidents=incidents)

        query = query_empty_selected_engines_builder(from_to=from_to, max_fetch=max_fetch)
        gw_metadata = handle_big_fetch_metadata(client=client, query=query, max_fetch=max_fetch, fetch_type=fetch_type)
        incidents = index_metadata_incidents(incidents_dict=gw_metadata, incidents=incidents)

        return incidents

    else:

        gw_alerts = handle_little_fetch_alerts(client=client, query=query, engine_selection=engine_selection, fetch_type=fetch_type)
        incidents = index_alerts_incidents(incidents_dict=gw_alerts, incidents=incidents)

        query = query_empty_selected_engines_builder(from_to=from_to, max_fetch=max_fetch)
        gw_metadata = handle_little_fetch_metadata(client=client, query=query, fetch_type=fetch_type)
        incidents = index_metadata_incidents(incidents_dict=gw_metadata, incidents=incidents)

        return incidents

def fetch_empty_selected_engines(client: GwClient, max_fetch: int, fetch_type: str, incidents: list, params: dict) -> list:

    from_to = last_run_range(params=params)
    query = query_empty_selected_engines_builder(from_to=from_to, max_fetch=max_fetch)

    if max_fetch > 10000:

        gw_alerts = handle_big_fetch_empty_selected_engines(client=client, query=query, max_fetch=max_fetch, fetch_type=fetch_type)
        incidents += index_alerts_incidents(incidents_dict=gw_alerts, incidents=incidents)

        query = query_empty_selected_engines_builder(from_to=from_to, max_fetch=max_fetch)
        gw_metadata = handle_big_fetch_metadata(client=client, query=query, max_fetch=max_fetch, fetch_type=fetch_type)
        incidents += index_metadata_incidents(incidents_dict=gw_metadata, incidents=incidents)

        return incidents

    else:

        gw_alerts = handle_little_fetch_empty_selected_engines(client=client, query=query, fetch_type=fetch_type)
        incidents += index_alerts_incidents(incidents_dict=gw_alerts, incidents=incidents)

        query = query_empty_selected_engines_builder(from_to=from_to, max_fetch=max_fetch)
        gw_metadata = handle_little_fetch_metadata(client=client, query=query, fetch_type=fetch_type)
        incidents += index_metadata_incidents(incidents_dict=gw_metadata, incidents=incidents)

        return incidents

def fetch_incidents():

    params = demisto.params()
    args = demisto.args()

    max_fetch = arg_to_number(args.get('max_fetch')) or params.get('max_fetch', '200')
    max_fetch = int(max_fetch)
    
    fetch_type = str(params['fetch_type'])

    if fetch_type == "":
        fetch_type = "Alerts"
   
    engine_selection = params['engine_selection'] 
    
    client = gw_client_auth(params=params)
    
    incidents = []

    if len(engine_selection) > 0:

        incidents = fetch_selected_engines(client=client, engine_selection=engine_selection, params=params, max_fetch=max_fetch, fetch_type=fetch_type, incidents=incidents)

    else:

        incidents = fetch_empty_selected_engines(client=client, max_fetch=max_fetch, fetch_type=fetch_type, incidents=incidents, params=params)

    if len(incidents) > 0:
        incidents = sorted(incidents, key=lambda d: d['occurred'])
        last_incident = incidents[len(incidents) - 1]
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
