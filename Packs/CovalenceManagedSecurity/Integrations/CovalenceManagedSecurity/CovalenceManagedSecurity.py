import json
import os
import traceback
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Literal

import demistomock as demisto  # noqa: F401
import requests
import urllib3
from CommonServerPython import *  # noqa: F401
from requests import HTTPError, Response

DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
EMAIL = demisto.params().get('credentials')['identifier']
API_KEY = demisto.params().get('credentials')['password']
FIRST_RUN_TIME_RANGE = int(demisto.params().get('first_run_time_range').strip())
PROXY = demisto.params().get('proxy')
if not demisto.params().get('proxy', False):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']


class EndpointActionType(str, Enum):
    ISOLATE = "isolate"
    UNISOLATE = "unisolate"
    SHUTDOWN = "shutdown"
    RESTART = "restart"
    DEFENDER_QUICK_SCAN = "defender_quick_scan"
    DEFENDER_FULL_SCAN = "defender_full_scan"
    DEFENDER_SIGNATURE_UPDATE = "defender_signature_update"


class CloudActionType(str, Enum):
    DISABLE_USER = "disable_user"
    ENABLE_USER = "enable_user"
    REVOKE_SESSIONS = "revoke_sessions"


@dataclass
class OrganizationResponse:
    # pylint: disable=invalid-name
    ID: str
    name: str
    client_id: str


@dataclass
class ActionByHostResponse:
    host_identifier: str
    agent_uuid: str
    covalence_appliance: str
    task_id: int | str


@dataclass
class ActionByCloudAccountResponse:
    action_id: str
    action_type: Literal["disable_user", "enable_user", "revoke_sessions"]
    action_params: dict
    created_time: str
    status: Literal["QUEUED", "COMPLETE"]
    result: Literal["SUCCESS", "FAILED", "PENDING"]


class Portal():
    def __init__(self, bearer=None, portal_url="https://services.fieldeffect.net/v1", provider=None, verbose=False):
        self.auth = None
        self.portal_url = portal_url
        self.verbose = verbose
        self.provider_name = provider
        if bearer == "gan ceann":
            self.scheme = self.AuthScheme.FES
            # Headless login for those cursed with a GUI
        elif bearer:
            self.scheme = self.AuthScheme.BEARER
            self.auth = {"token": bearer, "expires": datetime.now() + timedelta(days=10 * 365), "refresh": None}
            self.provider_id = self.get_provider_id()
        else:
            raise ValueError('Bearer is missing')

    class AuthScheme:
        FES = 'FieldEffectAuth'
        BEARER = 'Bearer'
        KEY = 'FieldEffectKey'

    def try_saved_token(self, token):
        # Return True if this token works, also save this token as the token
        # Return False if this token doesn't work and user will need to auth
        try:
            self.auth = token
            if self.provider_name:
                self.provider_id = self.find_provider(self.provider_name)
            else:
                self.provider_id = self.get_provider_id()
            return True

        except requests.exceptions.HTTPError:
            self.auth = None
            return False

    def get(self, uri, query=None, headers=None, remove_subdomain=False, **kwargs):
        return self._request(uri, method='GET', query=query, headers=headers, remove_subdomain=remove_subdomain,
                             **kwargs)

    def post(self, uri, query=None, headers=None, remove_subdomain=False, **kwargs):
        return self._request(uri, method='POST', query=query, headers=headers, remove_subdomain=remove_subdomain, **kwargs)

    def _request(self, uri, method='GET', query=None, json=None, data=None, files=None, headers=None,
                 remove_subdomain=False, **kwargs):
        all_headers = {
            'Content-Type': 'application/json'
        } if json is not None else {}

        if headers is not None:
            all_headers.update(headers)
        if self.auth:
            auth = '{} {}'.format(self.scheme, self.auth['token'])
            all_headers.update({'Authorization': auth})

        url = '{}/{}'.format(self.portal_url, uri if len(kwargs) == 0 else uri.format(**kwargs))
        if remove_subdomain:
            url = url.replace('services.', '')

        if self.verbose:
            sys.stdout.write(f'{method} {url} ')

        if method == 'GET':
            r = requests.get(url, headers=all_headers, params=query)
        elif method == 'POST':
            r = requests.post(url, headers=all_headers, json=json, data=data, params=query, files=files)
        elif method == 'PUT':
            r = requests.put(url, headers=all_headers, json=json, data=data, params=query, files=files)
        elif method == 'DELETE':
            r = requests.delete(url, headers=all_headers, params=query)
        else:
            raise AssertionError(f'Unsupported HTTP method: {method}')

        if self.verbose:
            sys.stdout.write(str(r.status_code) + '\n')
        if r.status_code >= 400:
            raise HTTPError(r.text)
        return r

    def get_provider_id(self):
        r = self.get('my_providers', auth=self.auth)
        if not r.json():
            raise ValueError(f'Account {EMAIL} is not part of any provider')
        return r.json()[0]['ID']

    def find_provider(self, provider):
        r = self.get('providers', auth=self.auth)
        providers = r.json()
        for prov in providers:
            if provider == prov["name"] or provider == prov["ID"]:
                return prov["ID"]
        return None

    def get_organizations(self):
        r = self.get('my_providers/{id}/organizations', auth=self.auth, id=self.provider_id)
        return r.json()

    def find_organizations(self, org):
        r = self.get('my_providers/{id}/organizations', auth=self.auth, id=self.provider_id)
        orgs = r.json()
        matches = []
        for o in orgs:
            if org.lower() in o["name"].lower():
                matches.append(o)
        return matches

    def get_aros(self, **kwargs):
        aros = []
        if "query" not in kwargs:
            kwargs["query"] = {}
        kwargs["query"]["limit"] = 500
        r = self.get('providers/{id}/aros', auth=self.auth, id=self.provider_id, **kwargs).json()
        aros.extend(r["items"])
        while len(aros) < r["total"]:
            kwargs["query"]["page"] = r["page"] + 1
            r = self.get('providers/{id}/aros', auth=self.auth, id=self.provider_id, **kwargs).json()
            aros.extend(r["items"])
        return aros

    def get_active_response_profile(self, org_id):
        r = self.get('my_organizations/{org_id}', auth=self.auth, org_id=org_id)
        org_details = r.json()
        return org_details.get('active_response_profile', None)

    def transition_aro(self, aro_id, resolution, comment="", is_comment_sensitive=False):
        request = {
            "status": "Open",
            "resolution": resolution
        }
        if comment:
            request["comment"] = {"text": comment, "sensitive": is_comment_sensitive}

        r = self.post("aros/{aro_id}/transition", aro_id=aro_id, json=request)
        return r.json()

    def comment_aro(self, aro_id, comment="", is_comment_sensitive=False):
        request = {
            "aro_id": aro_id,
            "sensitive": is_comment_sensitive,
            "text": comment
        }

        r = self.post("aro_comments", json=request)
        return r.json()


class BrokerClient:
    def __init__(self, host: str, verify_ssl: bool = False, api_key: str | None = None, timeout: int = 60):
        self.host = host[:-1] if host.endswith("/") else host
        self.session = requests.Session()
        self.verify_ssl = verify_ssl
        self.api_key = api_key
        self.timeout = timeout

        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    @property
    def api_key(self) -> str | None:
        return self._api_key

    @api_key.setter
    def api_key(self, value: str | None) -> None:
        if isinstance(value, str):
            if not value.startswith("Bearer "):
                value = f"Bearer {value}"
            self.session.headers["Authorization"] = value
        self._api_key = value

    def ping(self) -> str:
        return self._request(method="GET", path="/ping", check_authentication=False).text

    def organizations(self, to_dataclass: bool = False) -> list[dict] | list[OrganizationResponse]:
        response: list[dict] = self._request(method="GET", path="/organizations").json()
        if to_dataclass is True:
            return [OrganizationResponse(**entry) for entry in response]
        return response

    def endpoint_action_by_host(
        self,
        action_type: EndpointActionType,
        org_id: str,
        host_identifier: str,
        to_dataclass: bool = False,
    ) -> dict | ActionByHostResponse:
        response: dict = self._request(
            method="POST",
            path=f"/endpoint/host/{action_type.value}",
            json={"org_id": org_id, "host_identifier": host_identifier},
        ).json()
        if to_dataclass is True:
            return ActionByHostResponse(**response)
        return response

    def endpoint_action_by_aro(
            self, action_type: EndpointActionType, aro_id: str, to_dataclass: bool = False) -> dict | ActionByHostResponse:
        response: dict = self._request(
            method="POST",
            path=f"/endpoint/aro/{action_type.value}",
            json={"aro_id": aro_id},
        ).json()
        if to_dataclass is True:
            return ActionByHostResponse(**response)
        return response

    def cloud_action_by_aro(
            self, action_type: CloudActionType, aro_id: str, to_dataclass: bool = False) -> dict | ActionByCloudAccountResponse:
        response: dict = self._request(
            method="POST",
            path=f"/cloud/aro/{action_type.value}",
            json={"aro_id": aro_id},
        ).json()
        if to_dataclass is True:
            return ActionByCloudAccountResponse(**response)
        return response

    # pylint: disable=too-many-arguments
    def _request(
        self,
        method: Literal["GET", "POST"],
        path: str,
        json: dict | None = None,
        data: dict | None = None,
        check_authentication: bool = True,
    ) -> Response:
        if check_authentication is True and not isinstance(self.session.headers.get("Authorization"), str):
            raise Exception('Must provide API Authorization to use Broker commands.')

        host_and_path = f"{self.host}{path}"

        if method == "GET":
            resp: Response = self.session.get(host_and_path, verify=self.verify_ssl, timeout=self.timeout)
        else:
            resp: Response = self.session.post(  # type: ignore[no-redef]
                host_and_path, json=json, data=data, verify=self.verify_ssl, timeout=self.timeout)

        resp.raise_for_status()
        return resp


''' Commands '''


def portal_check():
    '''
    Poking to the portal to make sure it's up
    '''
    try:
        Portal(bearer=API_KEY)
        return True
    except Exception:
        demisto.debug(traceback.format_exc())
        return False


def fetch_incidents(last_run, first_run_time_range):
    last_fetch = last_run.get('last_fetch', None)
    aro_time_max = datetime.utcnow() - timedelta(seconds=1)

    if last_fetch is None:
        aro_time_min = aro_time_max - timedelta(days=first_run_time_range)
    else:
        aro_time_min = dateparser.parse(last_fetch)  # type: ignore
    assert aro_time_min is not None

    p = Portal(bearer=API_KEY)
    query = {'resolution': 'Unresolved',
             'since': aro_time_min.strftime(DATE_FORMAT),
             'until': aro_time_max.strftime(DATE_FORMAT)}
    aros = p.get_aros(query=query)

    incidents = []

    # AROs are ordered by most recent ARO
    # it's required to traverse aros in chronological order (so last element first)
    # to avoid duplicating incidents
    for a in reversed(aros):
        created_time = dateparser.parse(a['creation_time'])
        assert created_time is not None, f'could not parse {a["creation_time"]}'
        if created_time != last_fetch:
            created_time_str = created_time.strftime(DATE_FORMAT)

            if a.get('organization', None):
                org_name = a['organization'].get('name', 'No org name')
                org_id = a['organization'].get('ID', None)
            else:
                org_name = 'No org name'
                org_id = None

            aro_type = a.get('type', 'No ARO type')

            aro_title = a.get('title', 'No title')

            incident: Dict[str, Any] = {
                'name': f'''[{org_name}] [{aro_type}] {aro_title}''',
                'occured': created_time_str,
                'rawJSON': json.dumps(a)
            }
            if a.get('severity', None):
                # XSOAR mapping
                # Unknown: 0
                # Informational: 0.5
                # Low: 1
                # Medium: 2
                # High: 3
                # Critical: 4
                severity_from_portal = a['severity']
                if severity_from_portal == 'Informational':
                    incident['severity'] = 0.5
                elif severity_from_portal == 'Warning':
                    incident['severity'] = 1
                elif severity_from_portal == 'Low':
                    incident['severity'] = 1
                elif severity_from_portal == 'Medium':
                    incident['severity'] = 2
                elif severity_from_portal == 'High':
                    incident['severity'] = 3
                elif severity_from_portal == 'Critical':
                    incident['severity'] = 4
            else:
                incident['severity'] = 0
            if a.get('details', None):
                incident['details'] = a['details']
                if a.get('steps', None) and len(a['steps']) > 0:
                    incident['details'] += '\n\nMitigation Steps\n'
                    for step in a['steps']:
                        incident['details'] += f'''- {step['label']}\n'''
                if org_id:
                    active_response_profile = p.get_active_response_profile(org_id)
                    if active_response_profile:
                        policy = active_response_profile.get('response_policy')
                        options = active_response_profile.get('options')
                        incident['details'] += '\nActive Response Profile\n'
                        incident['details'] += f'''- Response policy: {policy}\n'''
                        incident['details'] += f'''- Exclusions/ Modifications: {options}\n'''

            incidents.append(incident)

    next_run = {'last_fetch': aro_time_max.strftime(DATE_FORMAT)}

    return next_run, incidents


def get_aros():
    p = Portal(bearer=API_KEY)

    q = demisto.args().get('query', None)

    if q:
        query = {}  # pragma: no cover
        for param in q.split('&'):
            key = param.split('=')[0]
            value = param.split('=')[1]
            query[key] = value

            if 'org' in query:
                org = p.find_organizations(query['org'])
                if not org:
                    raise ValueError(f'Unknown organization named {query["org"]}')
                del query['org']
                query['organization_id'] = org[0]['ID']
        aros = p.get_aros(query=query)
    else:
        aros = p.get_aros()

    details = argToBoolean(demisto.args().get('details', 'false'))
    keys = ['title',
            'organization',
            'resolution',
            'severity',
            'status',
            'type']

    if not details:
        filtered_r = []
        # returning only data in keys
        for aro in aros:
            a = {k: aro[k] for k in keys}
            filtered_r.append(a)
        return filtered_r
    else:
        return aros


def list_organizations():
    p = Portal(bearer=API_KEY)

    return p.get_organizations()


def transition_aro_command():
    p = Portal(bearer=API_KEY)
    args = demisto.args()
    return p.transition_aro(**args)


def comment_aro_command():
    p = Portal(bearer=API_KEY)
    args = demisto.args()
    return p.comment_aro(**args)


''' Broker Commands '''


def ping_broker_command(broker_instance: BrokerClient):
    result = broker_instance.ping()
    if 'pong' in result:
        readable_output = '## Success'
    else:
        readable_output = f'Failure - {result}.'
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='FESBroker.APIStatus',
        outputs_key_field='',
        outputs=result
    )


def list_organizations_broker_command(broker_instance: BrokerClient):
    result = broker_instance.organizations()
    if result:
        readable_output = tableToMarkdown('Organizations', result)
    else:
        readable_output = "No broker organizations found."
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='FESBroker.Org',
        outputs_key_field='ID',
        outputs=result
    )


def endpoint_action_by_host_broker_command(broker_instance: BrokerClient, args):
    action_type = EndpointActionType[args["action_type"]]
    result = broker_instance.endpoint_action_by_host(action_type, args["org_id"], args["host_identifier"])
    return CommandResults(
        readable_output=tableToMarkdown('Command Result - Success', result),
        outputs_prefix='FESBroker.Action',
        outputs_key_field='agent_uuid',
        outputs=result
    )


def endpoint_action_by_aro_broker_command(broker_instance: BrokerClient, args):
    action_type = EndpointActionType[args["action_type"]]
    result = broker_instance.endpoint_action_by_aro(action_type, args['aro_id'])
    return CommandResults(
        readable_output=tableToMarkdown('Command Result - Success', result),
        outputs_prefix='FESBroker.Action',
        outputs_key_field='agent_uuid',
        outputs=result
    )


def cloud_action_by_aro_broker_command(broker_instance: BrokerClient, args):
    action_type = CloudActionType[args["action_type"]]
    result = broker_instance.cloud_action_by_aro(action_type, args['aro_id'])
    return CommandResults(
        readable_output=tableToMarkdown('Command Result', result),
        outputs_prefix='FESBroker.Action',
        outputs_key_field='action_id',
        outputs=result
    )


def main():
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    broker_url = params.get('broker_url', '')
    return_error_msg = None
    demisto.info(f'{command} is called')

    if broker_url and (command.startswith("cov-mgsec-broker") or command == 'test-module'):
        # Initialize Broker client only if required, allowing the Portal commands to still function if the Broker
        # connection is down or unwanted.
        broker_instance = BrokerClient(host=broker_url, api_key=API_KEY)
    else:
        demisto.debug("No condition was met. Initializing BrokerClient")
        broker_instance = BrokerClient(host=broker_url, api_key=API_KEY)

    try:
        if command == 'test-module':
            portal_result = portal_check()
            if broker_url:
                broker_result = bool(broker_instance.ping() == "pong")
                if broker_result is True and portal_result is True:
                    return_results('ok')
            elif portal_result is True:
                return_results('ok')

        elif command == 'fetch-incidents':
            next_run, incidents = fetch_incidents(
                last_run=demisto.getLastRun(),
                first_run_time_range=FIRST_RUN_TIME_RANGE)

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command == 'cov-mgsec-get-aro':
            r = get_aros()
            if r:
                readable_output = tableToMarkdown('AROs', r, removeNull=True, headerTransform=string_to_table_header)
            else:
                readable_output = 'No AROs found'

            results = CommandResults(
                outputs_prefix='FESPortal.ARO',
                outputs_key_field='ID',
                outputs=r,
                readable_output=readable_output
            )
            return_results(results)
        elif command == 'cov-mgsec-list-org':
            r = list_organizations()
            if r:
                readable_output = tableToMarkdown('Organizations', r, removeNull=True,
                                                  headerTransform=string_to_table_header)
            else:
                readable_output = 'No organizations found'

            results = CommandResults(
                outputs_prefix='FESPortal.Org',
                outputs_key_field='ID',
                outputs=r,
                readable_output=readable_output
            )
            return_results(results)
        elif command == 'cov-mgsec-transition-aro':
            r = transition_aro_command()
            if r:
                readable_output = tableToMarkdown('ARO', r, removeNull=True,
                                                  headerTransform=string_to_table_header)
            else:
                readable_output = 'Error transitioning ARO.'

            results = CommandResults(
                outputs_prefix='FESPortal.Org',
                outputs_key_field='ID',
                outputs=r,
                readable_output=readable_output
            )
            return_results(results)
        elif command == 'cov-mgsec-comment-aro':
            r = comment_aro_command()
            if r:
                readable_output = tableToMarkdown('ARO', r, removeNull=True,
                                                  headerTransform=string_to_table_header)
            else:
                readable_output = 'Error commenting on ARO.'

            results = CommandResults(
                outputs_prefix='FESPortal.Org',
                outputs_key_field='ID',
                outputs=r,
                readable_output=readable_output
            )
            return_results(results)
        elif command == 'cov-mgsec-broker-ping':
            return_results(ping_broker_command(broker_instance))
        elif command == 'cov-mgsec-broker-list-org':
            return_results(list_organizations_broker_command(broker_instance))
        elif command == 'cov-mgsec-broker-endpoint-action-by-host':
            return_results(endpoint_action_by_host_broker_command(broker_instance, args))
        elif command == 'cov-mgsec-broker-endpoint-action-by-aro':
            return_results(endpoint_action_by_aro_broker_command(broker_instance, args))
        elif command == 'cov-mgsec-broker-cloud-action-by-aro':
            return_results(cloud_action_by_aro_broker_command(broker_instance, args))
    except HTTPError as e:
        demisto.error(traceback.format_exc())
        http_text = None
        try:
            http_text = e.response.text  # Try to extract a text response if it exists.
        except AttributeError:
            http_text = e.response
        return_error_msg = (f'Failed to execute {command} command with HTTP response: {str(http_text)}.'
                            f'\nStack trace: {traceback.format_exc()}')
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error_msg = f'Failed to execute {command} command. Error: {str(e)}.\nStack trace: {traceback.format_exc()}'

    if return_error_msg:
        return_error(return_error_msg)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
