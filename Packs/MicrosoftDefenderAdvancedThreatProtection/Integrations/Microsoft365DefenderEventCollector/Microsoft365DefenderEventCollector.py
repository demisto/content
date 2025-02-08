import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# pylint: disable=no-name-in-module
# pylint: disable=no-self-argument
import copy

from CommonServerUserPython import *  # noqa

from abc import ABC
from typing import Any
from collections.abc import Callable

from enum import Enum
from pydantic import BaseConfig, BaseModel, AnyUrl, validator  # type: ignore[E0611, E0611, E0611]
from requests.auth import HTTPBasicAuth
import requests
import urllib3.util

from MicrosoftApiModule import *

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''
MAX_ALERTS_PAGE_SIZE = 1000
ALERT_CREATION_TIME = 'alertCreationTime'
DEFENDER_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
AUTH_ERROR_MSG = 'Authorization Error: make sure tenant id, client id and client secret is correctly set'
VENDOR = 'Microsoft 365'
PRODUCT = 'Defender'

''' HELPER CLASSES '''


# COPY OF SiemApiModule


class Method(str, Enum):
    GET = 'GET'
    POST = 'POST'
    PUT = 'PUT'
    HEAD = 'HEAD'
    PATCH = 'PATCH'
    DELETE = 'DELETE'


def load_json(v: Any) -> dict:
    if not isinstance(v, dict | str):
        raise ValueError('headers are not dict or a valid json')
    if isinstance(v, str):
        try:
            v = json.loads(v)
            if not isinstance(v, dict):
                raise ValueError('headers are not from dict type')
        except json.decoder.JSONDecodeError as exc:
            raise ValueError('headers are not valid Json object') from exc
    if isinstance(v, dict):
        return v
    return None


class IntegrationHTTPRequest(BaseModel):
    method: Method
    url: AnyUrl
    verify: bool = True
    headers: dict = {}  # type: ignore[type-arg]
    auth: HTTPBasicAuth | None = None
    data: Any = None

    class Config(BaseConfig):
        arbitrary_types_allowed = True

    _normalize_headers = validator('headers', pre=True, allow_reuse=True)(
        load_json
    )  # type: ignore[type-var]


class Credentials(BaseModel):
    identifier: str | None
    password: str


def set_authorization(request: IntegrationHTTPRequest, auth_credentials):
    """Automatic authorization.
    Supports {Authorization: Bearer __token__}
    or Basic Auth.
    """
    creds = Credentials.parse_obj(auth_credentials)
    if creds.password and creds.identifier:
        request.auth = HTTPBasicAuth(creds.identifier, creds.password)
    auth = {'Authorization': f'Bearer {creds.password}'}
    if request.headers:
        request.headers |= auth  # type: ignore[assignment, operator]
    else:
        request.headers = auth  # type: ignore[assignment]


class IntegrationOptions(BaseModel):
    """Add here any option you need to add to the logic"""

    proxy: bool = False
    limit: int = 1000


class IntegrationEventsClient(ABC):
    def __init__(
            self,
            request: IntegrationHTTPRequest,
            options: IntegrationOptions,
            session=requests.Session(),
    ):
        self.request = request
        self.options = options
        self.session = session
        self._set_proxy()
        self._skip_cert_verification()

    @abstractmethod
    def set_request_filter(self, after: Any):
        """TODO: set the next request's filter.
        Example:
        """
        self.request.headers['after'] = after

    def __del__(self):
        try:
            self.session.close()
        except AttributeError as err:
            demisto.debug(
                f'ignore exceptions raised due to session not used by the client. {err=}'
            )

    def call(self, request: IntegrationHTTPRequest) -> requests.Response:
        try:
            response = self.session.request(**request.dict())
            response.raise_for_status()
            return response
        except Exception as exc:
            msg = f'something went wrong with the http call {exc}'
            LOG(msg)
            raise DemistoException(msg) from exc

    def _skip_cert_verification(
            self, skip_cert_verification: Callable = skip_cert_verification
    ):
        if not self.request.verify:
            skip_cert_verification()

    def _set_proxy(self):
        if self.options.proxy:
            ensure_proxy_has_http_prefix()
        else:
            skip_proxy()


class IntegrationGetEvents(ABC):
    def __init__(
            self, client: IntegrationEventsClient, options: IntegrationOptions
    ) -> None:
        self.client = client
        self.options = options

    def run(self):
        stored = []
        for logs in self._iter_events():
            stored.extend(logs)
            if len(stored) >= self.options.limit:
                return stored[:self.options.limit]
        return stored

    def call(self) -> requests.Response:
        return self.client.call(self.client.request)

    @staticmethod
    @abstractmethod
    def get_last_run(events: list) -> dict:
        """Logic to get the last run from the events
        Example:
        """
        return {'after': events[-1]['created']}

    @abstractmethod
    def _iter_events(self):
        """Create iterators with Yield"""
        raise NotImplementedError


# END COPY OF SiemApiModule


class DefenderIntegrationOptions(IntegrationOptions):
    first_fetch: str


class DefenderAuthenticator(BaseModel):
    verify: bool
    url: str
    endpoint_type: str
    scope_url: str
    tenant_id: str
    client_id: str
    credentials: dict
    ms_client: Any = None

    def set_authorization(self, request: IntegrationHTTPRequest):
        try:
            if not self.ms_client:
                demisto.debug(f"try init the ms client for the first time, {self.url=}")
                self.ms_client = MicrosoftClient(
                    endpoint=self.endpoint_type,
                    base_url=self.url,
                    tenant_id=self.tenant_id,
                    auth_id=self.client_id,
                    enc_key=self.credentials.get('password'),
                    scope=urljoin(self.scope_url, "/windowsatpservice/.default"),
                    verify=self.verify,
                    self_deployed=True,
                    command_prefix="microsoft-365-defender",
                )

            token = self.ms_client.get_access_token()
            auth = {'Authorization': f'Bearer {token}'}
            if request.headers:
                request.headers |= auth  # type: ignore[assignment, operator]
            else:
                request.headers = auth  # type: ignore[assignment]

            demisto.debug('getting access token for Defender Authenticator - succeeded')

        except BaseException as e:
            # catch BaseException to catch also sys.exit via return_error
            demisto.error(f'Fail to authenticate with Microsoft services: {str(e)}')

            err_msg = 'Fail to authenticate with Microsoft services, see the error details in the log'
            raise DemistoException(err_msg)


class DefenderHTTPRequest(IntegrationHTTPRequest):
    params: dict | None = {}
    method: Method = Method.GET

    _normalize_url = validator('url', pre=True, allow_reuse=True)(
        lambda base_url: f'{base_url}/api/alerts'
    )  # type: ignore[type-var]


class DefenderClient(IntegrationEventsClient):
    authenticator: DefenderAuthenticator
    request: DefenderHTTPRequest
    options: DefenderIntegrationOptions

    def __init__(self, request: DefenderHTTPRequest, options: IntegrationOptions, authenticator: DefenderAuthenticator):
        self.authenticator = authenticator
        super().__init__(request, options)

    def set_request_filter(self, after: Any):
        limit = min(self.options.limit, MAX_ALERTS_PAGE_SIZE)
        if not after:
            demisto.debug(f'lastRunObj is empty, calculate the first fetch time according {self.options.first_fetch=}')
            first_fetch_date = dateparser.parse(self.options.first_fetch, settings={'TIMEZONE': 'UTC'})
            after = datetime.strftime(first_fetch_date, DEFENDER_DATE_FORMAT)  # type: ignore[arg-type]
        self.request.params = {
            '$filter': f'{ALERT_CREATION_TIME}+gt+{after}',
            '$orderby': f'{ALERT_CREATION_TIME}+asc',
            '$top': limit,
            '$expand': 'evidence',

        }
        demisto.debug(f'setting the request filter to be: {self.request.params}')

    def authenticate(self):
        self.authenticator.set_authorization(self.request)


class DefenderGetEvents(IntegrationGetEvents):
    client: DefenderClient

    def _split_evidence(self, org_alerts):
        """
        Extract evidence and create new alert entry that will contain the alert & evidence, for each evidence.
        """
        res: List[Dict] = []
        if not org_alerts:
            return res

        for alert in org_alerts:
            evidences = alert.pop('evidence', [])
            if evidences:
                for evidence in evidences:
                    updated_alert = alert.copy()
                    updated_alert['evidence'] = evidence
                    res.append(updated_alert)
            else:
                alert['evidence'] = {}
                res.append(alert)

        return res

    def _iter_events(self):

        self.client.authenticate()
        self.client.set_request_filter(demisto.getLastRun() and demisto.getLastRun().get('after'))

        response = self.client.call(self.client.request)
        value = response.json().get('value', [])
        value = self._split_evidence(value)

        demisto.debug(f'getting {len(value)} alerts from Defender Api')
        return [value]

    @staticmethod
    def get_last_run(events: list) -> dict:
        """Logic to get the last run from the events
        """
        return events and len(events) > 0 and {'after': events[-1]['alertCreationTime']} or demisto.getLastRun()


''' HELPER FUNCTIONS '''


''' COMMAND FUNCTIONS '''


def test_module(get_events: DefenderGetEvents) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type get_events: ``DefenderGetEvents``
    :param get_events: the get_events instance

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    try:
        get_events.client.request.params = {'limit': 1}
        get_events.run()
        return 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'authenticate' in str(e):
            return AUTH_ERROR_MSG
        raise


def main(command: str, params: dict):
    demisto.debug(f'Command being called is {command}')
    try:
        params_endpoint_type = params.get('endpoint_type') or 'Worldwide'
        params_url = params.get('url')
        # is_gcc wasn't supported in the event collector, thus passing it as None.
        endpoint_type, params_url = microsoft_defender_for_endpoint_get_base_url(params_endpoint_type, params_url)

        parsed_params = copy.copy(params)
        parsed_params["url"] = params_url
        parsed_params["endpoint_type"] = endpoint_type
        parsed_params["scope_url"] = MICROSOFT_DEFENDER_FOR_ENDPOINT_APT_SERVICE_ENDPOINTS[endpoint_type]

        options = DefenderIntegrationOptions.parse_obj(parsed_params)
        request = DefenderHTTPRequest.parse_obj(parsed_params)
        authenticator = DefenderAuthenticator.parse_obj(parsed_params)

        client = DefenderClient(request=request, options=options, authenticator=authenticator)
        get_events = DefenderGetEvents(client=client, options=options)

        if command == 'test-module':
            return_results(test_module(get_events=get_events))

        elif command == 'microsoft-365-defender-get-events':
            events = get_events.run()
            demisto.debug(f'{command=}, publishing events to the context')
            human_readable = tableToMarkdown(name="Alerts:", t=events)
            return_results(
                CommandResults('Microsoft365Defender.alerts', 'id', events, readable_output=human_readable))

            if argToBoolean(params.get('push_to_xsiam', False)):
                demisto.debug(f'{command=}, publishing events to XSIAM')
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

        elif command == 'fetch-events':
            events = get_events.run()

            demisto.debug(f'{command=}, publishing events to XSIAM')
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

            demisto.setLastRun(get_events.get_last_run(events))
            demisto.debug(f'Last run set to {demisto.getLastRun()}')

        elif command == 'microsoft-365-defender-auth-reset':
            return_results(reset_auth())

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    # Args is always stronger. Get getIntegrationContext even stronger
    demisto_params = demisto.params() | demisto.args() | demisto.getLastRun()
    main(demisto.command(), demisto_params)
