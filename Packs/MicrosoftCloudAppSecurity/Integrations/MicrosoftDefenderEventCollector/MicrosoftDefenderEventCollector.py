import pytest

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# pylint: disable=no-name-in-module
# pylint: disable=no-self-argument

from CommonServerUserPython import *  # noqa
from abc import ABC
from typing import Any
from collections.abc import Callable

from enum import Enum
from pydantic import BaseConfig, BaseModel, AnyUrl, validator, Field, parse_obj_as, HttpUrl  # type: ignore[E0611, E0611, E0611]
from requests.auth import HTTPBasicAuth
import requests
import dateparser

from MicrosoftApiModule import *
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
AUTH_ERROR_MSG = 'Authorization Error: make sure tenant id, client id and client secret is correctly set'
TYPES_TO_RETRIEVE = {'alerts': {'type': 'alerts', 'filters': {}},
                     'activities_admin': {'type': 'activities', 'filters': {"activity.type": {"eq": True}}},
                     'activities_login': {'type': 'activities', 'filters': {
                         "activity.eventType": {"eq": ["EVENT_CATEGORY_LOGIN", "EVENT_CATEGORY_FAILED_LOGIN"]}}}}
VENDOR = "Microsoft"
PRODUCT = "defender_cloud_apps"

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
    return v if isinstance(v, dict) else None


class IntegrationHTTPRequest(BaseModel):
    method: Method
    url: AnyUrl
    verify: bool = True
    headers: dict = {}  # type: ignore[type-arg]
    auth: HTTPBasicAuth | None
    data: Any = None

    class Config(BaseConfig):
        arbitrary_types_allowed = True

    _normalize_headers = validator('headers', pre=True, allow_reuse=True)(
        load_json
    )


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

    proxy: bool | None = False
    limit: int | None = Field(None, ge=1)


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
            demisto.debug(msg)
            raise DemistoException(msg) from exc

    def _skip_cert_verification(
            self, skip_cert_verification_callable: Callable = skip_cert_verification
    ):
        if not self.request.verify:
            skip_cert_verification_callable()

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
            if self.options.limit:
                demisto.debug(
                    f'{self.options.limit=} reached. \
                    slicing from {len(logs)=}. \
                    limit must be presented ONLY in commands and not in fetch-events.'
                )
                if len(stored) >= self.options.limit:
                    return stored[: self.options.limit]
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


class DefenderAuthenticator(BaseModel):
    verify: bool
    url: str
    tenant_id: str
    client_id: str
    client_secret: str
    scope: str
    ms_client: Any = None
    endpoint_type: str

    def set_authorization(self, request: IntegrationHTTPRequest):
        try:

            endpoint_type_name = self.endpoint_type or 'Worldwide'
            endpoint_type = MICROSOFT_DEFENDER_FOR_APPLICATION_TYPE[endpoint_type_name]
            azure_cloud = AZURE_CLOUDS[endpoint_type]  # The MDA endpoint type is a subset of the azure clouds.

            if not self.ms_client:
                demisto.debug('try init the ms client for the first time')
                self.ms_client = MicrosoftClient(
                    base_url=self.url,
                    tenant_id=self.tenant_id,
                    auth_id=self.client_id,
                    enc_key=self.client_secret,
                    scope=self.scope,
                    verify=self.verify,
                    self_deployed=True,
                    azure_cloud=azure_cloud,
                    command_prefix="microsoft-defender-cloud-apps",
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
            raise DemistoException(err_msg) from e


class DefenderHTTPRequest(IntegrationHTTPRequest):
    params: dict = {'sortDirection': 'asc'}
    method: Method = Method.GET

    _normalize_url = validator('url', pre=True, allow_reuse=True)(
        lambda base_url: f'{base_url}/api/v1/'
    )


class DefenderClient(IntegrationEventsClient):
    authenticator: DefenderAuthenticator
    request: DefenderHTTPRequest
    options: IntegrationOptions

    def __init__(self, request: DefenderHTTPRequest, options: IntegrationOptions, authenticator: DefenderAuthenticator,
                 after: int):
        self.after = after
        self.authenticator = authenticator
        super().__init__(request, options)

    def set_request_filter(self, after: Any):
        curr_filters = json.loads(self.request.params['filters'])
        curr_filters['date'] = {"gte": after + 1}
        self.request.params['filters'] = json.dumps(curr_filters)

    def authenticate(self):
        self.authenticator.set_authorization(self.request)


class DefenderGetEvents(IntegrationGetEvents):
    client: DefenderClient

    def _iter_events(self):
        self.last_timestamp = {}
        base_url = self.client.request.url
        self.client.authenticate()

        # In this integration we need to do 3 API calls:
        # - activities with filter to get the admin events
        # - activities with different filter to get the login events
        # - alerts with no filter
        # TYPES_TO_RETRIEVE dictionary contains the filters and the endpoint according to the event type.
        for event_type_name, endpoint_details in TYPES_TO_RETRIEVE.items():
            self.client.request.params.pop('filters', None)
            self.client.request.url = parse_obj_as(HttpUrl, f'{base_url}{endpoint_details["type"]}')

            # get the filter for this type
            filters = endpoint_details['filters']

            after = demisto.getLastRun().get(event_type_name) or self.client.after
            # add the time filter
            if after:
                filters['date'] = {'gte': after}  # type: ignore

            self.client.request.params['filters'] = json.dumps(filters)
            response = self.client.call(self.client.request).json()
            events = response.get('data', [])

            # add new field with the event type
            for event in events:
                event['event_type_name'] = event_type_name

            has_next = response.get('hasNext')

            yield events

            while has_next:
                last = events.pop()
                self.client.set_request_filter(last['timestamp'])
                response = self.client.call(self.client.request).json()
                events = response.get('data', [])

                # add new field with the event type
                for event in events:
                    event['event_type_name'] = event_type_name

                has_next = response.get('hasNext')

                yield events

    @staticmethod
    def get_last_run(events: list) -> dict:
        last_run = demisto.getLastRun()
        alerts_last_run = 0
        activities_admin_last_run = 0
        activities_login_last_run = 0

        for event in events:
            event_type = event['event_type_name']
            timestamp = event['timestamp']
            if event_type == 'alerts':
                alerts_last_run = timestamp
            elif event_type == 'activities_login':
                activities_login_last_run = timestamp
            elif event_type == 'activities_admin':
                activities_admin_last_run = timestamp

        if alerts_last_run:
            last_run['alerts'] = alerts_last_run + 1
        if activities_login_last_run:
            last_run['activities_login'] = activities_login_last_run + 1
        if activities_admin_last_run:
            last_run['activities_admin'] = activities_admin_last_run + 1

        return last_run


''' HELPER FUNCTIONS '''

''' COMMAND FUNCTIONS '''


@pytest.mark.skip("Not a pytest")
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
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'authenticate' in str(e):
            message = AUTH_ERROR_MSG
        else:
            raise
    return message


def main(command: str, demisto_params: dict):
    demisto.debug(f'Command being called is {command}')

    try:
        demisto_params['client_secret'] = demisto_params['credentials']['password']
        push_to_xsiam = argToBoolean(demisto_params.get('should_push_events', 'false'))

        after = demisto_params.get('after')
        if after and not isinstance(after, int):
            timestamp = dateparser.parse(after)  # type: ignore
            after = int(timestamp.timestamp() * 1000)  # type: ignore

        options = IntegrationOptions.parse_obj(demisto_params)
        request = DefenderHTTPRequest.parse_obj(demisto_params)
        authenticator = DefenderAuthenticator.parse_obj(demisto_params)

        client = DefenderClient(request=request, options=options, authenticator=authenticator,
                                after=after)
        get_events = DefenderGetEvents(client=client, options=options)

        if command == 'test-module':
            return_results(test_module(get_events=get_events))

        elif command == 'microsoft-defender-cloud-apps-auth-reset':
            return_results(reset_auth())

        elif command in ('fetch-events', 'microsoft-defender-cloud-apps-get-events'):
            events = get_events.run()

            if command == 'fetch-events':
                # publishing events to XSIAM
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)  # type: ignore
                demisto.setLastRun(DefenderGetEvents.get_last_run(events))

            elif command == 'microsoft-defender-cloud-apps-get-events':
                command_results = CommandResults(
                    readable_output=tableToMarkdown('microsoft defender cloud apps events', events,
                                                    headerTransform=pascalToSpace),
                    outputs_prefix='Microsoft.Events',
                    outputs_key_field='_id',
                    outputs=events,
                    raw_response=events,
                )
                return_results(command_results)
                if push_to_xsiam:
                    # publishing events to XSIAM
                    send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)  # type: ignore

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    # Args is always stronger. Get getIntegrationContext even stronger
    compound_demisto_params = demisto.params() | demisto.args() | demisto.getLastRun()
    main(demisto.command(), compound_demisto_params)
