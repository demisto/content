import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# pylint: disable=no-name-in-module
# pylint: disable=no-self-argument

from abc import ABC
from typing import Any, Callable, Optional
from CommonServerUserPython import *

from enum import Enum
from pydantic import BaseConfig, BaseModel, AnyUrl, validator, Field
from requests.auth import HTTPBasicAuth


class Method(str, Enum):
    GET = 'GET'
    POST = 'POST'
    PUT = 'PUT'
    HEAD = 'HEAD'
    PATCH = 'PATCH'
    DELETE = 'DELETE'


def load_json(v: Any) -> dict:
    if not isinstance(v, (dict, str)):
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
    return {}


class IntegrationHTTPRequest(BaseModel):
    method: Method
    url: AnyUrl
    verify: bool = True
    headers: dict = {}  # type: ignore[type-arg]
    auth: Optional[HTTPBasicAuth] = None
    data: Any = None
    params: dict = {}  # type: ignore[type-arg]

    class Config(BaseConfig):
        arbitrary_types_allowed = True

    _normalize_headers = validator('headers', pre=True, allow_reuse=True)(  # type: ignore[type-var]
        load_json
    )


class Credentials(BaseModel):
    identifier: Optional[str]
    password: str


def set_authorization(request: IntegrationHTTPRequest, auth_credendtials):
    """Automatic authorization.
    Supports {Authorization: Bearer __token__}
    or Basic Auth.
    """
    creds = Credentials.parse_obj(auth_credendtials)
    if creds.password and creds.identifier:
        request.auth = HTTPBasicAuth(creds.identifier, creds.password)
    auth = {'Authorization': f'Bearer {creds.password}'}
    if request.headers:
        request.headers |= auth  # type: ignore[assignment, operator]
    else:
        request.headers = auth  # type: ignore[assignment]


class IntegrationOptions(BaseModel):
    """Add here any option you need to add to the logic"""

    proxy: Optional[bool] = False
    limit: Optional[int] = Field(None, ge=1)


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

    @abstractmethod  # noqa: B027
    def _iter_events(self):
        """Create iterators with Yield"""
