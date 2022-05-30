# pylint: disable=no-name-in-module
# pylint: disable=no-self-argument

from abc import ABC
from typing import Any, Callable, Optional
import demistomock as demisto
from CommonServerPython import *
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


class IntegrationHTTPRequest(BaseModel):
    method: Method
    url: AnyUrl
    verify: bool = True
    headers: dict = dict()  # type: ignore[type-arg]
    auth: Optional[HTTPBasicAuth]
    data: Any = None

    class Config(BaseConfig):
        arbitrary_types_allowed = True

    _normalize_headers = validator('headers', pre=True, allow_reuse=True)(
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


class IntegrationEventsClient(ABC):
    def __init__(
        self,
        request: IntegrationHTTPRequest,
        session=requests.Session(),
    ):
        self.request = request
        self.session = session
        self._skip_cert_verification()
        handle_proxy()

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
