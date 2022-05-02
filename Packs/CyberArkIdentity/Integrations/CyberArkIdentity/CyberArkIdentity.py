from enum import Enum

import requests
import urllib3
from CommonServerPython import *
import demistomock as demisto
from pydantic import BaseModel, AnyUrl, Json, validator
import dateparser
from collections.abc import Generator


class Method(str, Enum):
    """
    A list that represent the types of http request available
    """
    GET = 'GET'
    POST = 'POST'
    PUT = 'PUT'
    HEAD = 'HEAD'
    PATCH = 'PATCH'
    DELETE = 'DELETE'


class ReqParams(BaseModel):
    """
    A class that stores the request query params
    """
    include: str
    order: str = 'asc'
    after: str
    per_page: int = 100  # Maximum is 100
    # _normalize_after = validator('after', pre=True, allow_reuse=True)(
    #     get_github_timestamp_format
    # )


class Request(BaseModel):
    """
    A class that stores a request configuration
    """
    method: Method
    url: AnyUrl
    headers: Optional[Union[Json[dict], dict]]
    params: Optional[ReqParams]
    verify = True
    data: Optional[str] = None


class Client:
    """
    A class for the client request handling
    """

    def __init__(self, request: Request):
        self.request = request
        self.session = self.get_session()


    def call(self, requests=requests) -> requests.Response:
        try:
            response = requests.request(**self.request.dict())
            response.raise_for_status()
            return response
        except Exception as exc:
            msg = f'something went wrong with the http call {exc}'
            LOG(msg)
            raise DemistoException(msg) from exc

    @staticmethod
    def get_session():
        url = "https://aam4730.my.idaptive.app/Security/StartAuthentication"
        payload = {
            "TenantId": "AAM4730",
            "Version": "1.0",
            "User": "a55668899A"
        }
        headers = {
            "Accept": "*/*",
            "Content-Type": "application/json"
        }
        response = requests.get(url, json=payload, headers=headers, verify=False)
        return response.json().get('Result').get('SessionId'), response.json().get('Result').get('Challenges')[0].get('Mechanisms')[0].get('MechanismId')

    # def set_next_run_filter(self, after: str):
    #     self.request.params.after = get_github_timestamp_format(after)


class GetEvents:
    """
    A class to handle the flow of the integration
    """
    def __init__(self, client: Client) -> None:
        self.client = client

    def _iter_events(self) -> Generator:
        """
        Function that responsible for the iteration over the events returned from github api
        """
        response = self.client.call()
        events: list = response.json()

        if len(events) == 0:
            return []
        while True:
            yield events
            last = events.pop()
            self.client.set_next_run_filter(last['@timestamp'])
            response = self.client.call()
            events = response.json()
            try:
                events.pop(0)
                assert events
            except (IndexError, AssertionError):
                LOG('empty list, breaking')
                break

    def aggregated_results(self, limit=2000) -> List[dict]:
        """
        Function to group the events returned from the api
        """
        stored_events = []
        for events in self._iter_events():
            stored_events.extend(events)
            if len(stored_events) >= limit:
                return stored_events[:limit]
        return stored_events

    @staticmethod
    def get_last_run(events: List[dict]) -> dict:
        """
        Get the info from the last run, it returns the time to query from and a list of ids to prevent duplications
        """

        last_timestamp = events[-1]['@timestamp']
        last_time = last_timestamp / 1000
        next_fetch_time = datetime.fromtimestamp(last_time) + timedelta(
            seconds=1
        )
        return {'after': next_fetch_time.isoformat()}


def main():
    # Args is always stronger. Get last run even stronger
    demisto_params = demisto.params() | demisto.args() | demisto.getLastRun()
    command = demisto.command()
    demisto.debug(f'Command {command} was called!!!')

    try:
        if command == 'test-module':
            request = Request(**demisto_params)
            client = Client(request)
            get_events = GetEvents(client)

    except Exception as e:
        return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
