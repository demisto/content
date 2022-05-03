from enum import Enum
from CommonServerPython import *
import demistomock as demisto
from pydantic import BaseModel, AnyUrl, Json
from collections.abc import Generator

DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'


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


class ReqHeaders(BaseModel):
    """
        A class that stores the request payload
    """
    Authorization: str


class ReqBody(BaseModel):
    """
        A class that stores the request payload
    """
    Script: str


class Request(BaseModel):
    """
    A class that stores a request configuration
    """
    method: Method
    url: AnyUrl
    headers: Optional[ReqHeaders]
    data: Optional[ReqBody]
    verify: bool = True


class Client:
    """
    A class for the client request handling
    """

    def __init__(self, request: Request):
        self.request = request
        self.token = self.get_access_token()

    def call(self, requests=requests) -> requests.Response:
        try:
            response = requests.request(**self.request.dict())
            response.raise_for_status()
            return response
        except Exception as exc:
            msg = f'something went wrong with the http call {exc}'
            LOG(msg)
            raise DemistoException(msg) from exc

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


def get_access_token(**kwargs):
    user_name = kwargs.get('credentials', {}).get('identifier')
    password = kwargs.get('credentials', {}).get('password')
    url = f'{kwargs.get("url")}/oauth2/token/{kwargs.get("app_id")}'
    headers = {'Authorization': f"Basic {base64.b64encode(f'{user_name}:{password}'.encode()).decode()}"}
    data = {'grant_type': 'client_credentials', 'scope': 'siem'}

    response = requests.post(url, headers=headers, data=data, verify=not kwargs.get('insecure'))
    json_response = response.json()
    access_token = json_response.get('access_token')

    return {'Authorization': f'Bearer {access_token}'}


def prepare_request_body(fetch_from: str) -> dict:
    _from = dateparser.parse(fetch_from, settings={'TIMEZONE': 'UTC'}).strftime(DATE_FORMAT)
    to = datetime.now().strftime(DATE_FORMAT)

    return {'Script': f'Select * from Event where WhenOccurred >= {_from} and WhenOccurred <= {to}'}


def main():
    # Args is always stronger. Get last run even stronger
    demisto_params = demisto.params() | demisto.args() | demisto.getLastRun()
    command = demisto.command()
    demisto.debug(f'Command {command} was called!!!')

    demisto_params['headers'] = ReqHeaders(**get_access_token(**demisto_params))
    demisto_params['data'] = ReqBody(**prepare_request_body(demisto_params.get('first_fetch', '3 days')))

    request = Request(**demisto_params)
    client = Client(request)
    get_events = GetEvents(client)

    try:
        if command == 'test-module':
            get_events.aggregated_results(1)
            demisto.results('ok')
        elif command in ('fetch-events', 'CyberArkIdentity-fetch-events'):
            events = get_events.aggregated_results(demisto_params.get('max_fetch'))
            if events:
                if command == 'fetch-events':
                    send_events_to_xsiam(events, 'CyberArkIdentity', 'Redrock records')
                if command == 'CyberArkIdentity-fetch-events':
                    CommandResults(

                    )
                    demisto.results(CommandResults)
                # Set next run
    except Exception as e:
        return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
