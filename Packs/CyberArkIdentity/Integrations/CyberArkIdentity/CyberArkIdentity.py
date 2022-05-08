from enum import Enum
from CommonServerPython import *
import demistomock as demisto
from pydantic import BaseModel, AnyUrl, Json, Field
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
    Accept: str = '*/*'
    content_type: str = Field('application/json', alias='Content-Type')


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
    # data: Optional[ReqBody]
    data: str
    verify: bool = False


class Client:
    """
    A class for the client request handling
    """

    def __init__(self, request: Request):
        self.request = request

    def call(self) -> requests.Response:
        try:
            response = requests.request(**self.request.dict(by_alias=True))
            response.raise_for_status()
            return response
        except Exception as exc:
            msg = f'something went wrong with the http call {exc}'
            LOG(msg)
            raise DemistoException(msg) from exc

    def prepare_next_run(self, after: str):
        self.request.data.Script = ''


class GetEvents:
    """
        A class to handle the flow of the integration
    """
    def __init__(self, client: Client) -> None:
        self.client = client

    def call(self) -> list:
        response = self.client.call()
        return response.json().get('Result', {}).get('Results', [])

    def _iter_events(self):
        events = self.call()

        while events:
            yield events

            self.client.prepare_next_run()
            events = self.call()

    def run(self, limit=1000) -> List[dict]:
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

    @staticmethod
    def events_to_incidents(events: list):
        incidents = []

        for event in events:
            incident = {
                'name': f"RedRock records - {event.get('Row', '').get('ID', '')}",
                'occurred': event.get('Row', '').get('WhenOccurred', ''),
                'rawJSON': json.dumps(event['Row'])
            }
            incidents.append(incident)

        demisto.incidents(incidents)


def get_access_token(**kwargs):
    user_name = kwargs.get('credentials', {}).get('identifier')
    password = kwargs.get('credentials', {}).get('password')
    url = f'{kwargs.get("url")}/oauth2/token/{kwargs.get("app_id")}'
    headers = {'Authorization': f"Basic {base64.b64encode(f'{user_name}:{password}'.encode()).decode()}"}
    data = {'grant_type': 'client_credentials', 'scope': 'siem'}

    response = requests.post(url, headers=headers, data=data, verify=not kwargs.get('insecure'))
    json_response = response.json()
    access_token = json_response.get('access_token')

    return {
        'Authorization': f'Bearer {access_token}',
        'Accept': '*/*',
        'Content-Type': 'application/json'
    }


def prepare_request_body(fetch_from: str) -> dict:
    _from = dateparser.parse(fetch_from, settings={'TIMEZONE': 'UTC'}).strftime(DATE_FORMAT)
    to = datetime.now().strftime(DATE_FORMAT)

    return {"Script": f"Select * from Event where WhenOccurred >= '{_from}' and WhenOccurred <= '{to}'"}


def main():
    # Args is always stronger. Get last run even stronger
    demisto_params = demisto.params() | demisto.args() | demisto.getLastRun()
    command = demisto.command()
    demisto.debug(f'Command {command} was called!!!')

    demisto_params['headers'] = ReqHeaders(**get_access_token(**demisto_params))
    # demisto_params['data'] = ReqBody(**prepare_request_body(demisto_params.get('from', '3 days')))
    demisto_params['data'] = json.dumps(prepare_request_body(demisto_params.get('from', '3 days')))
    demisto_params['url'] = demisto.params().get('url', '') + 'RedRock/Query'

    request = Request(**demisto_params)
    client = Client(request)
    get_events = GetEvents(client)

    try:
        if command == 'test-module':
            get_events.run(1)
            demisto.results('ok')
        elif command in ('fetch-events', 'CyberArkIdentity-fetch-events'):
            events = get_events.run(demisto_params.get('max_fetch'))
            if events:
                if command == 'fetch-events':
                    send_events_to_xsiam(events, 'CyberArkIdentity', 'RedRock records')
                if command == 'CyberArkIdentity-fetch-events':
                    get_events.events_to_incidents(events)
                    CommandResults(
                        readable_output=tableToMarkdown('CyberArkIdentity RedRock records', events, removeNull=True, headerTransform=pascalToSpace),
                        outputs_prefix='JiraAudit.Records',
                        outputs_key_field='id',
                        outputs=events,
                        raw_response=events,
                    )
                    demisto.results(CommandResults)
                demisto.setLastRun({'from': events[-1].get('')})
    except Exception as e:
        return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
