from datetime import datetime
from enum import Enum
import urllib3
import csv
from CommonServerPython import *
import demistomock as demisto
from pydantic import BaseConfig, BaseModel, AnyUrl, Json, validator
import requests
import dateparser
import tempfile
from requests.auth import HTTPBasicAuth

urllib3.disable_warnings()


def convert_to_github_date(value: Union[str, datetime, int]) -> str:
    """Converting int(epoch), str(3 days) or datetime to github's api time"""
    timestamp: Optional[datetime]
    if isinstance(value, int):
        value = str(value)
    if not isinstance(value, datetime):
        timestamp = dateparser.parse(value)
    if timestamp is None:
        raise TypeError(f'after is not a valid time {value}')
    timestamp_epoch = timestamp.timestamp() * 1000
    str_bytes = f'{timestamp_epoch}|'.encode('ascii')
    base64_bytes = base64.b64encode(str_bytes)
    return base64_bytes.decode('ascii')


class Method(str, Enum):
    GET = 'GET'
    POST = 'POST'
    PUT = 'PUT'
    HEAD = 'HEAD'
    PATCH = 'PATCH'
    DELETE = 'DELETE'


class Options(BaseModel):
    proxy: bool = False


class Request(BaseModel):
    method: Method
    url: AnyUrl
    headers: Union[Json, dict] = {}
    params: Optional[BaseModel]
    verify: bool = True
    data: Optional[str] = None
    auth: Optional[HTTPBasicAuth]

    class Config(BaseConfig):
        arbitrary_types_allowed = True


class ReqParams(BaseModel):  # TODO: implement request params (if any)
    password: str
    username: str
    client_secret: str
    client_id: str
    grant_type: str


class Args(BaseModel):
    limit: int = 10


class Client:
    def __init__(self, request: Request, options: Options, session=requests.Session()):
        self.request = request
        self.options = options
        self.session = session
        self._set_proxy()
        self._skip_cert_verification()

    def __del__(self):
        try:
            self.session.close()
        except AttributeError as err:
            demisto.debug(f'ignore exceptions raised due to session not used by the client. {err=}')

    def call(self) -> requests.Response:
        try:
            response = self.session.request(**self.request.dict())
            response.raise_for_status()
            return response
        except Exception as exc:
            msg = f'something went wrong with the http call {exc}'
            LOG(msg)
            raise DemistoException(msg) from exc

    def set_from_time_filter(self, after: Any):
        """TODO: set the next time to fetch"""
        self.request.params.after = convert_to_github_date(after)  # type: ignore[union-attr]

    def _skip_cert_verification(self, skip_cert_verification=skip_cert_verification):
        if not self.request.validate:
            skip_cert_verification()

    def _set_proxy(self):
        if self.options.proxy:
            ensure_proxy_has_http_prefix()
        else:
            skip_proxy()


class GetEvents:
    def __init__(self, client: Client) -> None:
        self.client = client

    def call(self):
        resp = self.client.call()
        return resp.json()

    def _iter_events(self):
        temp_dir = tempfile.TemporaryDirectory()
        events = []
        res = self.call()
        for file in res.get('records', []):
            local_filename = file["LogFile"].replace('/', '_').replace(':', '_')
            file_in_tmp_path = "{}/{}".format(temp_dir.name, local_filename)
            self.get_file_raw_lines(file["LogFile"], file_in_tmp_path)

            for chunk in self.gen_chunks_to_object(file_in_tmp_path, chunksize=2000):
                events.extend(chunk)
        return events

    def run(self, limit=10):
        stored = []
        for logs in self._iter_events():
            stored.extend(logs)
            if len(stored) >= limit:
                return stored[:limit]
        return stored

    @staticmethod
    def get_last_run(logs) -> dict:
        """TODO: Implement the last run (from previous logs)"""
        last_time = logs[-1].get('@timestamp') / 1000
        next_fetch_time = datetime.fromtimestamp(last_time) + timedelta(
            seconds=1
        )
        return {'after': next_fetch_time.isoformat()}


    def get_file_raw_lines(self, file_url, file_in_tmp_path):
        instance_url = 'https://d4k0000039io4uae-dev-ed.my.salesforce.com'
        headers = {}
        headers['Authorization'] = f"Bearer XXXX"
        url = f'{instance_url}{file_url}'
        try:
            with requests.get(url, stream=True, headers=headers) as r:
                with open(file_in_tmp_path, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=1024 * 1024):
                        if chunk:  # filter out keep-alive new chunks
                            f.write(chunk)
                if r.status_code == 200:
                    print('File successfully downloaded from url {} '.format(url))
                else:
                    print('File downloading failed. {r.status_code} {r.text} {file_url}')
        except Exception as err:
            print('File downloading failed. {err} {file_url}')


    def gen_chunks(self, file_in_tmp_path):
        events = []
        for chunk in self.gen_chunks_to_object(file_in_tmp_path, chunksize=2000):
            events.extend(chunk)

        return events


    def gen_chunks_to_object(self, file_in_tmp_path, chunksize=100):
        field_names = [name.lower() for name in list(csv.reader(open(file_in_tmp_path)))[0]]
        field_names = [x if x != 'type' else 'type_' for x in field_names]
        reader = csv.DictReader(open(file_in_tmp_path), fieldnames=field_names)
        chunk = []
        next(reader)
        for index, line in enumerate(reader):
            if (index % chunksize == 0 and index > 0):
                yield chunk
                del chunk[:]
            chunk.append(line)
        yield chunk


if __name__ in ('__main__', '__builtin__', 'builtins'):
    # Args is always stronger. Get last run even stronger
    demisto_params = demisto.params() | demisto.args() | demisto.getIntegrationContext()

    demisto_params = {'method': 'POST',
                      'url': 'https://um6.salesforce.com/services/oauth2/token?grant_type=password&client_id=XXXXXX&client_secret=XXXXXX&username=XXXXXX&password=XXXXXX',
                      'verify': False}

    request = Request.parse_obj(demisto_params)



    # demisto_params = {'method': 'POST',
    #                   'url': 'https://um6.salesforce.com/services/oauth2/token',
    #                   'grant_type': 'password',
    #                   'client_id': 'XXXXXX',
    #                   'client_secret': 'XXXXXX',
    #                   'username': 'XXXXXX',
    #                   'password': 'XXXXXX',
    #                   'verify': False}
    #
    # demisto_params['params'] = ReqParams.parse_obj(demisto_params)
    # request = Request.parse_obj(demisto_params)



    # url = "https://um6.salesforce.com/services/oauth2/token"

    # url = "https://um6.salesforce.com/services/oauth2/token?grant_type=password&client_id=XXXXXX&client_secret=XXXXXX&username=XXXXXX&password=XXXXXX"


    # params =  {'grant_type': 'password',
    #                   'client_id': 'XXXXXX',
    #                   'client_secret': 'XXXXXX',
    #                   'username': 'XXXXXX',
    #                   'password': 'XXXXXX'}
    #
    #
    # response = requests.post(url, params = params, verify = False)
    #
    # print(response.text.encode('utf8'))



    demisto_params = {'method': 'GET',
                      'url': 'https://um6.salesforce.com/services/data/v54.0/query?q=SELECT+Id+,+EventType+,+LogFile+,+LogDate+,+LogFileLength+FROM+EventLogFile',
                      'verify': False}


    request = Request.parse_obj(demisto_params)

    request.headers['Authorization'] = f"Bearer XXXXXX"


    options = Options.parse_obj(demisto_params)

    client = Client(request, options)

    get_events = GetEvents(client)

    command = demisto.command()
    if command == 'test-module':
        get_events.run(limit=1)
        demisto.results('ok')
    else:
        args = Args(**demisto_params)
        events = get_events.run(args.limit)

        if events:
            demisto.setIntegrationContext(GetEvents.get_last_run(events))
        command_results = CommandResults(
            readable_output=tableToMarkdown('Github events', events, headerTransform=pascalToSpace),
            outputs_prefix='Github.Events',
            outputs_key_field='@timestamp',
            outputs=events,
            raw_response=events,
        )
        return_results(command_results)
