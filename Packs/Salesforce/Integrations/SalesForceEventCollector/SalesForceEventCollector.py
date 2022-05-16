from enum import Enum
import urllib3
from CommonServerPython import *
import demistomock as demisto
from pydantic import BaseModel, AnyUrl, Json  # pylint: disable=no-name-in-module
from collections.abc import Generator
import tempfile
import requests
import csv


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


class Request(BaseModel):
    """
    A class that stores a request configuration
    """
    method: Method = Method.POST
    url: AnyUrl
    headers: Optional[Union[Json[dict], dict]]
    verify = True
    data: Optional[str] = None


class Client:
    """
    A class for the client request handling
    """

    def __init__(self, request: Request):
        self.request = request

    def call(self, requests=requests) -> requests.Response:
        try:
            response = requests.request(**self.request.dict())
            response.raise_for_status()
            return response
        except Exception as exc:
            msg = f'something went wrong with the http call {exc}'
            LOG(msg)
            raise DemistoException(msg) from exc


class GetEvents:
    """
    A class to handle the flow of the integration
    """
    def __init__(self, client: Client, insecure: bool, query: str, after: str, last_id: str) -> None:
        self.client: Client = client
        self.insecure: bool = insecure
        self.headers: dict = {}
        self.instance_url: str = ''
        self.query: str = query
        self.limit: int = 0
        self.after: str = after
        self.last_id: str = last_id
        self.get_token()

    def get_token(self):
        res = self.client.call().json()
        self.headers = {'Authorization': f"Bearer {res.get('access_token')}"}
        self.instance_url = res.get('instance_url')

    def pull_log_files(self):
        query = f'{self.query}+and+CreatedDate+>+{self.after} limit {self.limit}'

        demisto.info('Searching files last modified from {}'.format(self.after))

        url = f'https://um6.salesforce.com/services/data/v44.0/query?q={query}'

        r = requests.get(url, headers=self.headers, verify=self.insecure)

        if r.status_code == 401:
            self.get_token()
            r = requests.get(url, headers=self.headers, verify=self.insecure)

        if r.status_code == 200:
            res = json.loads(r.text)
            return self.get_files_from_res(res)
        else:
            demisto.error(f'File list getting failed: {r.status_code} {r.text}')

    def get_files_from_res(self, query_res):
        r = None
        files = query_res['records']
        done_status = query_res['done']

        while done_status is False:
            query = query_res['nextRecordsUrl']
            try:
                r = requests.get(f'{self.instance_url}{query}', headers=self.headers)
            except Exception as err:
                demisto.error(f'File list getting failed: {err}')
            if r.status_code == 200:
                res = json.loads(r.text)
                done_status = res['done']
                for file in res['records']:
                    files.append(file)
            else:
                done_status = True

        demisto.info('Total number of files is {}.'.format(len(files)))

        # sort all files by date
        files.sort(key=lambda k: dateparser.parse(k.get('LogDate')))

        if not self.last_id:
            return files

        # filter only the files we already fetched to avoid duplicates
        last_id_found = False
        new_files = []
        for file in files:
            if last_id_found:
                new_files.append(file)

            if file['Id'] == self.last_id:
                last_id_found = True

        if new_files:
            demisto.setLastRun(self.get_last_run(new_files))
        return new_files

    def get_file_raw_lines(self, file_url, file_in_tmp_path):
        url = f'{self.instance_url}{file_url}'
        try:
            r = requests.get(url, stream=True, headers=self.headers)
            if r.status_code == 401:
                self.get_token()
                r = requests.get(url, stream=True, headers=self.headers)

            with open(file_in_tmp_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=1024 * 1024):
                    if chunk:  # filter out keep-alive new chunks
                        f.write(chunk)
            if r.status_code == 200:
                demisto.info(f'File successfully downloaded from url {url}')
            else:
                demisto.info(f'File downloading failed. {r.status_code} {r.text} {file_url}')
        except Exception as err:
            demisto.error(f'File downloading failed. {err} {file_url}')

    @staticmethod
    def gen_chunks_to_object(file_in_tmp_path, chunksize=100):
        field_names = [name.lower() for name in list(csv.reader(open(file_in_tmp_path)))[0]]
        field_names = [x if x != 'type' else 'type_' for x in field_names]
        reader = csv.DictReader(open(file_in_tmp_path), fieldnames=field_names)
        chunk: list = []
        next(reader)
        for index, line in enumerate(reader):
            if index % chunksize == 0 and index > 0:
                yield chunk
                del chunk[:]
            chunk.append(line)
        yield chunk

    def _iter_events(self) -> Generator:
        temp_dir = tempfile.TemporaryDirectory()

        for line in self.pull_log_files():
            events_list = []
            local_filename = line["LogFile"].replace('/', '_').replace(':', '_')
            file_in_tmp_path = "{}/{}".format(temp_dir.name, local_filename)
            self.get_file_raw_lines(line["LogFile"], file_in_tmp_path)

            for chunk in self.gen_chunks_to_object(file_in_tmp_path=file_in_tmp_path, chunksize=2000):
                events_list.extend(chunk)

            yield events_list

    def aggregated_results(self, limit) -> List[dict]:
        """
        Function to group the events returned from the api
        """
        self.limit = limit
        stored_events = []
        for events in self._iter_events():
            stored_events.extend(events)
        return stored_events

    @staticmethod
    def get_last_run(files: List[dict]) -> dict:
        """
        Get the info from the last run, it returns the time to query from and a list of ids to prevent duplications
        """
        last_file = files[-1]
        last_timestamp = last_file['LogDate']
        timestamp = dateparser.parse(last_timestamp)
        if timestamp is None:
            raise TypeError('Failed to parse LogDate')
        return {'after': timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
                'last_id': last_file['Id']}


def get_timestamp_format(value):
    timestamp: Optional[datetime]
    if isinstance(value, int):
        value = str(value)
    if not isinstance(value, datetime):
        timestamp = dateparser.parse(value)
    if timestamp is None:
        raise TypeError(f'after is not a valid time {value}')
    return timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")


def main():
    # Args is always stronger. Get last run even stronger
    demisto_params = demisto.params() | demisto.args() | demisto.getLastRun()

    demisto_params['client_id'] = demisto_params['client_id']['password']
    demisto_params['client_secret'] = demisto_params['client_secret']['password']
    demisto_params['password'] = demisto_params['password']['password']

    events_to_add_per_request = demisto_params.get('events_to_add_per_request', 1000)
    try:
        events_to_add_per_request = int(events_to_add_per_request)
    except ValueError:
        events_to_add_per_request = 1000

    request = Request(**demisto_params)

    url = urljoin(demisto_params.get("url"), 'services/oauth2/token')
    request.url = f'{url}?grant_type=password&' \
                  f'client_id={demisto_params.get("client_id")}&' \
                  f'client_secret={demisto_params.get("client_secret")}&' \
                  f'username={demisto_params.get("username")}&' \
                  f'password={demisto_params.get("password")}'

    client = Client(request)

    after = get_timestamp_format(demisto_params.get('after'))

    get_events = GetEvents(client, demisto_params.get('verify'),
                           demisto_params.get('query'), after, demisto_params.get('last_id'))

    command = demisto.command()
    try:
        urllib3.disable_warnings()

        if command == 'test-module':
            get_events.aggregated_results(limit=1)
            return_results('ok')
        elif command in ('salesforce-get-events', 'fetch-events'):
            events = get_events.aggregated_results(limit=int(demisto_params.get('limit')))

            if command == 'fetch-events':
                while len(events) > 0:
                    send_events_to_xsiam(events[:events_to_add_per_request], 'salesforce-audit', 'salesforce-audit')
                    events = events[events_to_add_per_request:]
            elif command == 'salesforce-get-events':
                command_results = CommandResults(
                    readable_output=tableToMarkdown('salesforce Logs', events, headerTransform=pascalToSpace),
                    outputs_prefix='salesforce.Logs',
                    outputs_key_field='timestamp',
                    outputs=events,
                    raw_response=events,
                )
                return_results(command_results)
    except Exception as e:
        return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
