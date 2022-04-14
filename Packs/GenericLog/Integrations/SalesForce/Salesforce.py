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

    def _skip_cert_verification(self, skip_cert_verification=skip_cert_verification):
        if not self.request.validate:
            skip_cert_verification()

    def _set_proxy(self):
        if self.options.proxy:
            ensure_proxy_has_http_prefix()
        else:
            skip_proxy()


class GetEvents:
    def __init__(self, client: Client, url, client_id, client_secret, username, password) -> None:
        self.client = client
        self.url = url
        self.client_id = client_id
        self.client_secret = client_secret
        self.username = username
        self.password = password
        self.headers = {}
        self.instance_url = ''
        self.get_token()

    def call(self):
        resp = self.client.call()
        return resp.json()

    def _iter_events(self):
        temp_dir = tempfile.TemporaryDirectory()
        events_list = []

        from_date = '2022-01-01T00:00:00z'
        for line in self.pull_log_files(from_date):
            local_filename = line["LogFile"].replace('/', '_').replace(':', '_')
            file_in_tmp_path = "{}/{}".format(temp_dir.name, local_filename)
            self.get_file_raw_lines(line["LogFile"], file_in_tmp_path)

            for chunk in self.gen_chunks_to_object(file_in_tmp_path, chunksize=2000):
                events_list.extend(chunk)
        return [events_list]

    def get_token(self):
        params = {'grant_type': 'password',
                  'client_id': self.client_id,
                  'client_secret': self.client_secret,
                  'username': self.username,
                  'password': self.password}

        payload_str = "&".join("%s=%s" % (k, v) for k, v in params.items())
        url = urljoin(self.url, 'services/oauth2/token')
        try:
            r = requests.post(url, params=payload_str, verify=False)
        except Exception as err:
            raise DemistoException(f'Failed to get token {err}')
        if r.status_code == 200:
            res = json.loads(r.text)
            self.headers = {'Authorization': f"Bearer {res.get('access_token')}"}
            self.instance_url = res.get('instance_url')
        else:
            raise DemistoException(f'Failed to get token')

    def pull_log_files(self, from_date):
        interval = "hourly"

        if interval == 'hourly':
            query = "SELECT+Id+,+EventType+,+Interval+,+LogDate+,+LogFile+,+LogFileLength" + \
                    "+FROM+EventLogFile" + \
                    f"+WHERE+Interval+=+'Hourly'+and+CreatedDate+>+{from_date}"

        elif interval == 'daily':
            query = "SELECT+Id+,+CreatedDate+,+EventType+,+LogDate+,+LogFile+,+LogFileLength" + \
                    "+FROM+EventLogFile" + \
                    f"+WHERE+LogDate+>+{from_date}"

        demisto.info('Searching files last modified from {}'.format(from_date))

        url = f'https://um6.salesforce.com/services/data/v44.0/query?q={query}'

        r = requests.get(url, headers=self.headers, verify=False)

        if r.status_code == 401:
            self.get_token()
            r = requests.get(url, headers=self.headers, verify=False)

        if r.status_code == 200:
            files = json.loads(r.text)['records']
            done_status = json.loads(r.text)['done']
            while done_status is False:
                query = json.loads(r.text)['nextRecordsUrl']
                try:
                    r = requests.get(f'{instance_url}{query}', headers=headers)
                except Exception as err:
                    demisto.error(f'File list getting failed: {err}')
                if r.status_code == 200:
                    done_status = json.loads(r.text)['done']
                    for file in json.loads(r.text)['records']:
                        files.append(file)
                else:
                    done_status = True
            demisto.info('Total number of files is {}.'.format(len(files)))

            files.sort(key=lambda k: dateparser.parse(k.get('LogDate')))

            #TODO: save the last date and the last id for the next run
            last_date = files[-1].get('LogDate')
            last_id = files[-1].get('Id')

            return files
        else:
            demisto.error(f'File list getting failed: {r.status_code} {r.text}')

    def run(self, limit=10000):
        stored = []
        for logs in self._iter_events():
            stored.extend(logs)
            if len(stored) >= limit:
                return stored[:limit]
        return stored

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
                demisto.info('File successfully downloaded from url {} '.format(url))
            else:
                demisto.info('File downloading failed. {r.status_code} {r.text} {file_url}')
        except Exception as err:
            demisto.error('File downloading failed. {err} {file_url}')

    def gen_chunks_to_object(self, file_in_tmp_path, chunksize=100):
        field_names = [name.lower() for name in list(csv.reader(open(file_in_tmp_path)))[0]]
        field_names = [x if x != 'type' else 'type_' for x in field_names]
        reader = csv.DictReader(open(file_in_tmp_path), fieldnames=field_names)
        chunk = []
        next(reader)
        for index, line in enumerate(reader):
            if index % chunksize == 0 and index > 0:
                yield chunk
                del chunk[:]
            chunk.append(line)
        yield chunk


if __name__ in ('__main__', '__builtin__', 'builtins'):
    # Args is always stronger. Get last run even stronger
    demisto_params = demisto.params() | demisto.args() | demisto.getIntegrationContext()

    request = Request.parse_obj(demisto_params)

    options = Options.parse_obj(demisto_params)

    client = Client(request, options)

    get_events = GetEvents(client)

    command = demisto.command()
    if command == 'test-module':
        get_events.run(limit=1)
        demisto.results('ok')
    else:
        events = get_events.run()

        command_results = CommandResults(
            readable_output=tableToMarkdown('Github events', events, headerTransform=pascalToSpace),
            outputs_prefix='Github.Events',
            outputs_key_field='@timestamp',
            outputs=events,
            raw_response=events,
        )
        return_results(command_results)
