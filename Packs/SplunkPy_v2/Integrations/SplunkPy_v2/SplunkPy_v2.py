from typing import Dict, Optional, Union

import splunklib
from splunklib.binding import HTTPError
from splunklib.client import Job

import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]


class SplankPy:
    splunk_time_format: str = "%Y-%m-%dT%H:%M:%S"

    def __init__(self, host: str, username: str, password: str, port: str = '8089',
                 app: Optional[str] = None, verify: bool = True, proxy: bool = False):
        if not proxy:
            self.service = splunklib.client.connect(
                host=host,
                port=port,
                app=app,
                username=username,
                password=password,
                verify=verify)

    def __del__(self):
        self.service.logout()

    def create_job(self, query: str, exec_mode: str = 'normal', app='',
                   earliest_time: Union[str, None] = None, latest_time: str = '') -> Job:
        if earliest_time is None:
            earliest_time = get_default_earliest_time()
        job: Job = self.service.jobs.create(query=query, exec_mode=exec_mode, app=app,
                                            earliest_time=earliest_time, latest_time=latest_time).disable_preview()
        return job

    def get_results(self, sid: str):
        try:
            job = self.service.job(sid)
        except splunklib.binding.HTTPError as error:
            str_error = str(error)
            if str_error == 'HTTP 404 Not Found -- Unknown sid.':
                demisto.results("Found no job for sid: {}".format(sid))
            else:
                return_error(str_error, error)


def build_search_query(query: str) -> str:
    if not (query.startswith('search') or query.startswith('Search') or query.startswith('|')):
        query = f'search {query}'
    return query


def get_default_earliest_time() -> str:
    t = datetime.utcnow() - timedelta(days=7)
    return t.strftime(SplankPy.splunk_time_format)


def splunk_job_create_command(client: SplankPy):
    args: Dict = demisto.args()
    query: str = build_search_query(args.get('query', ''))
    app: Optional[str] = args.get('app')
    earliest_time: Optional[str] = args.get('earliest_time')
    latest_time: Optional[str] = args.get('latest_time')
    job = client.create_job(query=query, earliest_time=earliest_time, latest_time=latest_time, app=app)
    entry_context = {'Splunk': {'Job': job.sid}}
    human_readable = f'Splunk Job created with SID: {job.sid}'
    return_outputs(human_readable, entry_context)


def main():
    client = SplankPy(
        host="18.197.250.188",
        username="admin",
        password="188baQ@M3qg0LAZL",
        verify=False
    )
    q = 'sourcetype=*'
    t = client.get_results('11')
    # t.cancel()


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
