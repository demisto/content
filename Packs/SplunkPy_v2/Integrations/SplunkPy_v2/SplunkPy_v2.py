from splunklib import results
from typing import Dict, Optional, Union, Tuple, List, Any
import splunklib
from splunklib.binding import HTTPError
from splunklib.client import Job

import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]


class SplankPy:
    splunk_time_format: str = "%Y-%m-%dT%H:%M:%S"
    severity_to_level_dict: Dict[str, Union[float, int]] = {
        'informational': 0.5,
        'critical': 4,
        'high': 3,
        'medium': 2
    }

    def __init__(self, host: str, username: str, password: str, port: str = '8089',
                 app: Optional[str] = None, verify: bool = True, proxy: bool = False):
        if not proxy:
            self._service: splunklib.client = splunklib.client.connect(
                host=host,
                port=port,
                app=app,
                username=username,
                password=password,
                verify=verify)

    def __del__(self):
        try:
            self._service.logout()
        except AttributeError as error:
            if not str(error) == "'SplankPy' object has no attribute '_service'":
                raise error

    def _create_job(self, query: str, exec_mode: str = 'normal', app: str = '',
                    earliest_time: Union[str, None] = None, latest_time: str = '', **kwargs) -> Job:
        if earliest_time is None:
            earliest_time = get_default_earliest_time()
        job: Job = self._service.jobs.create(query=query, exec_mode=exec_mode, app=app,
                                             earliest_time=earliest_time, latest_time=latest_time,
                                             **kwargs).disable_preview()
        return job

    def _get_job(self, sid: str) -> Job:
        try:
            return self._service.job(sid)
        except splunklib.binding.HTTPError as error:
            str_error: str = str(error)
            if str_error == 'HTTP 404 Not Found -- Unknown sid.':
                demisto.results("Found no job for sid: {}".format(sid))
            else:
                return_error(str_error, error)

    def _get_splunk_time(self) -> str:
        query: str = '| gentimes start=-1 | eval clock = strftime(time(), "%Y-%m-%dT%H:%M:%S")' \
                     ' | sort 1 -_time | table clock'
        job: Job = self._create_job(query=query, exec_mode='blocking')
        splunk_time: str = SplankPy.ResultReader(job=job).splunk_time()
        job.cancel()
        return splunk_time

    def search(self):
        args: Dict = demisto.args()
        query: str = build_search_query(args.get('query', ''))
        earliest_time: Optional[str] = args.get('earliest_time')
        latest_time: str = args.get('latest_time', '')
        app: str = args.get('app', '')
        job: Job = self._create_job(query=query, earliest_time=earliest_time, latest_time=latest_time, app=app,
                                    exec_mode='blocking')

        result: SplankPy.ResultReader = SplankPy.ResultReader(job)
        limit: Union[int, bool] = int(args.get('event_limit', 100))
        if limit == 0:
            limit = False
        size: int = int(args.get('batch_limit', 2500))
        app: Optional[str] = args.get('app')
        parsed_results, dbot_scores = result.search(limit=limit, size=size, app=app)
        job.cancel()

        if args.get("update_context", 'true') == 'true':
            entry_context: Dict = {
                'Splunk': {'Result': parsed_results},
                'DBotScore': dbot_scores
            }
        else:
            entry_context = {}

        headers: str = 'results' if parsed_results and not isinstance(parsed_results[0], dict) else ''
        human_readable: str = tableToMarkdown(f'Splunk Search results for query: {query}', parsed_results, headers)
        return_outputs(human_readable, entry_context, parsed_results)

    def job_create(self):
        args: Dict = demisto.args()
        query: str = build_search_query(args.get('query', ''))
        app: str = args.get('app', '')
        earliest_time: Optional[str] = args.get('earliest_time')
        latest_time: str = args.get('latest_time', '')
        job: Job = self._create_job(query=query, earliest_time=earliest_time, latest_time=latest_time, app=app)
        entry_context: Dict = {'Splunk': {'Job': job.sid}}
        human_readable: str = f'Splunk Job created with SID: {job.sid}'
        return_outputs(human_readable, entry_context)

    def get_results(self):
        args: Dict = demisto.args()
        sid: str = args.get('sid', '')
        job: Job = self._get_job(sid)
        res, messages = SplankPy.ResultReader(job).get_results()

        for message in messages:
            demisto.results({"Type": 1, "ContentsFormat": "json", "Contents": json.dumps(message)})

        demisto.results({"Type": 1, "ContentsFormat": "json", "Contents": json.dumps(res)})

    def test_module(self):
        if self._service:
            params: Dict = demisto.params()
            if params.get('isFetch', False):
                query_oneshot: str = params.get('fetchQuery', '')
                try:
                    t: datetime = datetime.utcnow() - timedelta(hours=7)
                    _time: str = t.strftime(SplankPy.splunk_time_format)
                    self._service.jobs.oneshot(query_oneshot, count=1, earliest_time=_time)  # type: ignore
                except HTTPError as error:
                    return_error(str(error), error)

            demisto.results('ok')

    def get_indexes(self):
        indexes_data: List[Dict] = []
        for index in self._service.indexes:
            indexes_data.append({
                'name': index.name,
                'count': index["totalEventCount"]
            })
        human_readable: str = tableToMarkdown("Splunk Indexes names", indexes_data)
        return_outputs(human_readable, {}, indexes_data)

    def fetch_incidents(self):
        params: Dict = demisto.params()
        lust_run: Dict = demisto.getLastRun()

        query: str = params.get('fetchQuery', '')
        if 'extractFields' in params:
            query = build_fetch_fields(query=query, fields_csv=params['extractFields'])

        if params.get('useSplunkTime', True):
            latest_time: str = self._get_splunk_time()
        else:
            latest_time = set_latest_time(params.get('timezone'))

        earliest_time: Optional[str] = lust_run.get('time')
        if earliest_time is None:
            earliest_time = set_first_run(params.get('fetch_time', 60), latest_time)

        job_kwargs = {
            params.get("earliest_fetch_time_fieldname", "index_earliest"): earliest_time,
            params.get("latest_fetch_time_fieldname", "index_latest"): latest_time
        }

        job: Job = self._create_job(query=query, exec_mode='blocking', **job_kwargs)

        limit: int = min(params.get('fetch_limit', 50), 200)
        offset: int = int(lust_run.get('offset', 0))
        job_reader: SplankPy.ResultReader = SplankPy.ResultReader(job=job)
        job_result: results.ResultsReader = job_reader.fetch_incidents(index=offset, limit=limit)

        replace: bool = params.get('replaceKeys', False)
        parse_notable_events_raw: bool = params.get('parseNotableEventsRaw', False)
        incidents: List[Dict] = []
        for incident in job_result:
            incidents.append(notable_to_incident(incident, replace=replace,
                                                 parse_notable_events_raw=parse_notable_events_raw))

        if len(incidents) < len(job_reader):
            next_run: Dict = {'time': earliest_time, 'offset': offset + limit}
        else:
            next_run = {'time': latest_time}

        job.cancel()
        demisto.setLastRun(next_run)

    def test(self):
        print(self._get_splunk_time())

    class ResultReader(object):
        def __init__(self, job: Job):
            self.job: Job = job

        def _read(self, index: int = 0, limit: int = 2500) -> results.ResultsReader:
            result = self.job.results(**{'count': index, 'offset': limit})
            return results.ResultsReader(result)

        def __len__(self) -> int:
            return int(self.job['resultCount'])

        def search(self, limit: Union[bool, int] = False, size: int = 2500, app: Optional[str] = None) \
                -> Tuple[List, List]:
            parsed_results: List = []
            dbot_scores: List = []
            for index in range(0, limit if limit else len(self), size):
                if limit and index + size < limit:
                    size = limit - index - 1
                for item in self._read(index, size):
                    if isinstance(item, results.Message):
                        if "Error in" in item.message:
                            raise ValueError(item.message)
                        parsed_results.append(item.message)

                    elif isinstance(item, dict):
                        if item.get('host'):
                            dbot_scores.append({
                                'Indicator': item['host'],
                                'Type': 'hostname',
                                'Vendor': 'Splunk',
                                'Score': 0,
                                'isTypedIndicator': True
                            })
                        if app:
                            item['app'] = app
                        # Normal events are returned as dicts
                        parsed_results.append(item)

            return parsed_results, dbot_scores

        def get_results(self) -> Tuple[List, List]:
            res: List = []
            messages: List = []
            for result in results.ResultsReader(self.job.results()):
                if isinstance(result, results.Message):
                    messages.append(result.message)
                elif isinstance(result, dict):
                    # Normal events are returned as dicts
                    res.append(result)

            return res, messages

        def fetch_incidents(self, index: int = 0, limit: int = 50) -> results.ResultsReader:
            job_results: results.ResultsReader = self._read(index=index, limit=limit)
            return job_results

        def splunk_time(self) -> str:
            res: results.ResultsReader = results.ResultsReader(self.job.results())
            splunk_time: str = ''
            for item in res:
                if isinstance(item, results.Message):
                    splunk_time = item.message["clock"]
                    break
                elif isinstance(item, dict):
                    splunk_time = item["clock"]
                    break
                else:
                    raise ValueError('Error: Could not fetch Splunk time.')
            return splunk_time


def build_search_query(query: str) -> str:
    if not (query.startswith('search') or query.startswith('Search') or query.startswith('|')):
        query = f'search {query}'
    return query


def build_fetch_fields(query: str, fields_csv: str) -> str:
    query_fields: List[str] = []
    for field in fields_csv.split(','):
        if field:
            field = field.strip()
            query_fields.append(f' | eval {field}={field}')
    query += ''.join(query_fields)
    return query


def get_default_earliest_time() -> str:
    t: datetime = datetime.utcnow() - timedelta(days=7)
    return t.strftime(SplankPy.splunk_time_format)


def set_latest_time(time_zone: Optional[str]) -> str:
    latest_time: datetime = datetime.utcnow()
    latest_time = latest_time + timedelta(minutes=int(time_zone)) if time_zone else latest_time
    return latest_time.strftime(SplankPy.splunk_time_format)


def set_first_run(fetch_time: str, latest_time: str) -> str:
    first_run: datetime = datetime.strptime(latest_time, SplankPy.splunk_time_format)
    fetch_time_in_minute: int = int(fetch_time) if fetch_time else 0
    first_run = first_run - timedelta(minutes=fetch_time_in_minute)
    return first_run.strftime(SplankPy.splunk_time_format)


def severity_to_level(severity: str) -> Union[float, int]:
    return SplankPy.severity_to_level_dict.get(severity, 1)


def replace_key_name(_key: str) -> str:
    replace_to: str = '_'
    problematics_characters: List[str] = ['.', '(', ')', '[', ']']
    for char in problematics_characters:
        _key = _key.replace(char, replace_to)
    return _key


def replace_keys(event: Union[Dict[str, str], Any]) -> Union[Dict[str, str], Any]:
    if not isinstance(event, Dict):
        return event
    event_keys: List[str] = list(event.keys())
    for _key in event_keys:
        event[replace_key_name(_key=_key)] = event.pop(_key)
    return event


def raw_to_dict(raw_data: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    if 'message' in raw_data:
        raw_data = raw_data.replace('"', '').replace('message:{', '').strip('{').strip('}')
        key_val_arr: List[str] = raw_data.split(",")
        for key_val in key_val_arr:
            single_key_val: List[str] = key_val.split(":", 1)
            if len(single_key_val) > 1:
                key: str = single_key_val[0]
                val: str = single_key_val[1]

                if key in result.keys():
                    result[key] = f'{result[key]},{val}'
                else:
                    result[key] = val
    else:
        raw_response: List[str] = re.split(r'(?<=\S),', raw_data)  # split by any non-whitespace character
        for key_val in raw_response:
            key_value: str = key_val.replace('"', '').strip()
            if '=' in key_value:
                _key, val = key_value.split('=', 1)
                result[_key] = val
    return result


def notable_to_incident(event: Dict, replace: bool = False, parse_notable_events_raw: bool = False) -> Dict:
    incident: Dict[str, Any] = get_incident_data(event)

    if replace:
        event = replace_keys(event)

    incident["rawJSON"] = json.dumps(event)
    labels: List[Dict[str, str]] = get_incident_labels(event, parse_notable_events_raw)
    if len(labels) > 0:
        incident['labels'] = labels
    return incident


def get_incident_data(event: Dict) -> Dict[str, Union[str, int, float]]:
    incident: Dict[str, Union[str, int, float]] = {
        "name": '{} : {}'.format(event.get('rule_title', ''), event.get('rule_name', ''))
    }
    if 'urgency' in event:
        incident["severity"] = severity_to_level(event['urgency'])
    if 'rule_description' in event:
        incident["details"] = event["rule_description"]
    if "_time" in event:
        incident["occurred"] = event["_time"]
    else:
        incident["occurred"] = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
    return incident


def get_incident_labels(event: Dict, parse_notable_events_raw: bool = False) -> List[Dict[str, str]]:
    labels: List[Dict[str, str]] = []
    if parse_notable_events_raw:
        raw_dict: Dict[str, str] = raw_to_dict(event.get('_raw', ''))
        for raw_key, raw_value in raw_dict.items():
            labels.append({'type': raw_key, 'value': raw_value})
    if 'security_domain' in event:
        labels.append({'type': 'security_domain', 'value': event["security_domain"]})
    return labels


def parse_raw_command():
    args: Dict = demisto.args()
    raw_dict: Dict[str, str] = raw_to_dict(args.get('raw', ''))
    ec = {'Splunk': {'Raw': {'Parsed': raw_dict}}}
    demisto.results({"Type": 1, "ContentsFormat": "json", "Contents": json.dumps(raw_dict), "EntryContext": ec})


def main():
    pass


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
