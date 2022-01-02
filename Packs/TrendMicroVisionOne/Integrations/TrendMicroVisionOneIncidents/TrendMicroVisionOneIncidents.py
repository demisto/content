import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from datetime import datetime, timezone, timedelta
import json
import requests

# default settings
V1_URL = 'https://api.xdr.trendmicro.com'


def check_datetime_aware(d):
    return (d.tzinfo is not None) and (d.tzinfo.utcoffset(d) is not None)


class Client(BaseClient):
    base_url_default = V1_URL
    WB_STATUS_IN_PROGRESS = 1

    def __init__(self, token, base_url=None):
        if not token:
            raise ValueError('Authentication token missing')
        self.token = token
        self.base_url = base_url or Client.base_url_default

    def make_headers(self):
        return {
            'Authorization': 'Bearer ' + self.token,
            'Content-Type': 'application/json;charset=utf-8'
        }

    def get(self, path, **kwargs):
        kwargs.setdefault('headers', {}).update(self.make_headers())
        r = requests.get(self.base_url + path, **kwargs)
        if ((200 == r.status_code)
                and ('application/json' in r.headers.get('Content-Type', ''))):
            return r.json()
        raise RuntimeError(f'Request unsuccessful (GET {path}):'
                           f' {r.status_code} {r.text}')

    def put(self, path, **kwargs):
        kwargs.setdefault('headers', {}).update(self.make_headers())
        r = requests.put(self.base_url + path, **kwargs)
        if ((200 == r.status_code)
                and ('application/json' in r.headers.get('Content-Type', ''))):
            return r.json()
        raise RuntimeError(f'Request unsuccessful (PUT {path}):'
                           f' {r.status_code} {r.text}')

    def get_workbench_histories(self, start, end, offset=None, size=None):
        if not check_datetime_aware(start):
            start = start.astimezone()
        if not check_datetime_aware(end):
            end = end.astimezone()
        start = start.astimezone(timezone.utc)
        end = end.astimezone(timezone.utc)
        start = start.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
        end = end.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
        # API returns data in the range of [offset, offset+limit)
        return self.get(
            '/v2.0/xdr/workbench/workbenchHistories',
            params=dict([('startTime', start), ('endTime', end),
                        ('sortBy', 'createdTime')]
                        + ([('offset', offset)] if offset is not None else [])
                        + ([('limit', size)] if size is not None else [])
                        ))['data']['workbenchRecords']

    def update_workbench(self, workbench_id, status):
        return self.put(
            f'/v2.0/xdr/workbench/workbenches/{workbench_id}',
            json={'investigationStatus': status})


def fetch_workbench_alerts(v1, start, end):
    """
    This function do the loop to get all workbench alerts by changing
    the parameters of both 'offset' and 'size'.
    """
    offset = 0
    size = demisto.params().get('max_fetch')
    alerts = []
    while True:
        gotten = v1.get_workbench_histories(start, end, offset, size)
        if not gotten:
            break
        alerts.extend(gotten)
        offset = len(alerts)

    incidents = []
    if alerts:
        for record in alerts:
            incident = {
                'name': record['workbenchName'],
                'occurred': record['createdTime'],
                'rawJSON': json.dumps(record)
            }
            incidents.append(incident)
            last_event = datetime.strptime(record['createdTime'], "%Y-%m-%dT%H:%M:%SZ")

        next_search = last_event + timedelta(0, 1)

        demisto.setLastRun({
            'start_time': next_search.isoformat()
        })

    return incidents


def main():
    v1_token = demisto.params().get('v1_token')
    v1_url = demisto.params().get('v1_url')
    v1 = Client(v1_token, v1_url)

    try:
        if demisto.command() == 'test-module':
            end_time = datetime.now(timezone.utc)
            days = int(demisto.params().get('first_fetch'))
            start_time = end_time + timedelta(days=-days)
            v1.get_workbench_histories(start_time, end_time, 0, 1)
            demisto.results('ok')

        elif demisto.command() == 'fetch-incidents':
            end_time = datetime.now(timezone.utc)
            days = int(demisto.params().get('first_fetch'))
            start_time = end_time + timedelta(days=-days)

            last_run = demisto.getLastRun()
            if last_run and 'start_time' in last_run:
                start_time = datetime.fromisoformat(last_run.get('start_time'))

            incidents = fetch_workbench_alerts(v1, start_time, end_time)
            if incidents:
                demisto.incidents(incidents)
            else:
                demisto.incidents([])

    except Exception as err:
        if demisto.command() == 'fetch-incidents':
            LOG(str(err))
            raise

        demisto.error(traceback.format_exc())
        return_error(str(err))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
