import urllib3
import demistomock as demisto
from CommonServerPython import *

# Disable insecure warnings
urllib3.disable_warnings()

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
NDR_URL = 'https://now.checkpoint.com'


class Client(BaseClient):
    def __init__(self, base_url: str, client_id: str, access_key: str, domain: str, verify: bool, proxy: bool):

        super().__init__(base_url=base_url, verify=verify, proxy=proxy)

        self.client_id = client_id
        self.access_key = access_key
        self.domain = domain

    def _login(self) -> None:
        auth_data = {"selectedRealm": "ssl_vpn_Username_Password",
                     "userName": self.client_id,
                     "password": self.access_key}

        if self._session.cookies:
            self._session.cookies.clear()

        res = self._http_request('POST', url_suffix='/Login/LoginAPI', data=auth_data, resp_type='response')

        if res.status_code == 200:
            demisto.debug(f"Log-in successful, new API endpoint is: {res.url}")
            self._base_url = res.url
        else:
            raise DemistoException(f"Log-in failed: {str(res.status_code)}: {res.text}")

    def _logout(self) -> None:
        if self._session.cookies:
            self._http_request('POST', url_suffix='/../Portal/SignOut', resp_type='response')

    def _call_api(self,
                  url_suffix: str,
                  method: str = "GET",
                  params: Optional[dict[str, Any]] = None,
                  json_data: Optional[dict[str, Any]] = None) -> list[dict[str, Any]]:

        res_json = self._http_request(
            method,
            url_suffix=f'/incidents/v1/{url_suffix}',
            headers={'domain': self.domain},
            params=params,
            json_data=json_data
        )

        if res_json.get('status') and res_json.get('status') == "error":
            raise DemistoException(f"API call failed: {res_json.get('message')}")
        return res_json.get('objects')

    def test_api(self) -> None:
        self._login()
        self._logout()

    def get_events(self, startTS: int) -> tuple[list[dict[str, Any]], datetime]:
        incidents = []
        lastTS = startTS

        self._login()
        insights = self._call_api('insights', params={'updated': f"gt.{startTS}"})
        demisto.debug(f"Fetched {len(insights)} NDR Insights")

        for insight in insights:
            lastTS = max(lastTS, insight['updated'])
            ids = ','.join(map(str, insight['events']))
            events = self._call_api('events', params={'id': ids})
            demisto.debug(f"Fetched {len(events)} events of {insight['id']} Insights")

            for event in events:
                if event['created'] < startTS:
                    continue

                id = f"{insight['id']}_{event['id']}"
                name = insight['data'].get('name', insight['criteria'])
                updated = int(event['data'].get('discovery_date', event['updated']))
                desc_i = insight['data'].get('description', '')
                desc_e = event['data'].get('description', '')
                description = desc_i + "\n" + desc_e if desc_e else desc_i

                incidents.append({
                    'id': id,
                    'insight_id': insight['id'],
                    'event_id': event['id'],
                    'name': name,
                    'updated': updated,
                    'from': event['from'],
                    'to': event['to'],
                    'detections': event['count'],
                    'insight_description': desc_i,
                    'event_description': desc_e,
                    'description': description,
                    'probability': event['probability']
                })
        self._logout()
        last_time = datetime.fromtimestamp(lastTS / 1000)

        return incidents, last_time


def test_module(client: Client):
    try:
        client.test_api()
        return 'ok'
    except DemistoException as e:
        return e.message


def fetch_incidents(client: Client, last_run: dict[str, str], first_fetch: datetime, domain: str):
    last_fetch = last_run.get('last_fetch', first_fetch.isoformat())
    last_fetch_time = dateparser.parse(last_fetch)
    if not last_fetch_time:
        raise Exception(f"Invalid last fetch time value '{last_fetch}'")

    events, last_insight_time = client.get_events(int(last_fetch_time.timestamp() * 1000))
    demisto.debug(f"Fetched {len(events)} NDR events with insights")

    incidents: list[dict[str, Any]] = []
    for event in events:
        link = f"{NDR_URL}/#/insights?id={event['insight_id']}&domain={domain}&startDate={event['from']}&endDate={event['to']}"
        severity = 3
        if event['probability'] < 60:
            severity = 1
        elif event['probability'] < 80:
            severity = 2

        incidents.append({
            'type': 'Check Point NDR Insight',
            'dbotMirrorId': event['id'],
            'name': event['name'],
            'severity': severity,
            'occurred': datetime.utcfromtimestamp(event['updated'] / 1000).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            'details': event['description'],
            'CustomFields': {
                'externalstarttime': datetime.utcfromtimestamp(event['from'] / 1000).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                'externalendtime': datetime.utcfromtimestamp(event['to'] / 1000).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                'externallink': link,
                'description': event['insight_description'],
                'eventdescriptions': event['event_description']
            },
            'rawJSON': json.dumps(event)
        })

    return {'last_fetch': last_insight_time.isoformat()}, incidents


def main() -> None:  # pragma: no cover
    params = demisto.params()

    base_url = params.get('url', "")
    client_id = params.get('credentials', {}).get('identifier')
    access_key = params.get('credentials', {}).get('password')
    domain = params.get('domain', "")
    verify = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    fetch_time = params.get('first_fetch', '3 days').strip()
    first_fetch = dateparser.parse(fetch_time, settings={'TIMEZONE': 'UTC'})
    if not first_fetch:
        raise Exception(f"Invalid first fetch time value '{fetch_time}', must be '<number> <time unit>', e.g., '24 hours'")

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        client = Client(base_url, client_id, access_key, domain, verify, proxy)
        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'fetch-incidents':
            last_run = demisto.getLastRun()
            next_run, incidents = fetch_incidents(client, last_run, first_fetch, domain)
            demisto.incidents(incidents)
            demisto.debug(f"Set last run to {next_run.get('last_fetch')}")
            demisto.setLastRun(next_run)

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
