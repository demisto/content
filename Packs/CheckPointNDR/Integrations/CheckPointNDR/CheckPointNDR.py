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

    def get_insights(self, startTS: int, max_fetch: int):
        self._login()
        insights = self._call_api('insights', params={'updated': f"gt.{startTS}"})
        demisto.debug(f"Fetched {len(insights)} NDR Insights, processing {min(len(insights), max_fetch)} of them...")

        insights = sorted(insights, key=lambda x: x['updated'])[:max_fetch]
        for insight in insights:
            ids = ','.join(map(str, insight['events']))
            insight['events'] = self._call_api('events', params={'id': ids})
            demisto.debug(f"Fetched {len(insight['events'])} events of Insight {insight['id']}")

        self._logout()

        return insights


def test_module(client: Client, last_run: dict[str, str], first_fetch: datetime, domain: str):
    try:
        fetch_incidents(client, last_run, first_fetch, domain, 1, 0)
        return 'ok'
    except DemistoException as e:
        return e.message


def parse_insights(insights: list[dict[str, Any]], domain: str, startTS: int, max_fetch: int, min_probability: int):
    incidents: list[dict[str, Any]] = []
    for insight in insights:
        for event in insight['events']:
            if event['updated'] <= startTS:
                continue
            if event['probability'] < min_probability:
                continue

            id = f"{insight['id']}_{event['id']}"
            name = insight['data'].get('name', insight['criteria'])
            updated = int(event['data'].get('discovery_date', event['updated']))
            desc_i = insight['data'].get('description', '')
            desc_e = event['data'].get('description', '')
            statistics = event['data'].get('statistics', {})
            description = desc_i + "\n" + desc_e if desc_e else desc_i
            link = f"{NDR_URL}/#/insights?id={insight['id']}&domain={domain}&startDate={event['from']}&endDate={event['to']}"
            severity = 3
            if event['probability'] < 60:
                severity = 1
            elif event['probability'] < 80:
                severity = 2

            incidents.append({
                'type': 'Check Point NDR Insight',
                'dbotMirrorId': id,
                'name': name,
                'severity': severity,
                'occurred': datetime.utcfromtimestamp(updated / 1000).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                'updated': event['updated'],
                'details': description,
                'CustomFields': {
                    'externalstarttime': datetime.utcfromtimestamp(event['from'] / 1000).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                    'externalendtime': datetime.utcfromtimestamp(event['to'] / 1000).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                    'externallink': link,
                    'description': desc_i,
                    'eventdescriptions': desc_e,
                    'sourceips': statistics.get('top_src', []),
                    'sourceexternalips': statistics.get('top_proxy_src_ip', []),
                    'destinationips': statistics.get('top_dst', []),
                    'dstports': statistics.get('top_service', []),
                    'filemd5': statistics.get('top_file_md5', []),
                    'appiName': statistics.get('top_appi_name', []),
                    'users': statistics.get('top_src_user_name', []),
                    'hostnames': statistics.get('top_src_machine_name', []),
                    'sentbytes': statistics.get('total_bytes_sent', 0),
                    'receivedbytes': statistics.get('total_bytes_received', 0)
                },
                'rawJSON': json.dumps(event)
            })

    incidents = sorted(incidents, key=lambda x: x['updated'])[:max_fetch]
    last_time = datetime.fromtimestamp((incidents[-1]['updated'] if len(incidents) > 0 else startTS) / 1000).isoformat()

    demisto.debug(f"Made {len(incidents)} XSOAR incidents")
    return incidents, last_time


def fetch_incidents(client: Client, last_run: dict[str, str], first_fetch: datetime, domain: str, max_fetch: int,
                    min_probability: int):
    last_fetch = last_run.get('last_fetch', first_fetch.isoformat())
    last_fetch_time = dateparser.parse(last_fetch)
    if not last_fetch_time:
        raise Exception(f"Invalid last fetch time value '{last_fetch}'")

    startTS = int(last_fetch_time.timestamp() * 1000)
    insights = client.get_insights(startTS, max_fetch)
    incidents, last_insight_time = parse_insights(insights, domain, startTS, max_fetch, min_probability)

    return {'last_fetch': last_insight_time}, incidents


def main() -> None:  # pragma: no cover
    params = demisto.params()

    base_url = params.get('url', "")
    client_id = params.get('credentials', {}).get('identifier')
    access_key = params.get('credentials', {}).get('password')
    domain = params.get('domain', "")
    verify = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    max_fetch = int(params.get('max_fetch', 1000))
    min_probability = int(params.get('min_probability', 0))

    fetch_time = params.get('first_fetch', '3 days').strip()
    first_fetch = dateparser.parse(fetch_time, settings={'TIMEZONE': 'UTC'})
    if not first_fetch:
        raise Exception(f"Invalid first fetch time value '{fetch_time}', must be '<number> <time unit>', e.g., '24 hours'")

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        client = Client(base_url, client_id, access_key, domain, verify, proxy)
        last_run = demisto.getLastRun()
        if command == 'test-module':
            return_results(test_module(client, last_run, first_fetch, domain))
        elif command == 'fetch-incidents':
            next_run, incidents = fetch_incidents(client, last_run, first_fetch, domain, max_fetch, min_probability)
            demisto.incidents(incidents)
            demisto.debug(f"Set last run to {next_run.get('last_fetch')}")
            demisto.setLastRun(next_run)

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
