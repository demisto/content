import demistomock as demisto
from dateutil import parser
from CommonServerPython import *

class Client(BaseClient):
    def __init__(self, base_url: str, client_id: str, access_key: str, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.client_id = client_id
        self.access_key = access_key
        self.token = None

    def _login(self) -> None:
        if self._session.cookies:
            self._session.cookies.clear()

        auth_data = {
            "clientId": self.client_id,
            "accessKey": self.access_key
        }
        res = self._http_request('POST', url_suffix='/auth/external', data=auth_data, resp_type='response')

        if res.status_code == 200:
            self.token = res.json().get("data").get("token")
            demisto.debug(f"Log-in successful! Token: {self.token}")
        else:
            raise DemistoException(f"Log-in failed: {str(res.status_code)}: {res.text}")

    def get_incidents(self, startTS: int, max_fetch: int):
        self._login()
        incidents_url = f"{self._base_url}/app/xdr/api/xdr/v1/incidents"
        headers = {"Authorization": f"Bearer {self.token}"}

        # TODO: Handle max_fetch and startTS properly
        res = self._http_request('GET', url_suffix='/app/xdr/api/xdr/v1/incidents', headers=headers, resp_type='response')
        if res.status_code != 200:
            raise DemistoException(f"Failed to fetch XDR incidents: {str(res.status_code)}: {res.text}")
        incidents = res.json().get("data")
        demisto.debug(f"Fetched {len(incidents)} XDR Incidents.")

        return incidents


def test_module(client: Client, last_run: dict[str, str], first_fetch: datetime):
    try:
        fetch_incidents(client, last_run, first_fetch, 1)
        return 'ok'
    except DemistoException as e:
        return e.message

def map_severity(severity: str) -> int:
    """
    Maps the severity from CheckPoint XDR to XSOAR severity levels.

    Args:
        severity (str): The severity level from CheckPoint XDR.

    Returns:
        int: The corresponding XSOAR severity level.
    """
    severity_mapping = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }
    return severity_mapping.get(severity.lower(), 1)

def parse_incidents(xdr_incidents: list[dict[str, Any]], startTS: int, max_fetch: int):
    incidents: list[dict[str, Any]] = []
    for incident in xdr_incidents.get("incidents", []):
        # Extracting insights and alerts
        insights = incident.get("insights", [])
        alerts = [
            {
                "category": insight.get("attack_family", ""),
                "action_pretty": insight.get("creation_time", ""),
                "description": insight.get("summary", ""),
                "severity": insight.get("severity", "medium"),
                "host_name": next((asset["value"] for asset in insight.get("assets", []) if asset["type"] == "host"), ""),
                "user_name": next((asset["value"] for asset in insight.get("assets", []) if asset["type"] == "user"), ""),
                "detection_timestamp": insight.get("detection_time", ""),
                "name": insight.get("summary", ""),
            }
            for insight in insights
        ]

        # Constructing the XSOAR incident
        incidents.append({
            'type': 'Check Point XDR Incident',
            'dbotMirrorId': incident.get("id", "unknown_id"),
            # "sourceInstance": "CheckPoint XDR Instance",
            "occurred": incident.get("created_at", ""),
            "updated": incident.get("updated_at", ""),
            "CustomFields": {
                # "xdrincidentid": incident.get("id", ""),
                # "xdrurl": f"https://cloudinfra-gw.portal.checkpoint.com/app/xdr/incidents/{incident.get('id', '')}",
                # "xdrdescription": incident.get("summary", ""),
                # "xdralertcount": len(insights),
                # "xdrstatus": incident.get("status", ""),
                # "xdrassignedusermail": "",
                # "xdrassigneduserprettyname": "",
                # "xdrmodificationtime": incident.get("updated_at", ""),
                # "xdralerts": alerts,
                # "xdrfileartifacts": [],
                # "xdrnetworkartifacts": [],
            },
            "severity": map_severity(incident.get("severity", "medium")),
            "name": f"#{incident.get('display_id', '')} - {incident.get('summary', '')}",
            'details': incident.get("summary", ""),
            # "created": incident.get("created_at", ""),
            # "sourceBrand": "CheckPoint XDR",
            'rawJSON': json.dumps(incident)
        })
    # incidents.append({
    #     'type': 'Check Point XDR Incident',
    #     'dbotMirrorId': 'test_id',
    #     'name':'test',
    #     'severity': 1,
    #     'occurred': '2025-05-26T09:48:48.358000Z',
    #     'updated': 1737558099528,
    #     'details': 'Test summary',
    #     'CustomFields': {},
    #     'rawJSON': json.dumps(event)
    # })
    incidents = sorted(
        incidents,
        key=lambda x: parser.isoparse(x['updated']) if x.get('updated') else datetime.utcfromtimestamp(startTS / 1000)
    )
    last_time = (
        parser.isoparse(incidents[-1]['updated']).isoformat()
        if len(incidents) > 0 and incidents[-1].get('updated')
        else datetime.utcfromtimestamp(startTS / 1000).isoformat()
    )

    demisto.debug(f"Made {len(incidents)} XSOAR incidents")
    return incidents, last_time


def fetch_incidents(client: Client, last_run: dict[str, str], first_fetch: datetime, max_fetch: int):
    last_fetch = last_run.get('last_fetch', first_fetch.isoformat())
    last_fetch_time = dateparser.parse(last_fetch)
    if not last_fetch_time:
        raise Exception(f"Invalid last fetch time value '{last_fetch}'")

    startTS = int(last_fetch_time.timestamp() * 1000)
    xdr_incidents = client.get_incidents(startTS, max_fetch)
    incidents, last_insight_time = parse_incidents(xdr_incidents, startTS, max_fetch)

    return {'last_fetch': last_insight_time}, incidents


def main() -> None:  # pragma: no cover
    params = demisto.params()

    base_url = params.get('url', "")
    client_id = params.get('credentials', {}).get('identifier')
    access_key = params.get('credentials', {}).get('password')
    verify = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    max_fetch = int(params.get('max_fetch', 1000))

    fetch_time = params.get('first_fetch', '3 days').strip()
    first_fetch = dateparser.parse(fetch_time, settings={'TIMEZONE': 'UTC'})
    if not first_fetch:
        raise Exception(f"Invalid first fetch time value '{fetch_time}', must be '<number> <time unit>', e.g., '24 hours'")

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        client = Client(base_url, client_id, access_key, verify, proxy)
        last_run = demisto.getLastRun()
        if command == 'test-module':
            return_results(test_module(client, last_run, first_fetch))
        elif command == 'fetch-incidents':
            next_run, incidents = fetch_incidents(client, last_run, first_fetch, max_fetch)
            demisto.incidents(incidents)
            demisto.debug(f"Set last run to {next_run.get('last_fetch')}")
            demisto.setLastRun(next_run)

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
