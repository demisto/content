import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from typing import Any, Dict, Union, Optional

ORCA_API_DNS_NAME = "https://orcadeveden-internal-dev.orcasecurity.net/api"
DEMISTO_OCCURRED_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


class OrcaClient:
    def __init__(self, client: BaseClient):
        self.client = client

    def get_alerts_by_type(self, alert_type: Optional[str] = None) -> Union[List[Dict[str, Any]], str]:  # pylint: disable=E1136
        demisto.info("get_alerts, enter")
        url_suffix = "/alerts"
        if alert_type:
            url_suffix = f"{url_suffix}?type={alert_type}"
        response = self.client._http_request(method="GET", url_suffix=url_suffix)

        if response['status'] != 'success':
            return response['error']

        alerts = response["data"]
        return alerts

    def get_all_alerts(self) -> List[Dict[str, Any]]:
        demisto.info("get_all_alerts, enter")

        alerts: List[Dict[str, Any]] = []
        params: Dict[str, str] = {}
        next_page_token = None

        while True:
            if next_page_token:
                params = {"next_page_token": next_page_token}

            response = self.client._http_request(method="GET", url_suffix="/query/alerts", params=params)
            if response['status'] != 'success':
                demisto.info(f"got bad response, {response['error']}")
                return response['error']

            alerts = alerts + response["data"]

            if "next_page_token" not in response:
                # that was the last chunk
                break
            else:
                next_page_token = response.get("next_page_token")

        demisto.info(f"done fetching orca alerts, fetched {len(alerts)} alerts")

        return alerts

    def get_asset(self, asset_unique_id: str) -> Union[List[Dict[str, Any]], str]:  # pylint: disable=E1136
        demisto.debug("get_asset, enter")
        try:
            response = self.client._http_request(method="GET", url_suffix=f"/assets/{asset_unique_id}")
        except DemistoException:
            return f"could not find {asset_unique_id}"

        if 'error' in response or not response:
            return "Asset Not Found"

        return response


def map_orca_score_to_demisto_score(orca_score: int) -> int:
    MAPPING = {1: 1, 2: 1, 3: 2, 4: 3}
    return MAPPING[orca_score]


def fetch_incidents(orca_client: OrcaClient) -> List[Dict[str, Any]]:
    demisto.debug("fetch-incidents called")
    if demisto.getLastRun().get('lastRun'):
        demisto.info("not first run, returning")
        # only first run is relevant, other incidents are dynamically pushed from Kafka
        demisto.incidents([])
        return []

    alerts = orca_client.get_all_alerts()
    if not alerts:
        demisto.incidents([])
        return []

    incidents = []
    for alert in alerts:
        alert['demisto_score'] = map_orca_score_to_demisto_score(orca_score=alert.get("state", {}).get("score", 1))
        incident = {
            'name': f"Orca Cloud Incident: {alert.get('state', {}).get('alert_id')}.",
            'occurred': datetime_to_string(
                datetime.strptime(alert.get('state', {}).get('last_seen'), "%Y-%m-%dT%H:%M:%S%z").isoformat()),
            'rawJSON': json.dumps(alert),
            'severity': map_orca_score_to_demisto_score(orca_score=alert.get('state', {}).get('score'))
        }
        incidents.append(incident)

    demisto.setLastRun({'lastRun': datetime.now().strftime(DEMISTO_OCCURRED_FORMAT)})
    demisto.incidents(incidents)
    return incidents


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    try:
        command = demisto.command()
        demisto.debug(f'Orca Command being called is {command}')
        api_key = demisto.params().get('apikey')

        client = BaseClient(
            base_url=ORCA_API_DNS_NAME,
            verify=True,
            headers={
                'Authorization': f'Bearer {api_key}'
            },
            proxy=True)

        orca_client = OrcaClient(client=client)
        if command == "orca-get-alerts":
            alerts = orca_client.get_alerts_by_type(alert_type=demisto.args().get('alert_type'))
            if not alerts:
                return_results(f"Alerts with type {demisto.args().get('alert_type')} does not exist")
            return_results(alerts)

        elif command == "orca-get-asset":
            asset = orca_client.get_asset(asset_unique_id=demisto.args()['asset_unique_id'])
            return_results(asset)

        elif command == "fetch-incidents":
            fetch_incidents(orca_client)

        else:
            raise NotImplementedError(f'{command} is not an existing orca command')
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
