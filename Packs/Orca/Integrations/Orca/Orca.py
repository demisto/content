import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from urllib.parse import urlparse

import dateutil.parser
from requests import Response


from typing import Any, Dict, Union, Optional, Tuple, cast

DEMISTO_OCCURRED_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
DEMISTO_INFORMATIONAL = 0.5
ORCA_API_TIMEOUT = 30  # Increase timeout for ORCA API
ORCA_API_LIMIT = 500  # limit number of returned records from ORCA API
STEP_INIT = "init"
STEP_FETCH = "fetch"


class OrcaClient:
    def __init__(self, client: BaseClient):
        self.client = client

    def validate_api_key(self) -> str:
        demisto.info("validate_api_key, enter")
        invalid_token_string = "Test failed because the Orca API token that was entered is invalid," \
                               " please provide a valid API token"
        try:
            response = self.client._http_request(
                method="POST",
                url_suffix="/rules/query/alerts", data={},
                timeout=ORCA_API_TIMEOUT
            )

            if response.get("status") != "success":
                return_error(message=response.get("error") or invalid_token_string)
        except Exception as e:
            demisto.debug(str(e))

            # Try to get error message from response
            response = getattr(e, "res")
            message = invalid_token_string
            if isinstance(response, Response):
                message = response.json().get("error") or invalid_token_string

            return_error(message=message)

        return "ok"

    def get_alerts_by_filter(
            self,
            alert_type: Optional[str] = None,
            asset_unique_id: Optional[str] = None,
            limit: int = 1000
    ) -> Union[  # pylint: disable=E1136 # noqa: E501
        List[Dict[str, Any]], str]:  # pylint: disable=E1136 # noqa: E125
        demisto.info("get_alerts_by_filter, enter")

        url_suffix = "/alerts"

        if alert_type and asset_unique_id or (not alert_type and not asset_unique_id):
            demisto.info("must supply exactly one filter")
            return "must supply exactly one filter"

        params = {}
        if alert_type:
            params = {"type": alert_type}
        elif asset_unique_id:
            params = {"asset_unique_id": asset_unique_id}

        params["limit"] = str(limit)

        try:
            response = self.client._http_request(method="GET", url_suffix=url_suffix, params=params,
                                                 timeout=ORCA_API_TIMEOUT)
            if response.get("status") != 'success':
                demisto.info("bad response from Orca API")
                return response.get("error")

            return response.get("data")
        except requests.exceptions.ReadTimeout as e:
            demisto.info(f"Alerts Request ReadTimeout error: {str(e)}")
            return []

    def get_alerts(
            self,
            time_from: Optional[str],
            fetch_informational: bool = False,
            next_page_token: Optional[str] = None,
            limit: int = 1000
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """
        Fetch alerts
        :param time_from: datetime
        :param fetch_informational: bool
        :param next_page_token: str
        :param limit: int
        :return: dict
        """
        demisto.info("Get alerts, enter")
        alerts: List[Dict[str, Any]] = []
        params: Dict[str, Any] = {"limit": limit}
        filters: List[Dict[str, Any]] = []

        if time_from:
            filters.append({
                "field": "state.last_updated",
                "range": {"gte": time_from}
            })
        if fetch_informational:
            filters.append({
                "field": "state.score",
                "includes": [1, 2, 3, 4]
            })

        params["dsl_filter"] = json.dumps(filters)

        if next_page_token:
            params['next_page_token'] = next_page_token

        try:
            response = self.client._http_request(method="POST", url_suffix="/rules/query/alerts", data=params,
                                                 timeout=ORCA_API_TIMEOUT)

            if response.get("status") != 'success':
                demisto.info(f"got bad response, {response.get('error')}")
            else:
                alerts = response.get("data")
                next_page_token = response.get("next_page_token")

        except requests.exceptions.ReadTimeout as e:
            demisto.info(f"Alerts Request ReadTimeout error: {str(e)}")
        except DemistoException as e:
            demisto.info(f"Alerts Request Error: {str(e)}")

        demisto.info(f"done fetching orca alerts, fetched {len(alerts)} alerts.")
        if next_page_token:
            demisto.info("not the last page")
        else:
            demisto.info("the last page fetched")
        return alerts, next_page_token

    def get_asset(self, asset_unique_id: str) -> Union[Dict[str, Any], str]:  # pylint: disable=E1136
        demisto.debug("get_asset, enter")
        try:
            response = self.client._http_request(method="GET", url_suffix=f"/assets/{asset_unique_id}",
                                                 timeout=ORCA_API_TIMEOUT)
        except DemistoException:
            demisto.debug(f"could not find {asset_unique_id}")
            return {}
        except requests.exceptions.ReadTimeout as e:
            demisto.info(f"Assets Request ReadTimeout error: {str(e)}")
            return {}

        return "Asset Not Found" if 'error' in response or not response else response

    def set_alert_score(self, alert_id: str, orca_score: float) -> Dict[str, Any]:
        demisto.debug("Set alert score.")
        # api returns 400 status code if the alert have same score
        return self.client._http_request(
            method="PUT",
            url_suffix=f"/alerts/{alert_id}/severity",
            data={"orca_score": orca_score},
            timeout=ORCA_API_TIMEOUT,
            ok_codes=(200, 400)
        )

    def get_alert_event_log(self, alert_id: str, limit: int = 20, start_at_index: int = 0,
                            event_log_type: Optional[str] = None) -> Dict[str, Any]:
        params = {
            "limit": limit,
            "start_at_index": start_at_index,
        }

        if event_log_type:
            params["type"] = cast(int, event_log_type)

        return self.client._http_request(
            method="GET",
            url_suffix=f"/alerts/{alert_id}/event_log",
            params=params,
            timeout=ORCA_API_TIMEOUT,
        )

    def set_alert_status(self, alert_id: str, status: str) -> Dict[str, Any]:
        return self.client._http_request(
            method="PUT",
            url_suffix=f"/alerts/{alert_id}/status/{status}",
            timeout=ORCA_API_TIMEOUT,
        )

    def verify_alert(self, alert_id: str) -> Dict[str, Any]:
        return self.client._http_request(
            method="PUT",
            url_suffix=f"/alerts/{alert_id}/verify",
            timeout=ORCA_API_TIMEOUT,
        )

    def download_malicious_file(self, alert_id: str) -> Dict[str, Any]:
        response = self.client._http_request(
            method="GET",
            url_suffix=f"/alerts/{alert_id}/download_malicious_file",
            timeout=ORCA_API_TIMEOUT,
        )
        demisto.debug(f"Got malicious download link {response}")

        if "link" not in response:
            raise DemistoException("Unable to get malicious file")

        file_link = response.get("link")
        file_response = requests.get(
            url=file_link,
            timeout=ORCA_API_TIMEOUT,
        )
        if file_response.status_code != 200:
            raise DemistoException("Unable to download malicious file")
        file_name = os.path.basename(urlparse(file_link).path)

        return {"filename": file_name, "file": file_response.content}


def map_orca_score_to_demisto_score(orca_score: str) -> Union[int, float]:  # pylint: disable=E1136
    # demisto_unknown = 0  (commented because of linter issues)
    demisto_informational = 0.5
    demisto_low = 1
    demisto_medium = 2
    demisto_high = 3
    demisto_critical = 4

    # LHS is Orca score
    MAPPING = {
        "critical": demisto_critical,
        "high": demisto_high,
        "medium": demisto_medium,
        "low": demisto_low,
        "informational": demisto_informational
    }

    return MAPPING[orca_score] if orca_score in MAPPING else 0


def get_incident_from_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    if alert is None:
        return {}

    last_seen_time = dateutil.parser.parse(alert.get('state', {}).get('last_seen')).isoformat()
    return {
        'name': alert.get('state', {}).get('alert_id'),
        'occurred': last_seen_time,
        'rawJSON': json.dumps(alert),
        'severity': map_orca_score_to_demisto_score(orca_score=alert.get('state', {}).get('risk_level'))
    }


def get_incidents_from_alerts(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    demisto.info("get_incidents_from_alerts enter")
    incidents = []
    for alert in alerts:
        alert['demisto_score'] = map_orca_score_to_demisto_score(orca_score=alert.get("state", {}).get("risk_level"))
        incident = get_incident_from_alert(alert=alert)
        incidents.append(incident)

    demisto.info(f"get_incidents_from_alerts: Got {len(incidents)} incidents")
    return incidents


def fetch_incidents(
        orca_client: OrcaClient,
        last_run: Dict[str, Any],
        max_fetch: int,
        first_fetch_time: Optional[str],  # pylint: disable=E1136
        fetch_informational: bool = False,
        pull_existing_alerts: bool = False
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    demisto.info(f"fetch-incidents called {max_fetch=}")

    last_run_time = last_run.get("lastRun")
    next_page_token = last_run.get("next_page_token")
    step = last_run.get("step", STEP_INIT)
    time_from = first_fetch_time
    next_run = {
        "step": step
    }

    if step == STEP_INIT:
        if not pull_existing_alerts:
            demisto.info("pull_existing_alerts flag is not set, not pulling alerts")
            next_run["step"] = STEP_FETCH

        # Initial export flow
        # Fetch and import alerts per page.
        demisto.info("first run. export of existing alerts")
        time_from = first_fetch_time
    elif step == STEP_FETCH:
        demisto.info("not first run, exporting reminder of alerts")
        time_from = last_run_time

    alerts, next_page_token = orca_client.get_alerts(
        fetch_informational=fetch_informational,
        time_from=time_from,
        next_page_token=next_page_token,
        limit=max_fetch
    )

    if step == STEP_INIT and not next_page_token:
        # Go to the next step. All alerts are imported then just get a new alerts
        next_run["step"] = STEP_FETCH

    incidents = get_incidents_from_alerts(alerts)
    incidents = [incident for incident in incidents
                 if incident.get("severity") > DEMISTO_INFORMATIONAL]  # type: ignore

    next_run["lastRun"] = datetime.now().strftime(DEMISTO_OCCURRED_FORMAT)
    if next_page_token:
        next_run['next_page_token'] = next_page_token
    return next_run, incidents


def set_alert_severity(orca_client: OrcaClient, args: Dict[str, Any]) -> CommandResults:
    alert_id = args.get("alert_id")
    score = args.get("score")

    assert alert_id and score
    demisto.debug(f"Set alert severity {alert_id=} {score=}")

    response = orca_client.set_alert_score(alert_id=alert_id, orca_score=score)

    context = {}
    if "alert_id" in response:
        context = {
            "id": response.get("alert_id"),
            "details": response.get("details", {}).get("description"),
            "severity": response.get("details", {}).get("severity")
        }
    if "error" in response:
        raise DemistoException(response.get("error"))

    return CommandResults(
        readable_output=f"Alert severity changed to {score}",
        outputs_prefix="Orca.Alert",
        outputs=context,
        raw_response=response
    )


def get_alert_event_log(orca_client: OrcaClient, args: Dict[str, Any]) -> CommandResults:
    alert_id = args.get("alert_id")
    limit = cast(int, args.get("limit", 20))
    start_at_index = cast(int, args.get("start_at_index", 0))
    event_log_type = args.get("type")

    demisto.debug(f"Get alert event log {alert_id=} {limit=} {start_at_index=} {event_log_type=}")

    assert alert_id

    response = orca_client.get_alert_event_log(
        alert_id=alert_id,
        limit=limit,
        start_at_index=start_at_index,
        event_log_type=event_log_type
    )
    context = response.get("event_log", [])

    alert_logs = [{
        "id": item.get("id"),
        "alert_id": item.get("alert_id"),
        "type": item.get("type"),
        "description": item.get("details", {}).get("description")
    } for item in context]

    return CommandResults(
        readable_output=tableToMarkdown(f"Alert event log ({alert_id})", alert_logs, removeNull=True),
        outputs_prefix="Orca.EventLog",
        outputs=context
    )


def set_alert_status(orca_client: OrcaClient, args: Dict[str, Any]) -> CommandResults:
    alert_id = cast(str, args.get("alert_id"))
    status = cast(str, args.get("status"))
    assert alert_id and status
    demisto.debug(f"Set alert status {alert_id=} {status=}")

    response = orca_client.set_alert_status(alert_id=alert_id, status=status)
    return CommandResults(
        readable_output=f"Alert status changed to {status}",
        outputs_prefix="Orca.Alert",
        outputs={
            "id": alert_id,
            "status": response["data"]["details"]["to"]
        }
    )


def verify_alert(orca_client: OrcaClient, args: Dict[str, Any]) -> CommandResults:
    alert_id = args.get("alert_id")
    assert alert_id
    demisto.debug(f"Trigger verify alert {alert_id=}")

    response = orca_client.verify_alert(alert_id=alert_id)
    return CommandResults(
        readable_output="The alert verify has started. This process may take some time.",
        outputs_prefix="Orca.Alert",
        outputs={
            "id": alert_id,
            "status": response["status"]
        }
    )


def download_malicious_file(orca_client: OrcaClient, args: Dict[str, Any]) -> None:
    alert_id = args.get("alert_id")
    assert alert_id

    demisto.debug(f"Downloading malicious file for {alert_id=}")

    response = orca_client.download_malicious_file(alert_id=alert_id)
    demisto.results(fileResult(response['filename'], response['file']))


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    try:
        command = demisto.command()
        demisto.debug(f'Orca Command being called is {command}')
        api_token = demisto.params().get('api_token').get('password')
        api_host = demisto.params().get('api_host')
        fetch_informational = demisto.params().get('fetch_informational')
        max_fetch = int(demisto.params().get('max_fetch', '200'))
        pull_existing_alerts = demisto.params().get('pull_existing_alerts')

        max_fetch = min(max_fetch, 500)
        api_url = f"https://{api_host}/api"

        # How much time before the first fetch to retrieve incidents
        first_fetch_time = None
        if arg := demisto.params().get('first_fetch'):
            if first_fetch_time_stamp := dateparser.parse(arg):
                first_fetch_time = first_fetch_time_stamp.isoformat()

        client = BaseClient(
            base_url=api_url,
            verify=True,
            headers={
                'Authorization': f'Token {api_token}'
            },
            proxy=True
        )

        orca_client = OrcaClient(client=client)
        demisto_args = demisto.args()

        if command == "orca-get-alerts":
            alert_type = demisto_args.get('alert_type')
            asset_unique_id = demisto_args.get('asset_unique_id')
            alerts = orca_client.get_alerts_by_filter(
                alert_type=alert_type,
                asset_unique_id=asset_unique_id,
                limit=ORCA_API_LIMIT,
            )
            if isinstance(alerts, str):
                #  this means alert is an error
                command_result = CommandResults(readable_output=alerts, raw_response=alerts)
            else:
                command_result = CommandResults(outputs_prefix="Orca.Manager.Alerts", outputs=alerts,
                                                raw_response=alerts)

            return_results(command_result)

        elif command == "orca-get-asset":
            asset = orca_client.get_asset(asset_unique_id=demisto.args()['asset_unique_id'])
            command_result = CommandResults(outputs_prefix="Orca.Manager.Asset", outputs=[asset], raw_response=asset)
            return_results(command_result)

        elif command == "fetch-incidents":
            next_run, incidents = fetch_incidents(
                orca_client,
                last_run=demisto.getLastRun(),
                max_fetch=max_fetch,
                fetch_informational=fetch_informational,
                pull_existing_alerts=pull_existing_alerts,
                first_fetch_time=first_fetch_time
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command == "orca-set-alert-severity":
            return_results(set_alert_severity(orca_client=orca_client, args=demisto_args))

        elif command == "orca-get-alert-event-log":
            return_results(get_alert_event_log(orca_client=orca_client, args=demisto_args))

        elif command == "orca-set-alert-status":
            return_results(set_alert_status(orca_client=orca_client, args=demisto_args))

        elif command == "orca-verify-alert":
            return_results(verify_alert(orca_client=orca_client, args=demisto_args))

        elif command == "orca-download-malicious-file":
            download_malicious_file(orca_client=orca_client, args=demisto_args)

        elif command == "test-module":
            test_res = orca_client.validate_api_key()
            return_results(test_res)

        else:
            raise NotImplementedError(f'{command} is not an existing orca command')
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
