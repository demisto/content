import base64
from datetime import datetime
import dateutil.parser

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from typing import Any, Dict, Union, Optional, Tuple, List

FILTER_RELATIONSHIP_AND = "FILTER_RELATIONSHIP_AND"

DEMISTO_OCCURRED_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
RECO_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
DEMISTO_INFORMATIONAL = 0.5
RECO_API_TIMEOUT_IN_SECONDS = 30  # Increase timeout for RECO API
RECO_ACTIVE_INCIDENTS_VIEW = "active_incidents_view"
RECO_INCIDENT_ID_FIELD = "incident_id"
CREATED_AT_FIELD = "created_at"
STEP_FETCH = "fetch"
STEP_INIT = "init"


class RecoClient(BaseClient):
    def __init__(self, api_token: str, base_url: str, verify: bool, proxy):
        super().__init__(base_url, verify=verify, proxy=proxy, headers={"Authorization": f"Bearer {api_token}"})

    def get_incidents(
            self,
            risk_level: Optional[int] = None,
            source: Optional[str] = None,
            before: Optional[datetime] = None,
            after: Optional[datetime] = None,
            limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """
        Fetch incidents from Reco API
        :param risk_level: The risk level of the incidents to fetch
        :param source: The source of the incidents to fetch
        :param before: The maximum date of the incidents to fetch
        :param after: The minimum date of the incidents to fetch
        :param limit: int
        :return: dict
        """
        demisto.info("Get incidents, enter")
        alerts: List[Dict[str, Any]] = []
        params: Dict[str, Any] = {
            "getTableRequest": {
                "tableName": RECO_ACTIVE_INCIDENTS_VIEW,
                "pageSize": limit,
                "fieldFilters": {
                    "relationship": FILTER_RELATIONSHIP_AND,
                    "filters": {"filters": []},
                },
                "fieldSorts": {
                    "sorts": [
                        {
                            "sortBy": "updated_at",
                            "sortDirection": "SORT_DIRECTION_ASC"
                        }
                    ]
                }
            }
        }
        if risk_level:
            params["getTableRequest"]["fieldFilters"]["filters"]["filters"].append(
                {"field": "risk_level", "stringEquals": {"value": risk_level}}
            )
        if source:
            params["getTableRequest"]["fieldFilters"]["filters"]["filters"].append(
                {"field": "data_source", "stringEquals": {"value": source}}
            )
        if before:
            params["getTableRequest"]["fieldFilters"]["filters"]["filters"].append(
                {
                    "field": CREATED_AT_FIELD,
                    "before": {"value": before.strftime("%Y-%m-%dT%H:%M:%SZ")},
                }
            )
        if after:
            params["getTableRequest"]["fieldFilters"]["filters"]["filters"].append(
                {
                    "field": CREATED_AT_FIELD,
                    "after": {"value": after.strftime("%Y-%m-%dT%H:%M:%SZ")},
                }
            )

        demisto.debug(f"params: {params}")
        try:
            response = self._http_request(
                method="PUT",
                url_suffix="/incident",
                data=json.dumps(params),
                timeout=RECO_API_TIMEOUT_IN_SECONDS,
            )
            if response.get("getTableResponse") is None:
                demisto.info(f"got bad response, {response}")
            else:
                demisto.info(
                    f"Count of incidents: {response.get('getTableResponse').get('totalNumberOfRecords')}"
                )
                alerts = (
                    response.get("getTableResponse", {}).get("data", {}).get("rows", [])
                )
                demisto.info(f"Got {len(alerts)} alerts")
        except Exception as e:
            demisto.error(f"Findings Request ReadTimeout error: {str(e)}")
        demisto.info(f"done fetching RECO alerts, fetched {len(alerts)} alerts.")
        return alerts

    def get_incidents_assets(self, incident_id: str) -> List[Dict[str, Any]]:
        """
        Get assets of an incident.
        """
        demisto.info("Get incident assets, enter")
        result: List[Dict[str, Any]] = []
        try:
            response = self._http_request(
                method="GET",
                url_suffix=f"/incident/assets/{incident_id}",
                timeout=RECO_API_TIMEOUT_IN_SECONDS,
            )
            if response.get("assets") is None:
                demisto.info(f"got bad response, {response}")
            else:
                demisto.info(f"got good response, {response}")
                result = response.get("assets", {})
        except Exception as e:
            demisto.error(f"Validate API key ReadTimeout error: {str(e)}")
            raise e

        demisto.info(f"done fetching RECO incident assets, fetched {len(result)} assets.")
        return result

    def validate_api_key(self) -> str:
        """
        Validate API key
        :return: bool
        """
        demisto.info("Validate API key, enter")
        invalid_token_string = "Invalid token"
        try:
            response = self._http_request(
                method="POST",
                url_suffix="/incident-tables/tables",
                timeout=RECO_API_TIMEOUT_IN_SECONDS,
            )
            if response.get("listTablesResponse") is None:
                demisto.info(f"got bad response, {response}")
            else:
                demisto.info(f"got good response, {response}")
                return "ok"
        except Exception as e:
            demisto.error(f"Validate API key Error: {str(e)}")
            raise e
        return invalid_token_string


def parse_table_row_to_dict(alert: List[Dict[str, Any]]) -> Dict[str, Any]:
    if alert is None:
        return {}

    alert_as_dict = {}
    for obj in alert:
        key = obj.get("key", None)
        value = obj.get("value", None)
        if key is None:
            continue
        if value is None:
            continue
        obj[key] = base64.b64decode(value).decode("utf-8")
        # Remove " from the beginning and end of the string
        obj[key] = obj[key].replace('"', "")
        if key in ["updated_at", "created_at", "event_time"]:
            try:
                parsed_time = datetime.strptime(obj[key], RECO_TIME_FORMAT)
            except Exception:
                parsed_time = datetime.strptime(obj[key], DEMISTO_OCCURRED_FORMAT)
            if parsed_time:
                obj[key] = parsed_time.strftime(DEMISTO_OCCURRED_FORMAT)
        if key == "risk_level":
            obj[key] = int(obj[key])
        alert_as_dict[key] = obj[key]

    return alert_as_dict


def enrich_incident(reco_client: RecoClient, single_incident: Dict[str, Any]) -> Dict[str, Any]:
    alert_as_dict = parse_table_row_to_dict(single_incident.get("cells", {}))
    if RECO_INCIDENT_ID_FIELD in alert_as_dict.keys():
        incident_id: str = str(alert_as_dict[RECO_INCIDENT_ID_FIELD])
        alert_as_dict["assets"] = reco_client.get_incidents_assets(incident_id)

    return {
        "name": alert_as_dict.get("incident_description", ""),
        "occurred": alert_as_dict.get("event_time", ""),
        "dbotMirrorId": alert_as_dict.get("incident_id", ""),
        "rawJSON": json.dumps(alert_as_dict),
        "severity": map_reco_score_to_demisto_score(
            reco_score=alert_as_dict.get("risk_level", DEMISTO_INFORMATIONAL)
        ),
    }


def map_reco_score_to_demisto_score(
        reco_score: int,
) -> Union[int, float]:  # pylint: disable=E1136
    # demisto_unknown = 0  (commented because of linter issues)
    demisto_informational = 0.5
    # demisto_low = 1  (commented because of linter issues)
    demisto_medium = 2
    demisto_high = 3
    demisto_critical = 4

    # LHS is Orca score
    MAPPING = {
        40: demisto_critical,
        30: demisto_high,
        20: demisto_medium,
        10: demisto_informational,
    }

    return MAPPING[reco_score]


def parse_incidents_objects(reco_client: RecoClient, incidents_raw: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    demisto.info("parse_incidents_objects enter")
    incidents = []
    for single_incident in incidents_raw:
        incident = enrich_incident(reco_client, single_incident=single_incident)
        incidents.append(incident)

    demisto.info(f"get_incidents_from_alerts: Got {len(incidents)} incidents")
    return incidents


def fetch_incidents(
        reco_client: RecoClient,
        last_run: Dict[str, Any],
        max_fetch: int,
        risk_level: Optional[int] = None,
        source: Optional[str] = None,
        before: Optional[datetime] = None,
        after: Optional[datetime] = None,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    demisto.info(f"fetch-incidents called {max_fetch=}")
    next_run = {}
    last_run_time = last_run.get("lastRun", None)
    if last_run_time is not None:
        after = dateutil.parser.parse(last_run_time)

    incidents_raw = reco_client.get_incidents(
        risk_level=risk_level,
        source=source,
        before=before,
        after=after,
        limit=max_fetch,
    )
    incidents = parse_incidents_objects(reco_client, incidents_raw)
    existing_incidents = last_run.get("incident_ids", [])
    incidents = [
        incident
        for incident in incidents
        if incident.get("severity", 0) > DEMISTO_INFORMATIONAL
        and incident.get("dbotMirrorId", None) not in existing_incidents
    ]  # type: ignore

    incidents_sorted = sorted(incidents, key=lambda k: k["occurred"])
    next_run["lastRun"] = incidents_sorted[0]["occurred"] if incidents_sorted else last_run_time
    next_run["incident_ids"] = existing_incidents + [incident["dbotMirrorId"] for incident in incidents]
    return next_run, incidents


def get_max_fetch(max_fetch: int) -> int:
    if max_fetch > 500:
        return 500
    return max_fetch


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    try:
        command = demisto.command()
        demisto.debug(f"Reco Command being called is {command}")
        params = demisto.params()
        api_url = params.get("url")
        api_token = params.get("api_token")
        verify_certificate = not params.get('insecure', False)
        proxy = params.get('proxy', False)

        max_fetch = get_max_fetch(int(params.get("max_fetch", "200")))

        reco_client = RecoClient(api_token=api_token, base_url=api_url, verify=verify_certificate, proxy=proxy)
        if command == "fetch-incidents":
            risk_level = params.get("risk_level")
            source = params.get("source")
            before = params.get("before")
            after = params.get("after")

            # How much time before the first fetch to retrieve incidents
            if arg := params.get('first_fetch'):
                first_fetch_time_stamp = dateparser.parse(arg)
                if first_fetch_time_stamp:
                    after = first_fetch_time_stamp

            next_run, incidents = fetch_incidents(
                reco_client,
                last_run=demisto.getLastRun(),
                max_fetch=max_fetch,
                risk_level=risk_level,
                source=source,
                before=before,
                after=after,
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        elif command == "test-module":
            test_res = reco_client.validate_api_key()
            return_results(test_res)
        else:
            raise NotImplementedError(f"{command} is not an existing reco command")
    except Exception as e:
        demisto.error(f"Failed to execute {demisto.command()} command. Error: {str(e)}")
        raise e


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
