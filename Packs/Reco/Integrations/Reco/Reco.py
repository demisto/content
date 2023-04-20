import base64
from datetime import datetime
import dateutil.parser

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from typing import Any, Dict, Union, Optional, Tuple, List

ENTRY_TYPE_USER = "ENTRY_TYPE_USER"

LABEL_STATUS_ACTIVE = "LABEL_STATUS_ACTIVE"

RISKY_USER = "Risky User"

LEAVING_ORG_USER = "Leaving Org User"

ENTRY_TYPE_EVENT = "ENTRY_TYPE_EVENT"

LABEL_STATUS_RESOLVED = "LABEL_STATUS_RESOLVED"

FILTER_RELATIONSHIP_AND = "FILTER_RELATIONSHIP_AND"

DEMISTO_OCCURRED_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
RECO_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
DEMISTO_INFORMATIONAL = 0.5
RECO_API_TIMEOUT_IN_SECONDS = 30  # Increase timeout for RECO API
RECO_ACTIVE_INCIDENTS_VIEW = "active_incidents_view"
RECO_INCIDENT_ID_FIELD = "incident_id"
RECO_TIMELINE_EVENT_TYPE = "TIMELINE_EVENT_TYPE_USER_COMMENT"
CREATED_AT_FIELD = "created_at"
STEP_FETCH = "fetch"
STEP_INIT = "init"


class RecoClient(BaseClient):
    def __init__(self, api_token: str, base_url: str, verify: bool, proxy):
        super().__init__(
            base_url,
            verify=verify,
            proxy=proxy,
            headers={"Authorization": f"Bearer {api_token}"},
        )

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
                        {"sortBy": "updated_at", "sortDirection": "SORT_DIRECTION_ASC"}
                    ]
                },
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
                    f"Count of incidents: {response.get('getTableResponse').get('totalNumberOfResults')}"
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

        demisto.info(
            f"done fetching RECO incident assets, fetched {len(result)} assets."
        )
        return result

    def update_reco_incident_timeline(self, incident_id: str, comment: str) -> Any:
        """
        Update timeline of an incident.
        """
        demisto.info("Update incident timeline, enter")
        try:
            response = self._http_request(
                method="PUT",
                url_suffix=f"/incident-timeline/{incident_id}",
                timeout=RECO_API_TIMEOUT_IN_SECONDS,
                data=json.dumps(
                    {
                        "event": {
                            "eventType": RECO_TIMELINE_EVENT_TYPE,
                            "eventTime": datetime.now().strftime(
                                "%Y-%m-%dT%H:%M:%S.%fZ"
                            ),
                            "title": "Comment added by XSOAR",
                            "content": comment,
                        }
                    }
                ),
            )
        except Exception as e:
            demisto.error(f"Update incident timeline error: {str(e)}")
            raise e

        demisto.info(f"Comment added to timeline of incident {incident_id}")
        return response

    def resolve_visibility_event(self, entity_id: str, label_name: str) -> Any:
        """Resolve visibility event.
        :param entity_id: The entry id of the visibility event to resolve
        :param label_name: The label name of the visibility event to resolve
        """
        try:
            response = self._http_request(
                method="PUT",
                url_suffix="/set-label-status",
                timeout=RECO_API_TIMEOUT_IN_SECONDS,
                data=json.dumps(
                    {
                        "labelsRelationStatusUpdate": [
                            {
                                "labelName": label_name,
                                "entryId": f"{entity_id}_visibility",
                                "entryType": ENTRY_TYPE_EVENT,
                                "newStatus": LABEL_STATUS_RESOLVED,
                                "oldStatus": LABEL_STATUS_ACTIVE,
                                "comment": "Resolved by XSOAR Automation",
                            }
                        ]
                    }
                ),
            )
        except Exception as e:
            demisto.error(f"Resolve visibility event error: {str(e)}")
            raise e

        demisto.info(f"Visibility event {entity_id} resolved")
        return response

    def get_risky_users(self) -> List[Dict[str, Any]]:
        """Get risky users. Returns a list of risky users with analysis."""
        params = {
            "getTableRequest": {
                "tableName": "RISK_MANAGEMENT_VIEW_USER_LIST",
                "pageSize": 200,
                "fieldSorts": {
                    "sorts": [
                        {"sortBy": "risk_level", "sortDirection": "SORT_DIRECTION_DESC"}
                    ]
                },
                "fieldFilters": {},
            }
        }
        try:
            response = self._http_request(
                method="PUT",
                url_suffix="/risk-management/get-risk-management-table",
                timeout=RECO_API_TIMEOUT_IN_SECONDS,
                data=json.dumps(params),
            )
            if response.get("getTableResponse") is None:
                demisto.error(f"got bad response, {response}")
                raise Exception(f"got bad response, {response}")
            else:
                demisto.info(
                    f"Count of risky users: {response.get('getTableResponse').get('totalNumberOfResults')}"
                )
                users = (
                    response.get("getTableResponse", {}).get("data", {}).get("rows", [])
                )
                demisto.info(f"Got {len(users)} users")
                return users
        except Exception as e:
            demisto.error(f"Validate API key ReadTimeout error: {str(e)}")
            raise e

    def get_assets_user_has_access(
        self, email_address: str, only_sensitive: bool
    ) -> List[Dict[str, Any]]:
        """Get assets user has access to. Returns a list of assets."""
        params: Dict[str, Any] = {
            "getTableRequest": {
                "tableName": "files_view",
                "pageSize": 1000,
                "fieldFilters": {
                    "relationship": "FILTER_RELATIONSHIP_AND",
                    "fieldFilterGroups": {
                        "fieldFilters": [
                            {
                                "relationship": "FILTER_RELATIONSHIP_OR",
                                "filters": {
                                    "filters": [
                                        {
                                            "field": "currently_permitted_users",
                                            "regexCaseInsensitive": {
                                                "value": email_address
                                            },
                                        }
                                    ]
                                },
                            }
                        ]
                    },
                },
            }
        }
        if only_sensitive:
            params["getTableRequest"]["fieldFilters"]["fieldFilterGroups"][
                "fieldFilters"
            ].append(
                {
                    "relationship": "FILTER_RELATIONSHIP_OR",
                    "filters": {
                        "filters": [
                            {
                                "field": "sensitivity_level",
                                "stringEquals": {"value": "30"},
                            },
                            {
                                "field": "sensitivity_level",
                                "stringEquals": {"value": "40"},
                            },
                        ]
                    },
                }
            )
        try:
            response = self._http_request(
                method="POST",
                url_suffix="/asset-management",
                timeout=RECO_API_TIMEOUT_IN_SECONDS * 2,
                data=json.dumps(params),
            )
            if response.get("getTableResponse") is None:
                demisto.error(f"got bad response, {response}")
                raise Exception(f"got bad response, {response}")
            else:
                demisto.info(
                    f"Count of assets: {response.get('getTableResponse').get('totalNumberOfResults')}"
                )
                assets = (
                    response.get("getTableResponse", {}).get("data", {}).get("rows", [])
                )
                demisto.info(f"Got {len(assets)} result")
                return assets
        except Exception as e:
            demisto.error(f"Validate API key ReadTimeout error: {str(e)}")
            raise e

    def get_sensitive_assets_information(self, asset_name: str, regex_search: bool) -> List[Dict[str, Any]]:
        """Get sensitive assets information. Returns a list of assets."""
        filter = "regexCaseInsensitive" if regex_search else "stringEquals"
        params: Dict[str, Any] = {
            "getTableRequest": {
                "tableName": "files_view",
                "pageSize": 1000,
                "fieldFilters": {
                    "relationship": "FILTER_RELATIONSHIP_AND",
                    "fieldFilterGroups": {
                        "fieldFilters": [
                            {
                                "relationship": "FILTER_RELATIONSHIP_OR",
                                "filters": {
                                    "filters": [
                                        {
                                            "field": "file_name",
                                            filter: {
                                                "value": asset_name
                                            },
                                        }
                                    ]
                                },
                            },
                            {
                                "relationship": "FILTER_RELATIONSHIP_OR",
                                "filters": {
                                    "filters": [
                                        {
                                            "field": "sensitivity_level",
                                            "stringEquals": {"value": "30"},
                                        },
                                        {
                                            "field": "sensitivity_level",
                                            "stringEquals": {"value": "40"},
                                        },
                                    ]
                                },
                            }
                        ]
                    },
                },
            }
        }
        try:
            response = self._http_request(
                method="POST",
                url_suffix="/asset-management",
                timeout=RECO_API_TIMEOUT_IN_SECONDS * 2,
                data=json.dumps(params),
            )
            if response.get("getTableResponse") is None:
                demisto.error(f"got bad response, {response}")
                raise Exception(f"got bad response, {response}")
            else:
                demisto.info(
                    f"Count of assets: {response.get('getTableResponse').get('totalNumberOfResults')}"
                )
                assets = (
                    response.get("getTableResponse", {}).get("data", {}).get("rows", [])
                )
                demisto.info(f"Got {len(assets)} result")
                return assets
        except Exception as e:
            demisto.error(f"Validate API key ReadTimeout error: {str(e)}")
            raise e

    def set_entry_label_relations(
        self, entry_id: str, label_name: str, label_status: str, entry_type: str
    ) -> Any:
        """Set entry label relations.
        :param entry_id: The entry id to set (email_address, asset_id etc.)
        :param label_name: The label name to set
        :param label_status: The label_status to set. Can be one of the following:
        LABEL_STATUS_INACTIVE,
        LABEL_STATUS_ACTIVE,
        LABEL_STATUS_RESOLVED,
        LABEL_STATUS_FALSE_POSITIVE,
        LABEL_STATUS_PENDING
        :param entry_type: The entry type to set. Can be one of the following: ENTRY_TYPE_INCIDENT,
        ENTRY_TYPE_PROCESS,
        ENTRY_TYPE_EVENT,
        ENTRY_TYPE_USER,
        ENTRY_TYPE_ASSET,
        ENTRY_TYPE_PLAYBOOK
        """
        try:
            response = self._http_request(
                method="PUT",
                url_suffix="/entry-label-relations",
                timeout=RECO_API_TIMEOUT_IN_SECONDS,
                data=json.dumps({"labelRelations": [{
                    "labelName": label_name,
                    "entryId": entry_id,
                    "count": 1,
                    "confidence": 1,
                    "entryType": entry_type,
                    "labelStatus": label_status,
                    "attributes": {}
                }]}),
            )
        except Exception as e:
            demisto.error(f"Set entry label relations error: {str(e)}")
            raise e
        demisto.info(f"Label {label_name} set to {label_status} for event {entry_id}")
        return response

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


def get_risky_users_from_reco(reco_client: RecoClient) -> CommandResults:
    """Get risky users from Reco."""
    risky_users = reco_client.get_risky_users()
    users = []
    for user in risky_users:
        user_as_dict = parse_table_row_to_dict(user.get("cells", {}))
        users.append(user_as_dict)
    return CommandResults(
        readable_output=tableToMarkdown(
            "Risky Users",
            users,
            headers=["email_account", "risk_level", "labels", "status"],
        ),
        outputs_prefix="Reco.RiskyUsers",
        outputs_key_field="email_account",
        outputs=users,
        raw_response=risky_users,
    )


def add_risky_user_label(reco_client: RecoClient, email_address: str) -> CommandResults:
    """Add a risky user to Reco."""
    raw_response = reco_client.set_entry_label_relations(
        email_address, RISKY_USER, LABEL_STATUS_ACTIVE, ENTRY_TYPE_USER
    )
    return CommandResults(
        raw_response=raw_response,
        readable_output=f"User {email_address} labeled as risky",
    )


def add_leaving_org_user(reco_client: RecoClient, email_address: str) -> CommandResults:
    """Tag user as leaving org."""
    raw_response = reco_client.set_entry_label_relations(
        email_address, LEAVING_ORG_USER, LABEL_STATUS_ACTIVE, ENTRY_TYPE_USER
    )
    return CommandResults(
        raw_response=raw_response,
        readable_output=f"User {email_address} labeled as leaving org user",
    )


def enrich_incident(
    reco_client: RecoClient, single_incident: Dict[str, Any]
) -> Dict[str, Any]:
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

    # LHS is Reco score
    MAPPING = {
        40: demisto_critical,
        30: demisto_high,
        20: demisto_medium,
        10: demisto_informational,
        0: demisto_informational,
    }

    return MAPPING[reco_score]


def parse_incidents_objects(
    reco_client: RecoClient, incidents_raw: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    demisto.info("parse_incidents_objects enter")
    incidents = []
    for single_incident in incidents_raw:
        incident = enrich_incident(reco_client, single_incident=single_incident)
        incidents.append(incident)

    demisto.info(f"get_incidents_from_alerts: Got {len(incidents)} incidents")
    return incidents


def get_assets_user_has_access(
    reco_client: RecoClient, email_address: str, only_sensitive: bool
) -> CommandResults:
    """Get assets from Reco. If only_sensitive is True, only sensitive assets will be returned."""
    assets = reco_client.get_assets_user_has_access(email_address, only_sensitive)
    assets_list = []
    for asset in assets:
        asset_as_dict = parse_table_row_to_dict(asset.get("cells", {}))
        assets_list.append(asset_as_dict)
    return CommandResults(
        readable_output=tableToMarkdown(
            "Assets",
            assets_list,
            headers=[
                "file_name",
                "file_owner",
                "file_url",
                "currently_permitted_users",
                "visibility",
                "location",
                "source",
            ],
        ),
        outputs_prefix="Reco.Assets",
        outputs_key_field="asset_value",
        outputs=assets_list,
        raw_response=assets,
    )


def get_sensitive_assets_by_name(reco_client: RecoClient, asset_name: str, regex_search: bool) -> CommandResults:
    """Get sensitive assets from Reco. If contains is True, the asset name will be searched as a regex."""
    assets = reco_client.get_sensitive_assets_information(asset_name, regex_search)
    assets_list = []
    for asset in assets:
        asset_as_dict = parse_table_row_to_dict(asset.get("cells", {}))
        assets_list.append(asset_as_dict)
    return CommandResults(
        readable_output=tableToMarkdown(
            "Assets",
            assets_list,
            headers=[
                "file_name",
                "file_owner",
                "file_url",
                "currently_permitted_users",
                "visibility",
                "location",
                "source",
                "sensitivity_level"
            ],
        ),
        outputs_prefix="Reco.SensitiveAssets",
        outputs_key_field="asset_value",
        outputs=assets_list,
        raw_response=assets,
    )


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
        if (incident.get("severity", 0) > DEMISTO_INFORMATIONAL)
        and (incident.get("dbotMirrorId", None) not in existing_incidents)
    ]  # type: ignore

    incidents_sorted = sorted(incidents, key=lambda k: k["occurred"])
    next_run["lastRun"] = (
        incidents_sorted[0]["occurred"] if incidents_sorted else last_run_time
    )
    next_run["incident_ids"] = existing_incidents + [
        incident["dbotMirrorId"] for incident in incidents
    ]
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
        verify_certificate = not params.get("insecure", False)
        proxy = params.get("proxy", False)

        max_fetch = get_max_fetch(int(params.get("max_fetch", "200")))

        reco_client = RecoClient(
            api_token=api_token,
            base_url=api_url,
            verify=verify_certificate,
            proxy=proxy,
        )
        if command == "fetch-incidents":
            risk_level = params.get("risk_level")
            source = params.get("source")
            before = params.get("before")
            after = params.get("after")

            # How much time before the first fetch to retrieve incidents
            if arg := params.get("first_fetch"):
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
        elif command == "reco-update-incident-timeline":
            incident_id = demisto.args()["incident_id"]
            response = reco_client.update_reco_incident_timeline(
                incident_id=incident_id,
                comment=demisto.args()["comment"],
            )
            return_results(
                CommandResults(
                    raw_response=response,
                    readable_output=f"Timeline updated successfully for incident {incident_id}",
                )
            )
        elif command == "reco-resolve-visibility-event":
            entity_id = demisto.args()["entity_id"]
            label_name = demisto.args()["label_name"]
            response = reco_client.resolve_visibility_event(
                entity_id=entity_id, label_name=label_name
            )
            return_results(
                CommandResults(
                    raw_response=response,
                    readable_output=f"Visibility event {entity_id} resolved successfully",
                )
            )
        elif command == "test-module":
            test_res = reco_client.validate_api_key()
            return_results(test_res)
        elif command == "reco-get-risky-users":
            result = get_risky_users_from_reco(reco_client)
            return_results(result)
        elif command == "reco-add-risky-user-label":
            email_address = demisto.args()["email_address"]
            result = add_risky_user_label(reco_client, email_address)
            return_results(result)
        elif command == "reco-add-leaving-org-user-label":
            email_address = demisto.args()["email_address"]
            result = add_leaving_org_user(reco_client, email_address)
            return_results(result)
        elif command == "reco-get-assets-user-has-access-to":
            only_sensitive = demisto.args().get("only_sensitive", False)
            result = get_assets_user_has_access(
                reco_client,
                demisto.args()["email_address"],
                only_sensitive,
            )
            return_results(result)
        elif command == "reco-get-sensitive-assets-by-name":
            regex_search = demisto.args().get("regex_search", False)
            result = get_sensitive_assets_by_name(
                reco_client,
                demisto.args()["asset_name"],
                regex_search,
            )
            return_results(result)
        else:
            raise NotImplementedError(f"{command} is not an existing reco command")
    except Exception as e:
        demisto.error(f"Failed to execute {demisto.command()} command. Error: {str(e)}")
        raise e


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
