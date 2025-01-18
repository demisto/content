import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import base64
import json
from datetime import datetime
import dateutil.parser

from typing import Any

ENTRY_TYPE_USER = "ENTRY_TYPE_USER"
ENTRY_TYPE_IDENTITY = "ENTRY_TYPE_IDENTITY"

LABEL_STATUS_ACTIVE = "LABEL_STATUS_ACTIVE"

RISKY_USER = "Risky User"

LEAVING_ORG_USER = "Leaving Org User"

ENTRY_TYPE_EVENT = "ENTRY_TYPE_EVENT"

LABEL_STATUS_RESOLVED = "LABEL_STATUS_RESOLVED"

FILTER_RELATIONSHIP_AND = "FILTER_RELATIONSHIP_AND"
PAGE_SIZE = 1000

DEMISTO_OCCURRED_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
RECO_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
DEMISTO_INFORMATIONAL = 0.5
RECO_API_TIMEOUT_IN_SECONDS = 180  # Increase timeout for RECO API
RECO_ACTIVE_INCIDENTS_VIEW = "active_incidents_view"
RECO_ACTIVE_ALERTS_VIEW = "alerts"
RECO_INCIDENT_ID_FIELD = "incident_id"
RECO_TIMELINE_EVENT_TYPE = "TIMELINE_EVENT_TYPE_USER_COMMENT"
CREATED_AT_FIELD = "created_at"
STEP_FETCH = "fetch"
STEP_INIT = "init"


def create_filter(field, value):
    return {"field": field, "stringContains": {"value": value}}


def extract_response(response: Any) -> list[dict[str, Any]]:
    if response.get("getTableResponse") is None:
        demisto.error(f"got bad response, {response}")
        raise Exception(f"got bad response, {response}")
    else:
        demisto.info(
            f"Count of entites: {response.get('getTableResponse').get('totalNumberOfResults')}"
        )
        entities = (
            response.get("getTableResponse", {}).get("data", {}).get("rows", [])
        )
        demisto.info(f"Got {len(entities)} entities")
        return entities


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
        risk_level: int | None = None,
        source: str | None = None,
        before: datetime | None = None,
        after: datetime | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
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
        alerts: list[dict[str, Any]] = []
        params: dict[str, Any] = {
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
            alerts = extract_response(response)
        except Exception as e:
            demisto.error(f"Findings Request ReadTimeout error: {str(e)}")
        demisto.info(f"done fetching RECO alerts, fetched {len(alerts)} alerts.")
        return alerts

    def get_alerts(
        self,
        risk_level: int | None = None,
        source: str | None = None,
        before: datetime | None = None,
        after: datetime | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """
        Fetch alerts from Reco API
        :param risk_level: The risk level of the incidents to fetch
        :param source: The source of the incidents to fetch
        :param before: The maximum date of the incidents to fetch
        :param after: The minimum date of the incidents to fetch
        :param limit: int
        :return: dict
        """
        demisto.info("Get alerts, enter")
        alerts: list[dict[str, Any]] = []
        params: dict[str, Any] = {
            "getTableRequest": {
                "tableName": RECO_ACTIVE_ALERTS_VIEW,
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
                url_suffix="/policy-subsystem/alert-inbox/table",
                data=json.dumps(params),
                timeout=RECO_API_TIMEOUT_IN_SECONDS,
            )
            alerts = extract_response(response)
        except Exception as e:
            demisto.error(f"Findings Request ReadTimeout error: {str(e)}")
        demisto.info(f"done fetching RECO alerts, fetched {len(alerts)} alerts.")
        return alerts

    def get_single_alert(self, alert_id: str) -> Any:
        """
        Fetch a single alert from Reco API
        :param alert_id: The id of the alert to fetch
        :return: dict
        """
        demisto.info(f"Get single alert, enter, alert_id: {alert_id}")
        alert: dict[str, Any] = {}
        try:
            response = self._http_request(
                method="GET",
                url_suffix=f"/policy-subsystem/alert-inbox/{alert_id}",
                timeout=RECO_API_TIMEOUT_IN_SECONDS,
            )
            if response.get("alert") is None:
                demisto.info(f"got bad response, {response}")
            else:
                demisto.info(f"got good response, {response}")
                alert = response.get("alert", {})
        except Exception as e:
            demisto.error(f"Validate API key ReadTimeout error: {str(e)}")
            raise e

        demisto.info(f"done fetching RECO alert, fetched {alert}")
        return alert

    def get_incidents_assets(self, incident_id: str) -> list[dict[str, Any]]:
        """
        Get assets of an incident.
        """
        demisto.info("Get incident assets, enter")
        result: list[dict[str, Any]] = []
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

    def get_risky_users(self) -> list[dict[str, Any]]:
        """Get risky users. Returns a list of risky users with analysis."""
        return self.get_identities(email_address=None, label=RISKY_USER)

    def get_identities(self, email_address: Optional[str] = None, label: Optional[str] = None) -> list[dict[str, Any]]:
        """
        Get identities from Reco with specified filters.

        :param email_address: Optional email substring to filter identities.
        :param label: Optional label value to filter identities.
        :return: A dictionary representing the getTableRequest payload.
        """
        params: Dict[str, Any] = {
            "getTableRequest": {
                "tableName": "RISK_MANAGEMENT_VIEW_IDENTITIES",
                "pageSize": 50,
                "fieldSorts": {
                    "sorts": [
                        {"sortBy": "primary_email_address", "sortDirection": "SORT_DIRECTION_ASC"}
                    ]
                },
                "fieldFilters": {
                    "relationship": "FILTER_RELATIONSHIP_AND",
                    "fieldFilterGroups": {
                        "fieldFilters": []
                    },
                    "forceEstimateSize": True
                },
            }
        }

        # Add label filter if provided
        if label is not None:
            label_filter = {
                "relationship": "FILTER_RELATIONSHIP_OR",
                "filters": {
                    "filters": [
                        {
                            "field": "labels",
                            "labelNameEquals": {
                                "keys": ["identity_id"],
                                "value": [label],
                                "filterColumn": "label_name",
                                "entryTypes": ["ENTRY_TYPE_IDENTITY"]
                            }
                        }
                    ]
                }
            }
            params["getTableRequest"]["fieldFilters"]["fieldFilterGroups"]["fieldFilters"].append(label_filter)

        # Add email address filter if provided
        if email_address:
            email_filter = {
                "relationship": "FILTER_RELATIONSHIP_OR",
                "filters": {
                    "filters": [
                        create_filter("full_name", email_address),
                        create_filter("primary_email_address", email_address)
                    ]
                }
            }
            params["getTableRequest"]["fieldFilters"]["fieldFilterGroups"]["fieldFilters"].append(email_filter)

        try:
            response = self._http_request(
                method="PUT",
                url_suffix="/risk-management/get-risk-management-table",
                timeout=RECO_API_TIMEOUT_IN_SECONDS,
                data=json.dumps(params),
            )
            return extract_response(response)
        except Exception as e:
            demisto.error(f"Validate API key ReadTimeout error: {str(e)}")
            raise e

    def get_exposed_publicly_files_at_risk(self) -> list[dict[str, Any]]:
        """Get exposed publicly files at risk. Returns a list of exposed publicly files at risk with analysis."""
        params: Dict[str, Any] = {
            "getTableRequest": {
                "tableName": "DATA_RISK_MANAGEMENT_VIEW_BREAKDOWN_EXPOSED_PUBLICLY",
                "pageSize": PAGE_SIZE,
                "fieldSorts": {
                    "sorts": [
                        {
                            "sortBy": "last_access_date",
                            "sortDirection": "SORT_DIRECTION_DESC"
                        }
                    ]
                },
                "fieldFilters": {
                    "relationship": "FILTER_RELATIONSHIP_OR",
                    "filters": {
                        "filters": [
                            {
                                "field": "data_category",
                                "stringEquals": {
                                    "value": "ALL"
                                }
                            }
                        ]
                    }
                }
            }
        }
        try:
            response = self._http_request(
                method="PUT",
                url_suffix="/risk-management/get-data-risk-management-table",
                timeout=RECO_API_TIMEOUT_IN_SECONDS,
                data=json.dumps(params),
            )
            return extract_response(response)
        except Exception as e:
            demisto.error(f"Validate API key ReadTimeout error: {str(e)}")
            raise e

    def get_files_exposed_to_email(self, email_account) -> list[dict[str, Any]]:
        """Get files exposed to email. Returns a list of files exposed to email with analysis."""
        params = {
            "getTableRequest": {
                "tableName": "data_posture_view_files_by_emails_slider",
                "pageSize": PAGE_SIZE,
                "fieldSorts": {
                    "sorts": [
                        {
                            "sortBy": "last_access_date",
                            "sortDirection": "SORT_DIRECTION_DESC"
                        }
                    ]
                },
                "fieldFilters": {
                    "relationship": "FILTER_RELATIONSHIP_AND",
                    "fieldFilterGroups": {
                        "fieldFilters": [
                            {
                                "relationship": "FILTER_RELATIONSHIP_AND",
                                "fieldFilterGroups": {
                                    "fieldFilters": [
                                        {
                                            "relationship": "FILTER_RELATIONSHIP_AND",
                                            "filters": {
                                                "filters": [
                                                    {
                                                        "field": "email_account",
                                                        "stringEquals": {
                                                            "value": f"{email_account}"
                                                        }
                                                    }
                                                ]
                                            }
                                        }
                                    ]
                                },
                                "forceEstimateSize": True
                            }
                        ]
                    },
                    "forceEstimateSize": True
                }
            }
        }
        try:
            response = self._http_request(
                method="PUT",
                url_suffix="/risk-management/get-data-risk-management-table",
                timeout=RECO_API_TIMEOUT_IN_SECONDS,
                data=json.dumps(params),
            )
            return extract_response(response)
        except Exception as e:
            demisto.error(f"Validate API key ReadTimeout error: {str(e)}")
            raise e

    def get_list_of_private_emails_with_access(self) -> list[dict[str, Any]]:
        """Get files exposed to email. Returns a list of private email addresses with access."""
        params = {
            "getTableRequest": {
                "tableName": "data_posture_view_private_email_with_access",
                "pageSize": PAGE_SIZE,
                "fieldSorts": {
                    "sorts": [
                        {
                            "sortBy": "files_num",
                            "sortDirection": "SORT_DIRECTION_DESC"
                        }
                    ]
                },
                "fieldFilters": {
                    "relationship": "FILTER_RELATIONSHIP_AND",
                    "fieldFilterGroups": {
                        "fieldFilters": []
                    },
                    "forceEstimateSize": True
                }
            }
        }
        try:
            response = self._http_request(
                method="PUT",
                url_suffix="/risk-management/get-data-risk-management-table",
                timeout=RECO_API_TIMEOUT_IN_SECONDS,
                data=json.dumps(params),
            )
            return extract_response(response)
        except Exception as e:
            demisto.error(f"Validate API key ReadTimeout error: {str(e)}")
            raise e

    def get_3rd_parties_risk_list(self, last_interaction_time_before_in_days: int) -> list[dict[str, Any]]:
        formatted_date = self.get_date_time_before_days_formatted(last_interaction_time_before_in_days)
        params = {
            "getTableRequest": {
                "tableName": "data_posture_view_3rd_parties_domain",
                "pageSize": PAGE_SIZE,
                "fieldSorts": {
                    "sorts": [
                        {
                            "sortBy": "files_num",
                            "sortDirection": "SORT_DIRECTION_DESC"
                        }
                    ]
                },
                "fieldFilters": {
                    "relationship": "FILTER_RELATIONSHIP_AND",
                    "fieldFilterGroups": {
                        "fieldFilters": [
                            {
                                "relationship": "FILTER_RELATIONSHIP_AND",
                                "fieldFilterGroups": {
                                    "fieldFilters": [
                                        {
                                            "relationship": "FILTER_RELATIONSHIP_AND",
                                            "filters": {
                                                "filters": [
                                                    {
                                                        "field": "last_activity",
                                                        "before": {
                                                            "value": f"{formatted_date}"
                                                        }
                                                    }
                                                ]
                                            }
                                        }
                                    ]
                                }
                            }
                        ]
                    },
                    "forceEstimateSize": True
                }
            }
        }
        try:
            response = self._http_request(
                method="PUT",
                url_suffix="/risk-management/get-data-risk-management-table",
                timeout=RECO_API_TIMEOUT_IN_SECONDS,
                data=json.dumps(params),
            )
            return extract_response(response)
        except Exception as e:
            demisto.error(f"Validate API key ReadTimeout error: {str(e)}")
            raise e

    @staticmethod
    def get_date_time_before_days_formatted(last_interaction_time_before_in_days: int) -> str:
        # Calculate the date 30 days ago
        thirty_days_ago = datetime.utcnow() - timedelta(days=last_interaction_time_before_in_days)
        # Format the date in the desired format
        formatted_date = thirty_days_ago.strftime('%Y-%m-%dT%H:%M:%S.999Z')
        return formatted_date

    def get_files_shared_with_3rd_parties(self,
                                          domain: str,
                                          last_interaction_time_before_in_days: int) -> list[dict[str, Any]]:
        """Get files shared with 3rd parties. Returns a list of files at risk with analysis."""
        formatted_date = self.get_date_time_before_days_formatted(last_interaction_time_before_in_days)
        params = {
            "getTableRequest": {
                "tableName": "data_posture_view_files_by_domain_slider",
                "pageSize": PAGE_SIZE,
                "fieldSorts": {
                    "sorts": [
                        {
                            "sortBy": "last_access_date",
                            "sortDirection": "SORT_DIRECTION_ASC"
                        }
                    ]
                },
                "fieldFilters": {
                    "relationship": "FILTER_RELATIONSHIP_AND",
                    "fieldFilterGroups": {
                        "fieldFilters": [
                            {
                                "relationship": "FILTER_RELATIONSHIP_AND",
                                "filters": {
                                    "filters": [
                                        {
                                            "field": "domain",
                                            "regexCaseInsensitive": {
                                                "value": f"{domain}"
                                            }
                                        },
                                        {
                                            "field": "last_access_date",
                                            "before": {
                                                "value": f"{formatted_date}"
                                            }
                                        }
                                    ]
                                }
                            }
                        ]
                    },
                    "forceEstimateSize": True
                }
            }
        }
        try:
            response = self._http_request(
                method="PUT",
                url_suffix="/risk-management/get-data-risk-management-table",
                timeout=RECO_API_TIMEOUT_IN_SECONDS,
                data=json.dumps(params),
            )
            return extract_response(response)
        except Exception as e:
            demisto.error(f"Validate API key ReadTimeout error: {str(e)}")
            raise e

    def get_assets_user_has_access(
        self, email_address: str, only_sensitive: bool
    ) -> list[dict[str, Any]]:
        """Get assets user has access to. Returns a list of assets."""
        params: dict[str, Any] = {
            "getTableRequest": {
                "tableName": "files_view",
                "pageSize": PAGE_SIZE,
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

        if only_sensitive is True:
            params["getTableRequest"]["fieldFilters"]["fieldFilterGroups"][
                "fieldFilters"
            ].append(
                {
                    "relationship": "FILTER_RELATIONSHIP_OR",
                    "filters": {
                        "filters": [
                            {
                                "field": "sensitivity_level",
                                # 30 confidential
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
                method="PUT",
                url_suffix="/asset-management/query",
                timeout=RECO_API_TIMEOUT_IN_SECONDS * 2,
                data=json.dumps(params),
            )
            return extract_response(response)
        except Exception as e:
            demisto.error(f"Validate API key ReadTimeout error: {str(e)}")
            raise e

    def get_assets_shared_externally(self, email_address: str) -> list[dict[str, Any]]:
        """Get assets user has access to. Returns a list of assets."""
        params: dict[str, Any] = {
            "getTableRequest": {
                "tableName": "files_view",
                "pageSize": PAGE_SIZE,
                "fieldSorts": {
                    "sorts": [
                        {
                            "sortBy": "last_access_date",
                            "sortDirection": "SORT_DIRECTION_DESC"
                        }
                    ]
                },
                "fieldFilters": {
                    "relationship": "FILTER_RELATIONSHIP_AND",
                    "fieldFilterGroups": {
                        "fieldFilters": [
                            {
                                "relationship": "FILTER_RELATIONSHIP_OR",
                                "filters": {
                                    "filters": [
                                        {
                                            "field": "permission_visibility",
                                            "stringEquals": {
                                                "value": "PERMISSION_TYPE_SHARED_EXTERNALLY"
                                            }
                                        }
                                    ]
                                }
                            },
                            {
                                "relationship": "FILTER_RELATIONSHIP_OR",
                                "filters": {
                                    "filters": [
                                        {
                                            "field": "file_owner",
                                            "stringContains": {
                                                "value": f"{email_address}"
                                            }
                                        }
                                    ]
                                }
                            }
                        ]
                    },
                    "forceEstimateSize": True
                },
            }
        }
        try:
            response = self._http_request(
                method="PUT",
                url_suffix="/asset-management/query",
                timeout=RECO_API_TIMEOUT_IN_SECONDS * 2,
                data=json.dumps(params),
            )
            return extract_response(response)
        except Exception as e:
            demisto.error(f"Validate API key ReadTimeout error: {str(e)}")
            raise e

    def get_user_context_by_email_address(
        self, email_address: str
    ) -> list[dict[str, Any]]:
        """ Get user context by email address. Returns a dict of user context. """
        identities = self.get_identities(email_address=email_address)
        if not identities:
            return []
        identity_ids = []
        for user in identities:
            user_as_dict = parse_table_row_to_dict(user.get("cells", {}))
            identity_id = user_as_dict.get("identity_id")
            if identity_id:
                identity_ids.append(identity_id)

        params: Dict[str, Any] = {
            "getTableRequest": {
                "tableName": "RISK_MANAGEMENT_VIEW_IDENTITIES",
                "pageSize": 1,
                "fieldSorts": {
                    "sorts": []
                },
                "fieldFilters": {
                    "relationship": "FILTER_RELATIONSHIP_OR",
                    "forceEstimateSize": True,
                    "filters": {"filters": []} if identity_ids else {},
                },
            }
        }

        # Add filters for multiple identity_ids
        if identity_ids:
            identity_filters = [
                {
                    "field": "identity_id",
                    "stringEquals": {"value": identity_id}
                }
                for identity_id in identity_ids
            ]
            params["getTableRequest"]["fieldFilters"]["filters"]["filters"] = identity_filters

        response = self._http_request(
            method="PUT",
            url_suffix="/risk-management/get-risk-management-table",
            timeout=RECO_API_TIMEOUT_IN_SECONDS * 2,
            data=json.dumps(params),
        )
        return extract_response(response)

    def get_sensitive_assets_information(self,
                                         asset_name: str | None,
                                         asset_id: str | None,
                                         sensitive_only: bool,
                                         regex_search: bool) -> list[dict[str, Any]]:
        """Get sensitive assets' information. Returns a list of assets."""
        filter = "regexCaseInsensitive" if regex_search else "stringEquals"
        field_to_search = "file_name" if asset_name else "asset_id"
        value_to_search = asset_name if asset_name else asset_id
        params: dict[str, Any] = {
            "getTableRequest": {
                "tableName": "files_view",
                "pageSize": PAGE_SIZE,
                "fieldFilters": {
                    "relationship": "FILTER_RELATIONSHIP_AND",
                    "fieldFilterGroups": {
                        "fieldFilters": [
                            {
                                "relationship": "FILTER_RELATIONSHIP_OR",
                                "filters": {
                                    "filters": [
                                        {
                                            "field": field_to_search,
                                            filter: {
                                                "value": value_to_search
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
        if sensitive_only:
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
                method="PUT",
                url_suffix="/asset-management/query",
                timeout=RECO_API_TIMEOUT_IN_SECONDS * 2,
                data=json.dumps(params),
            )
            return extract_response(response)
        except Exception as e:
            demisto.error(f"Validate API key ReadTimeout error: {str(e)}")
            raise e

    def get_link_to_user_overview_page(self, link_type: str, entity_id: str) -> str:
        """
        Get link to user overview page.
        :param link_type: The link type to get (RM_LINK_TYPE_USER).
        :param entity_id: The entity id. In case of user, it's the user's email address.
        :return: dict
        """
        demisto.info(f"Getting link to {link_type} overview page for {entity_id}")
        try:
            response = self._http_request(
                method="GET",
                url_suffix=f"/risk-management/risk-management/link?link_type={link_type}&param={entity_id}",
                timeout=RECO_API_TIMEOUT_IN_SECONDS,
            )
            if response.get("link") is None:
                demisto.info(f"got bad response, {response}")
            else:
                demisto.info(f"got good response, {response}")
                link = response.get("link", None)
        except Exception as e:
            demisto.error(f"Validate API key ReadTimeout error: {str(e)}")
            raise e

        demisto.info(f"Got link: {link}")  # pylint: disable=E0606
        return link

    def add_exclusion_filter(self, key_to_add: str, values_to_add: list[str]):
        body = {"environmentName": "string", "keyToAddTo": key_to_add, "valuesToAdd": values_to_add}

        try:
            response = self._http_request(
                method="POST",
                url_suffix="/algo/add_values_to_data_type_exclude_analyzer",
                timeout=RECO_API_TIMEOUT_IN_SECONDS * 2,
                data=json.dumps(body),
            )
            return response
        except Exception as e:
            demisto.error(f"Can't add exclusion filter: {str(e)}")
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

    def change_alert_status(self, alert_id: str, status: str) -> Any:
        """Change alert status."""
        try:
            response = self._http_request(
                method="PUT",
                url_suffix=f"/policy-subsystem/alert-inbox/{alert_id}/status/{status}",
                timeout=RECO_API_TIMEOUT_IN_SECONDS,
            )
        except Exception as e:
            demisto.error(f"Change alert status error: {str(e)}")
            raise e
        demisto.info(f"Alert {alert_id} status changed to {status}")
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
                method="GET",
                url_suffix="/policy-subsystem/alert-inbox?limit=1",
                timeout=RECO_API_TIMEOUT_IN_SECONDS,
            )
            if response.get("alerts") is None:
                demisto.info(f"got bad response, {response}")
            else:
                demisto.info(f"got good response, {response}")
                return "ok"
        except Exception as e:
            demisto.error(f"Validate API key Error: {str(e)}")
            raise e
        return invalid_token_string


def parse_table_row_to_dict(alert: list[dict[str, Any]]) -> dict[str, Any]:
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
        if key != "labels":
            obj[key] = obj[key].replace('"', "")
        if key in ["updated_at", "created_at", "event_time"]:
            try:
                parsed_time = datetime.strptime(obj[key], RECO_TIME_FORMAT)
            except Exception:
                parsed_time = datetime.strptime(obj[key], DEMISTO_OCCURRED_FORMAT)
            if parsed_time:
                obj[key] = parsed_time.strftime(DEMISTO_OCCURRED_FORMAT)
        if key == "risk_level":
            try:
                obj[key] = int(obj[key])
            except Exception:
                demisto.info(f"Could not parse risk level {obj[key]} to int")
        if key in ["group", "job_title", "departments", "labels"]:
            try:
                obj[key] = json.loads(obj[key])
            except Exception:
                pass
        alert_as_dict[key] = obj[key]

    return alert_as_dict


def get_alerts(reco_client: RecoClient,
               risk_level: int | None = None,
               source: str | None = None,
               before: datetime | None = None,
               after: datetime | None = None,
               limit: int = 1000) -> list[Any]:
    """Get alerts from Reco.
    :param reco_client: The Reco client
    :param risk_level: The risk level to filter by
    :param source: The source to filter by
    :param before: The before time to filter by
    :param after: The after time to filter by
    :param limit: The limit of alerts to get
    :return: The alerts"""
    alerts = reco_client.get_alerts(risk_level, source, before, after, limit)
    alerts_data = []
    for alert in alerts:
        alert_as_dict = parse_table_row_to_dict(alert.get("cells", {}))
        alert_id = alert_as_dict.get("id", None)
        if alert_id is not None:
            alert_id = base64.b64decode(alert_id).decode("utf-8")
            single_alert = reco_client.get_single_alert(alert_id)
            violations = single_alert["policyViolations"]
            for violation in violations:
                violation_data = json.loads(base64.b64decode(violation["jsonData"]))
                if "violation" in violation_data:
                    violation_data.pop("violation")
                violation["jsonData"] = violation_data
            single_alert["policyViolations"] = json.loads(json.dumps(single_alert["policyViolations"]))
            alerts_data.append(single_alert)
        else:
            demisto.info(f"Got alert without id: {alert_as_dict}")
    return alerts_data


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
            headers=user_as_dict.keys(),
        ),
        outputs_prefix="Reco.RiskyUsers",
        outputs_key_field="primary_email_address",
        outputs=users,
        raw_response=risky_users,
    )


def add_risky_user_label(reco_client: RecoClient, email_address: str) -> CommandResults:
    """Add a risky user to Reco."""

    users = reco_client.get_identities(email_address)
    for user in users:
        user_as_dict = parse_table_row_to_dict(user.get("cells", {}))
        raw_response = reco_client.set_entry_label_relations(
            user_as_dict["identity_id"], RISKY_USER, LABEL_STATUS_ACTIVE, ENTRY_TYPE_IDENTITY
        )

    return CommandResults(
        raw_response=raw_response,
        readable_output=f"User {email_address} labeled as risky",
    )


def add_leaving_org_user(reco_client: RecoClient, email_address: str) -> CommandResults:
    """Tag user as leaving org."""
    users = reco_client.get_identities(email_address)
    for user in users:
        user_as_dict = parse_table_row_to_dict(user.get("cells", {}))
        raw_response = reco_client.set_entry_label_relations(
            user_as_dict["identity_id"], LEAVING_ORG_USER, LABEL_STATUS_ACTIVE, ENTRY_TYPE_IDENTITY
        )

    return CommandResults(
        raw_response=raw_response,
        readable_output=f"User {email_address} labeled as leaving org user",
    )


def enrich_incident(
    reco_client: RecoClient, single_incident: dict[str, Any]
) -> dict[str, Any]:
    alert_as_dict = parse_table_row_to_dict(single_incident.get("cells", {}))
    if RECO_INCIDENT_ID_FIELD in alert_as_dict:
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
) -> int | float:  # pylint: disable=E1136
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


def map_reco_alert_score_to_demisto_score(
    reco_score: str,
) -> int | float:  # pylint: disable=E1136
    # demisto_unknown = 0  (commented because of linter issues)
    demisto_informational = 0.5
    # demisto_low = 1  (commented because of linter issues)
    demisto_medium = 2
    demisto_high = 3
    demisto_critical = 4

    # LHS is Reco score
    MAPPING = {
        "CRITICAL": demisto_critical,
        "HIGH": demisto_high,
        "MEDIUM": demisto_medium,
        "LOW": demisto_informational,
    }

    return MAPPING[reco_score]


def parse_incidents_objects(
    reco_client: RecoClient, incidents_raw: list[dict[str, Any]]
) -> list[dict[str, Any]]:
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


def get_sensitive_assets_shared_with_public_link(reco_client: RecoClient) -> CommandResults:
    """Get sensitive assets shared with public link from Reco."""
    assets = reco_client.get_exposed_publicly_files_at_risk()
    assets_list = []
    for asset in assets:
        asset_as_dict = parse_table_row_to_dict(asset.get("cells", {}))
        assets_list.append(asset_as_dict)
    return CommandResults(
        readable_output=tableToMarkdown(
            "Assets",
            assets_list,
            headers=[
                "asset_id",
                "asset",
                "data_category",
                "data_categories",
                "last_access_date",
                "visibility",
                "location",
            ],
        ),
        outputs_prefix="Reco.Assets",
        outputs_key_field="asset_id",
        outputs=assets_list,
        raw_response=assets,
    )


def get_assets_shared_externally_command(reco_client: RecoClient, email_address) -> CommandResults:
    """Get assets shared externally ."""
    assets = reco_client.get_assets_shared_externally(email_address)
    assets_list = []
    for asset in assets:
        asset_as_dict = parse_table_row_to_dict(asset.get("cells", {}))
        assets_list.append(asset_as_dict)
    return CommandResults(
        readable_output=tableToMarkdown(
            "Assets",
            assets_list,
            headers=[
                "asset_id",
                "asset",
                "data_category",
                "data_categories",
                "last_access_date",
                "visibility",
                "location",
                "file_owner"
            ],
        ),
        outputs_prefix="Reco.Assets",
        outputs_key_field="asset_id",
        outputs=assets_list,
        raw_response=assets,
    )


def get_files_exposed_to_email_command(reco_client: RecoClient, email_account: str) -> CommandResults:
    """Get files exposed to email. Returns a list of files exposed to email with analysis."""
    assets = reco_client.get_files_exposed_to_email(email_account)
    assets_list = []
    for asset in assets:
        asset_as_dict = parse_table_row_to_dict(asset.get("cells", {}))
        assets_list.append(asset_as_dict)
    return CommandResults(
        readable_output=tableToMarkdown(
            "Assets",
            assets_list,
            headers=[
                "asset_id",
                "asset",
                "data_category",
                "data_categories",
                "last_access_date",
                "visibility",
                "location",
                "email_account",
                "file_owner"
            ],
        ),
        outputs_prefix="Reco.Assets",
        outputs_key_field="asset_id",
        outputs=assets_list,
        raw_response=assets,
    )


def get_3rd_parties_list(reco_client: RecoClient, last_interaction_time_in_days: int) -> CommandResults:
    """Get 3rd parties list from Reco."""
    domains = reco_client.get_3rd_parties_risk_list(last_interaction_time_in_days)
    domains_list = []
    for domain in domains:
        domain_as_dict = parse_table_row_to_dict(domain.get("cells", {}))
        domains_list.append(domain_as_dict)
    return CommandResults(
        readable_output=tableToMarkdown(
            "Domains",
            domains_list,
            headers=[
                "domain",
                "last_activity",
                "files_num",
                "users_with_access_num",
            ],
        ),
        outputs_prefix="Reco.Domains",
        outputs_key_field="domain",
        outputs=domains_list,
        raw_response=domains,
    )


def get_files_shared_with_3rd_parties(reco_client: RecoClient,
                                      domain: str,
                                      last_interaction_time_before_in_days: int) -> CommandResults:
    """Get files shared with 3rd parties from Reco."""
    files = reco_client.get_files_shared_with_3rd_parties(domain, last_interaction_time_before_in_days)
    files_list = []
    for file in files:
        file_as_dict = parse_table_row_to_dict(file.get("cells", {}))
        files_list.append(file_as_dict)
    return CommandResults(
        readable_output=tableToMarkdown(
            "Files",
            files_list,
            headers=[
                "domain",
                "location",
                "users",
                "file_owner",
                "data_category",
                "asset",
                "last_access_date",
                "asset_id",
            ],
        ),
        outputs_prefix="Reco.Assets",
        outputs_key_field="asset_id",
        outputs=files_list,
        raw_response=files,
    )


def get_sensitive_assets_by_name(reco_client: RecoClient, asset_name: str, regex_search: bool) -> CommandResults:
    """Get sensitive assets from Reco. If contains is True, the asset name will be searched as a regex."""
    assets = reco_client.get_sensitive_assets_information(asset_name, None, True, regex_search)
    return assets_to_command_result(assets)


def get_assets_by_id(reco_client: RecoClient, asset_id: str) -> CommandResults:
    """Get assets from Reco by file id."""
    assets = reco_client.get_sensitive_assets_information(None, asset_id, False, False)
    return assets_to_command_result(assets)


def get_user_context_by_email_address(reco_client: RecoClient, email_address: str) -> CommandResults:
    users_context = reco_client.get_user_context_by_email_address(email_address)
    user_as_dict = None
    headers = []
    if len(users_context) > 0:
        user_as_dict = parse_table_row_to_dict(users_context[0].get("cells", {}))
        headers = list(user_as_dict.keys())

    return CommandResults(
        readable_output=tableToMarkdown(
            "User",
            user_as_dict,
            headers=headers
        ),
        outputs_prefix="Reco.User",
        outputs_key_field="email_address",
        outputs=user_as_dict,
        raw_response=users_context)


def add_exclusion_filter(reco_client: RecoClient, key_to_add: str, values: list[str]) -> CommandResults:
    """Add exclusion filter to Reco."""
    response = reco_client.add_exclusion_filter(key_to_add, values)
    return CommandResults(raw_response=response, readable_output="Exclusion filter added successfully")


def change_alert_status(reco_client: RecoClient, alert_id: str, status: str) -> CommandResults:
    """Change alert status."""
    response = reco_client.change_alert_status(alert_id, status)
    return CommandResults(raw_response=response, readable_output=f"Alert {alert_id} status changed successfully to {status}")


def assets_to_command_result(assets: list[dict[str, Any]]) -> CommandResults:
    """Convert assets to CommandResults."""
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


def get_sensitive_assets_by_id(reco_client: RecoClient, asset_id: str) -> CommandResults:
    """Get sensitive assets from Reco by file id."""
    assets = reco_client.get_sensitive_assets_information(None, asset_id, True, False)
    return assets_to_command_result(assets)


def get_link_to_user_overview_page(reco_client: RecoClient, entity: str, link_type: str) -> CommandResults:
    link = reco_client.get_link_to_user_overview_page(link_type, entity)
    return CommandResults(outputs_prefix="Reco.Link",
                          outputs={"link": link}, raw_response=link)


def fetch_incidents(
    reco_client: RecoClient,
    last_run: dict[str, Any],
    max_fetch: int,
    risk_level: int | None = None,
    source: str | None = None,
    before: datetime | None = None,
    after: datetime | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    demisto.info(f"fetch-incidents called {max_fetch=}")
    next_run = {}
    incidents = []
    last_run_time = last_run.get("lastRun", None)
    if last_run_time is not None:
        after = dateutil.parser.parse(last_run_time)

    try:
        incidents_raw = reco_client.get_incidents(risk_level=risk_level,
                                                  source=source,
                                                  before=before,
                                                  after=after,
                                                  limit=max_fetch)
        incidents = parse_incidents_objects(reco_client, incidents_raw)
    except Exception as e:
        demisto.info(f"Error fetching incidents: {e}")

    alerts = get_alerts(reco_client, risk_level, source, before, after, max_fetch)
    alerts_as_incidents = parse_alerts_to_incidents(alerts)
    incidents.extend(alerts_as_incidents)

    existing_incidents = last_run.get("incident_ids", [])
    incidents = [
        incident for incident in incidents
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


def parse_alerts_to_incidents(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts_as_incidents = []
    for alert in alerts:
        incident = {
            "name": alert.get("description", ""),
            "occurred": alert.get("createdAt", ""),
            "dbotMirrorId": alert.get("id", ""),
            "rawJSON": json.dumps(alert),
            "severity": map_reco_alert_score_to_demisto_score(
                reco_score=alert.get("riskLevel", DEMISTO_INFORMATIONAL)
            ),
        }

        alerts_as_incidents.append(incident)
    return alerts_as_incidents


def get_max_fetch(max_fetch: int) -> int:
    if max_fetch > 500:
        return 500
    return max_fetch


def get_private_email_list_with_access(reco_client):
    result = reco_client.get_list_of_private_emails_with_access()
    identities_list = []
    for identity in result:
        asset_as_dict = parse_table_row_to_dict(identity.get("cells", {}))
        identities_list.append(asset_as_dict)
    return CommandResults(
        readable_output=tableToMarkdown(
            "PrivateEmails",
            identities_list,
            headers=[
                "email_account",
                "primary_email",
                "files_num",
                "user_category",
            ],
        ),
        outputs_prefix="Reco.privateEmails",
        outputs_key_field="email_account",
        outputs=identities_list,
        raw_response=result,
    )


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
        elif command == "reco-get-sensitive-assets-by-id":
            result = get_sensitive_assets_by_id(
                reco_client,
                demisto.args()["asset_id"]
            )
            return_results(result)
        elif command == "reco-get-link-to-user-overview-page":
            result = get_link_to_user_overview_page(
                reco_client,
                demisto.args()["entity"],
                demisto.args()["param"],
            )
            return_results(result)
        elif command == "reco-get-sensitive-assets-with-public-link":
            result = get_sensitive_assets_shared_with_public_link(reco_client)
            return_results(result)
        elif command == "reco-get-3rd-parties-accessible-to-data-list":
            result = get_3rd_parties_list(reco_client, int(demisto.args()["last_interaction_time_in_days"]))
            return_results(result)
        elif command == "reco-get-files-shared-with-3rd-parties":
            result = get_files_shared_with_3rd_parties(reco_client,
                                                       demisto.args()["domain"],
                                                       int(demisto.args()["last_interaction_time_in_days"]))
            return_results(result)
        elif command == "reco-add-exclusion-filter":
            result = add_exclusion_filter(reco_client, demisto.args()["key_to_add"],
                                          argToList(demisto.args()["values_to_add"]))
            return_results(result)
        elif command == "reco-change-alert-status":
            result = change_alert_status(reco_client, demisto.args()["alert_id"], demisto.args()["status"])
            return_results(result)
        elif command == "reco-get-user-context-by-email-address":
            result = get_user_context_by_email_address(reco_client, demisto.args()["email_address"])
            return_results(result)
        elif command == "reco-get-files-exposed-to-email-address":
            result = get_files_exposed_to_email_command(reco_client, demisto.args()["email_address"])
            return_results(result)
        elif command == "reco-get-assets-shared-externally":
            result = get_assets_shared_externally_command(reco_client, demisto.args()["email_address"])
            return_results(result)
        elif command == "reco-get-private-email-list-with-access":
            result = get_private_email_list_with_access(reco_client)
            return_results(result)
        elif command == "reco-get-assets-by-id":
            result = get_assets_by_id(reco_client, demisto.args()["asset_id"])
            return_results(result)
        else:
            raise NotImplementedError(f"{command} is not an existing reco command")
    except Exception as e:
        demisto.error(f"Failed to execute {demisto.command()} command. Error: {str(e)}")
        return_error(str(e))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
