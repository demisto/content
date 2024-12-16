import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *  # noqa

import abc
import dateparser
from datetime import datetime, timedelta
from typing import Any, TypeAlias
from collections.abc import Collection, Callable
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

SMALLEST_TIME_UNIT = timedelta(seconds=1)

MAX_REQUEST_LIMIT = 5_000

DEFAULT_REQUEST_LIMIT = 1_000

MAX_FETCH_LIMIT = 50_000
DEFAULT_FETCH_LIMIT = 50_000

DEVICE_ALERT_FIELDS = {
    "alert_assignees",
    "alert_category",
    "alert_class",
    "alert_id",
    "alert_labels",
    "alert_name",
    "alert_type_name",
    "alert_description",
    "device_alert_detected_time",
    "device_alert_status",
    "device_alert_updated_time",
    "device_assignees",
    "device_category",
    "device_effective_likelihood_subscore",
    "device_effective_likelihood_subscore_points",
    "device_first_seen_list",
    "device_impact_subscore",
    "device_impact_subscore_points",
    "device_insecure_protocols",
    "device_insecure_protocols_points",
    "device_internet_communication",
    "device_ip_list",
    "device_known_vulnerabilities",
    "device_known_vulnerabilities_points",
    "device_labels",
    "device_last_seen_list",
    "device_likelihood_subscore",
    "device_likelihood_subscore_points",
    "device_mac_list",
    "device_manufacturer",
    "device_name",
    "device_network_list",
    "device_purdue_level",
    "device_retired",
    "device_risk_score",
    "device_risk_score_points",
    "device_site_name",
    "device_subcategory",
    "device_type",
    "device_uid",
    "mitre_technique_enterprise_ids",
    "mitre_technique_enterprise_names",
    "mitre_technique_ics_ids",
    "mitre_technique_ics_names",
}

DEVICE_VULNERABILITY_FIELDS = {
    "device_network_list",
    "device_category",
    "device_subcategory",
    "device_type",
    "device_uid",
    "device_asset_id",
    "device_mac_list",
    "device_ip_list",
    "device_type_family",
    "device_model",
    "device_os_category",
    "device_serial_number",
    "device_vlan_list",
    "device_retired",
    "device_labels",
    "device_assignees",
    "device_hw_version",
    "device_local_name",
    "device_os_name",
    "device_os_version",
    "device_os_revision",
    "device_os_subcategory",
    "device_combined_os",
    "device_endpoint_security_names",
    "device_equipment_class",
    "device_consequence_of_failure",
    "device_management_services",
    "device_ad_distinguished_name",
    "device_ad_description",
    "device_mdm_ownership",
    "device_mdm_enrollment_status",
    "device_mdm_compliance_status",
    "device_last_domain_user",
    "device_fda_class",
    "device_mobility",
    "device_purdue_level",
    "device_purdue_level_source",
    "device_dhcp_hostnames",
    "device_http_hostnames",
    "device_snmp_hostnames",
    "device_windows_hostnames",
    "device_other_hostnames",
    "device_windows_last_seen_hostname",
    "device_dhcp_last_seen_hostname",
    "device_http_last_seen_hostname",
    "device_snmp_last_seen_hostname",
    "device_ae_titles",
    "device_dhcp_fingerprint",
    "device_note",
    "device_domains",
    "device_battery_level",
    "device_internet_communication",
    "device_financial_cost",
    "device_handles_pii",
    "device_machine_type",
    "device_phi",
    "device_cmms_state",
    "device_cmms_ownership",
    "device_cmms_asset_tag",
    "device_cmms_campus",
    "device_cmms_building",
    "device_cmms_location",
    "device_cmms_floor",
    "device_cmms_department",
    "device_cmms_owning_cost_center",
    "device_cmms_asset_purchase_cost",
    "device_cmms_room",
    "device_cmms_manufacturer",
    "device_cmms_model",
    "device_cmms_serial_number",
    "device_cmms_last_pm",
    "device_cmms_technician",
    "device_edr_is_up_to_date_text",
    "device_mac_oui_list",
    "device_ip_assignment_list",
    "device_protocol_location_list",
    "device_vlan_name_list",
    "device_vlan_description_list",
    "device_connection_type_list",
    "device_ssid_list",
    "device_bssid_list",
    "device_wireless_encryption_type_list",
    "device_ap_name_list",
    "device_ap_location_list",
    "device_switch_mac_list",
    "device_switch_ip_list",
    "device_switch_name_list",
    "device_switch_port_list",
    "device_switch_location_list",
    "device_switch_port_description_list",
    "device_wlc_name_list",
    "device_wlc_location_list",
    "device_applied_acl_list",
    "device_applied_acl_type_list",
    "device_collection_servers",
    "device_edge_locations",
    "device_number_of_nics",
    "device_last_domain_user_activity",
    "device_last_scan_time",
    "device_edr_last_scan_time",
    "device_retired_since",
    "device_os_eol_date",
    "device_last_seen_list",
    "device_first_seen_list",
    "device_wifi_last_seen_list",
    "device_last_seen_on_switch_list",
    "device_is_online",
    "device_network_scope_list",
    "device_ise_authentication_method_list",
    "device_ise_endpoint_profile_list",
    "device_ise_identity_group_list",
    "device_ise_security_group_name_list",
    "device_ise_security_group_tag_list",
    "device_ise_logical_profile_list",
    "device_cppm_authentication_status_list",
    "device_cppm_roles_list",
    "device_cppm_service_list",
    "device_name",
    "device_manufacturer",
    "device_site_name",
    "device_risk_score",
    "device_risk_score_points",
    "device_effective_likelihood_subscore",
    "device_effective_likelihood_subscore_points",
    "device_likelihood_subscore",
    "device_likelihood_subscore_points",
    "device_impact_subscore",
    "device_impact_subscore_points",
    "device_known_vulnerabilities",
    "device_known_vulnerabilities_points",
    "device_insecure_protocols",
    "device_insecure_protocols_points",
    "device_suspicious",
    "device_switch_group_name_list",
    "device_managed_by",
    "device_authentication_user_list",
    "device_collection_interfaces",
    "device_slot_cards",
    "device_cmms_financial_cost",
    "device_software_or_firmware_version",
    "device_enforcement_or_authorization_profiles_list",
    "device_ise_security_group_description_list",
    "device_recommended_firewall_group_name",
    "device_recommended_zone_name",
    "vulnerability_id",
    "vulnerability_name",
    "vulnerability_type",
    "vulnerability_cve_ids",
    "vulnerability_cvss_v2_score",
    "vulnerability_cvss_v2_exploitability_subscore",
    "vulnerability_cvss_v3_score",
    "vulnerability_cvss_v3_exploitability_subscore",
    "vulnerability_adjusted_vulnerability_score",
    "vulnerability_adjusted_vulnerability_score_level",
    "vulnerability_epss_score",
    "vulnerability_sources",
    "vulnerability_description",
    "vulnerability_affected_products",
    "vulnerability_recommendations",
    "vulnerability_exploits_count",
    "vulnerability_is_known_exploited",
    "vulnerability_published_date",
    "vulnerability_labels",
    "vulnerability_assignees",
    "vulnerability_note",
    "vulnerability_last_updated",
    "vulnerability_relevance",
    "vulnerability_relevance_sources",
    "vulnerability_manufacturer_remediation_info",
    "vulnerability_manufacturer_remediation_info_source",
    "vulnerability_overall_cvss_v3_score",
    "device_vulnerability_detection_date",
    "device_vulnerability_resolution_date",
    "device_vulnerability_days_to_resolution",
    "patch_install_date",
}

INCIDENT_TIMESTAMP_FIELD = "device_alert_updated_time"

QueryFilterType: TypeAlias = dict[str, Any]


''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def _force_get_all_wrapper(
        self,
        paginated_getter_func: Callable,
        items_name: str,
        fields: Collection[str],
        filter_by: QueryFilterType | None = None,
        sort_by: list[dict] | None = None,
        stop_after: int | None = None,
        start_from: int | None = None,
    ) -> list[dict]:
        offset = start_from or 0
        batch_size = MAX_REQUEST_LIMIT
        result = paginated_getter_func(
            fields=fields, filter_by=filter_by, offset=offset, limit=batch_size, sort_by=sort_by, count=True
        )
        last_fetched_items = result.get(items_name, [])
        all_items = last_fetched_items

        while (res_cnt := len(last_fetched_items)) >= batch_size and (stop_after is None or len(all_items) < stop_after):
            offset += res_cnt
            result = paginated_getter_func(
                fields=fields, filter_by=filter_by, offset=offset, limit=batch_size, sort_by=sort_by, count=True
            )
            last_fetched_items = result.get(items_name, [])
            all_items.extend(last_fetched_items)
        return all_items[:stop_after] if stop_after is not None else all_items

    def get_device_alert_relations(
        self,
        fields: Collection[str],
        filter_by: QueryFilterType | None = None,
        offset: int = 0,
        limit: int = DEFAULT_REQUEST_LIMIT,
        sort_by: list[dict] | None = None,
        count: bool = False,
    ) -> dict:
        body = {"offset": offset, "limit": limit, "fields": list(fields), "include_count": count}
        if filter_by:
            body["filter_by"] = filter_by
        if sort_by:
            body["sort_by"] = sort_by
        return self._http_request("POST", url_suffix="device_alert_relations/", json_data=body)

    def get_device_vulnerability_relations(
        self,
        fields: Collection[str],
        filter_by: QueryFilterType | None = None,
        offset: int = 0,
        limit: int = DEFAULT_REQUEST_LIMIT,
        sort_by: list[dict] | None = None,
        count: bool = False,
    ) -> dict:
        body = {"offset": offset, "limit": limit, "fields": list(fields), "include_count": count}
        if filter_by:
            body["filter_by"] = filter_by
        if sort_by:
            body["sort_by"] = sort_by
        return self._http_request("POST", url_suffix="device_vulnerability_relations/", json_data=body)

    def force_get_all_device_vulnerability_relations(
        self,
        fields: Collection[str],
        filter_by: QueryFilterType | None = None,
        sort_by: list[dict] | None = None,
        stop_after: int | None = None,
        start_from: int | None = None,
    ) -> list[dict]:
        return self._force_get_all_wrapper(
            paginated_getter_func=self.get_device_vulnerability_relations,
            items_name="devices_vulnerabilities",
            fields=fields,
            filter_by=filter_by,
            sort_by=sort_by,
            stop_after=stop_after,
            start_from=start_from,
        )

    def force_get_all_device_alert_relations(
        self,
        fields: Collection[str],
        filter_by: QueryFilterType | None = None,
        sort_by: list[dict] | None = None,
        stop_after: int | None = None,
        start_from: int | None = None,
    ) -> list[dict]:
        return self._force_get_all_wrapper(
            paginated_getter_func=self.get_device_alert_relations,
            items_name="devices_alerts",
            fields=fields,
            filter_by=filter_by,
            sort_by=sort_by,
            stop_after=stop_after,
            start_from=start_from,
        )

    def set_device_single_alert_relations(self, alert_id: int, device_uids: list[str] | None, status: str) -> dict | None:
        devices_uids_filter = _simple_filter("uid", "in", device_uids) if device_uids else None
        return self.set_device_alert_relations([alert_id], devices_uids_filter, status)

    def set_device_alert_relations(self, alert_ids: list[int], device_filter_by: dict | None, status: str) -> dict:
        body = {"alerts": {"alert_ids": alert_ids}, "status": status}
        if device_filter_by:
            body["devices"] = {"filter_by": device_filter_by}
        return self._http_request("POST", url_suffix="device-alert-status/set/", json_data=body)


''' HELPER FUNCTIONS '''


def _device_alert_relation_id(device_alert_relation: dict) -> tuple[int, str]:
    return device_alert_relation["alert_id"], device_alert_relation["device_uid"]


def _device_alert_relation_id_str(device_alert_relation: dict) -> str:
    dar_id = _device_alert_relation_id(device_alert_relation)
    return f"{dar_id[0]}↔{dar_id[1]}"


def _split_device_alert_relation_id(device_alert_relation_id: str) -> tuple[int, str]:
    alert_id, device_uid = device_alert_relation_id.split("↔")
    return int(alert_id), device_uid


def _device_alert_relation_name(device_alert_relation: dict) -> str:
    return f"Alert “{device_alert_relation.get('alert_name', '')}” on Device “{device_alert_relation.get('device_name', '')}”"


def _format_date(date: str | datetime, format: str = DATE_FORMAT) -> str:
    dt = date if isinstance(date, datetime) else dateparser.parse(date)
    assert dt is not None
    return dt.strftime(format)


def _ascending(field: str) -> dict[str, str]:
    return {"field": field, "order": "asc"}


def _simple_filter(field: str, operation: str, value: Any) -> QueryFilterType:
    return {"field": field, "operation": operation, "value": value}


def _build_alert_types_filter(alert_types: list[str]) -> QueryFilterType:
    return _simple_filter("alert_type_name", "in", [at.strip() for at in alert_types])


def _compound_filter(op: str, *filters: dict | None) -> QueryFilterType | None:
    filters = [f for f in filters if f]
    return None if not filters else filters[0] if len(filters) == 1 else {"operation": op, "operands": filters}


def _and(*filters: dict | None) -> QueryFilterType | None:
    return _compound_filter("and", *filters)


def _or(*filters: dict | None) -> QueryFilterType | None:
    return _compound_filter("or", *filters)


def _device_alert_relation_to_incident(device_alert_relation: dict[str, Any]) -> dict[str, Any]:
    return {
        "dbotMirrorId": _device_alert_relation_id_str(device_alert_relation),
        "name": _device_alert_relation_name(device_alert_relation),
        "occurred": device_alert_relation[INCIDENT_TIMESTAMP_FIELD],
        "rawJSON": json.dumps(device_alert_relation),
    }


def _next_tick(date_time: str) -> str:
    parsed_time = dateparser.parse(date_time)
    assert parsed_time is not None
    return _format_date(parsed_time + SMALLEST_TIME_UNIT)


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        # This  should validate all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.
        client.get_device_alert_relations(fields=["device_uid", "alert_id"], limit=1)
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


class XDomeCommand(abc.ABC):
    retired_field_name: str = "retired"

    @classmethod
    @abc.abstractmethod
    def all_fields(cls) -> set[str]: ...

    @classmethod
    def _constant_filter(cls) -> QueryFilterType | None:
        return None

    @classmethod
    def exclude_retired_filter(cls):
        return _simple_filter(cls.retired_field_name, "in", [False])

    def __init__(
        self,
        client: Client,
        fields: str | None,
        filter_by: str | None,
        offset: str | None,
        limit: str | None,
        sort_by: str | None,
    ):
        self._client = client
        self._raw_args = {"fields": fields, "filter_by": filter_by, "offset": offset, "limit": limit, "sort_by": sort_by}
        self._fields = self._parse_fields(fields or "all")
        self._filter_by = self._parse_filter_by(filter_by)
        self._offset = int(offset or 0)
        self._limit = int(limit or DEFAULT_REQUEST_LIMIT)
        self._sort_by = json.loads(sort_by) if sort_by else None

    def execute(self) -> CommandResults:
        return self._generate_results(self._get_data())

    def _parse_fields(self, raw_fields: str) -> Collection[str]:
        parsed_fields = [field.strip() for field in raw_fields.split(",")]
        return self.all_fields() if "all" in parsed_fields else parsed_fields

    def _parse_filter_by(self, raw_filter_by: str | None) -> QueryFilterType:
        """parse the raw filter input and make sure to always exclude retired devices"""
        filter_by = json.loads(raw_filter_by) if raw_filter_by else None
        filter_by = _and(filter_by, self.exclude_retired_filter(), self._constant_filter())
        assert filter_by
        return filter_by

    @abc.abstractmethod
    def _get_data(self) -> list: ...

    @abc.abstractmethod
    def _generate_results(self, raw_response: list | dict) -> CommandResults: ...


class XDomeGetDeviceAlertRelationsCommand(XDomeCommand):
    retired_field_name: str = "device_retired"

    @classmethod
    def all_fields(cls) -> set[str]:
        return DEVICE_ALERT_FIELDS

    def _get_data(self) -> list:
        return self._client.force_get_all_device_alert_relations(
            fields=self._fields,
            filter_by=self._filter_by,
            sort_by=self._sort_by,
            stop_after=self._limit if self._raw_args.get("limit") is not None else None,
            start_from=self._offset if self._raw_args.get("offset") is not None else None,
        )

    def _generate_results(self, raw_response: list | dict) -> CommandResults:
        device_alert_pairs = raw_response
        outputs = {
            "XDome.DeviceAlert(val.device_uid == obj.device_uid && val.alert_id == obj.alert_id)": device_alert_pairs
        }
        human_readable_output = tableToMarkdown("xDome device-alert-pairs List", device_alert_pairs)
        return CommandResults(
            outputs_prefix='XDome.DeviceAlert',
            outputs=outputs,
            readable_output=human_readable_output,
            raw_response=raw_response,
        )


class XDomeGetDeviceVulnerabilityRelationsCommand(XDomeCommand):
    retired_field_name: str = "device_retired"

    @classmethod
    def all_fields(cls) -> set[str]:
        return DEVICE_VULNERABILITY_FIELDS

    @classmethod
    def _constant_filter(cls) -> QueryFilterType | None:
        return _simple_filter("vulnerability_relevance", "in", ["Confirmed", "Potentially Relevant"])

    def _get_data(self) -> list:
        return self._client.force_get_all_device_vulnerability_relations(
            fields=self._fields,
            filter_by=self._filter_by,
            sort_by=self._sort_by,
            stop_after=self._limit if self._raw_args.get("limit") is not None else None,
            start_from=self._offset if self._raw_args.get("offset") is not None else None,
        )

    def _generate_results(self, raw_response: list | dict) -> CommandResults:
        device_vulnerability_pairs = raw_response
        outputs = {
            "XDome.DeviceVulnerability(val.device_uid == obj.device_uid "
            "&& val.vulnerability_id == obj.vulnerability_id)": device_vulnerability_pairs
        }
        human_readable_output = tableToMarkdown('xDome device-vulnerability-pairs List', device_vulnerability_pairs)
        return CommandResults(
            outputs_prefix="XDome.DeviceVulnerability",
            outputs=outputs,
            readable_output=human_readable_output,
            raw_response=raw_response,
        )


def get_device_alert_relations_command(client: Client, args: dict) -> CommandResults:
    cmd = XDomeGetDeviceAlertRelationsCommand(
        client=client,
        fields=args.get("fields"),
        filter_by=args.get("filter_by"),
        offset=args.get("offset"),
        limit=args.get("limit"),
        sort_by=args.get("sort_by"),
    )
    return cmd.execute()


def get_device_vulnerability_relations_command(client: Client, args: dict) -> CommandResults:
    cmd = XDomeGetDeviceVulnerabilityRelationsCommand(
        client=client,
        fields=args.get("fields"),
        filter_by=args.get("filter_by"),
        sort_by=args.get("sort_by"),
        offset=args.get("offset"),
        limit=args.get("limit"),
    )
    return cmd.execute()


def set_device_alert_relations_command(client: Client, args: dict) -> CommandResults:
    alert_id = int(args["alert_id"])
    device_uids = args.get("device_uids")
    if device_uids:
        device_uids = [field.strip() for field in device_uids.split(",")]
    status = args["status"]

    res = client.set_device_single_alert_relations(alert_id, device_uids, status)
    if res and "details" in res:
        return CommandResults(readable_output=res["details"][0].get("msg"), raw_response=res)
    return CommandResults(readable_output="success", raw_response="success")


def fetch_incidents(
    client: Client,
    last_run: dict,
    initial_fetch_time: str,
    fetch_limit: int,
    alert_types: list[str] | None,
    fetch_only_unresolved: bool,
):
    """This function will execute each interval (default is 1 minute)"""
    start_time = last_run.get("last_fetch", initial_fetch_time)
    start_time = _format_date(start_time)
    latest_ids = last_run.get("latest_ids", [])

    only_unresolved_filter = (
        _simple_filter("device_alert_status", "in", ["Unresolved"]) if fetch_only_unresolved else None
    )
    alert_types_filter = _build_alert_types_filter(alert_types) if alert_types else None
    if latest_ids:
        last_run_alert_id_device_uid_pairs = [_split_device_alert_relation_id(dar_id) for dar_id in latest_ids]
        not_in_last_fetched_ids_filter = _and(*(
            _or(
                _simple_filter("alert_id", "not_in", [alert_id]),
                _simple_filter("device_uid", "not_in", [device_uid]),
            )
            for alert_id, device_uid in last_run_alert_id_device_uid_pairs
        ))
        # should be the 'not_equals' or the 'greater' operation, but they're currently not working.
        # not_last_fetched_time_filter = _simple_filter(INCIDENT_TIMESTAMP_FIELD, "not_equals", start_time)
        # patch: use the 'greater_or_equal' operation on value 'Time + 1s'
        not_last_fetched_time_filter = _simple_filter(INCIDENT_TIMESTAMP_FIELD, "greater_or_equal", _next_tick(start_time))
        no_last_run_dups_filter = _or(not_in_last_fetched_ids_filter, not_last_fetched_time_filter)
    else:
        no_last_run_dups_filter = None

    start_time_filter = _simple_filter(INCIDENT_TIMESTAMP_FIELD, "greater_or_equal", start_time)
    sort_by_update_time = [_ascending(INCIDENT_TIMESTAMP_FIELD)]

    try:
        device_alert_relations = client.force_get_all_device_alert_relations(
            fields=DEVICE_ALERT_FIELDS,
            filter_by=_and(
                XDomeGetDeviceAlertRelationsCommand.exclude_retired_filter(),
                only_unresolved_filter,
                alert_types_filter,
                no_last_run_dups_filter,
                start_time_filter,
            ),
            sort_by=sort_by_update_time,
            stop_after=fetch_limit,
        )
    except DemistoException as e:
        demisto.error(f"An error occurred while fetching xDome incidents:\n{str(e)}")
        return last_run, []

    for dar in device_alert_relations:
        dar[INCIDENT_TIMESTAMP_FIELD] = _format_date(dar[INCIDENT_TIMESTAMP_FIELD])

    incidents = [_device_alert_relation_to_incident(dar) for dar in device_alert_relations]

    if incidents:
        next_start_time = device_alert_relations[-1][INCIDENT_TIMESTAMP_FIELD]
        next_latest_ids = [
            _device_alert_relation_id_str(dar) for dar in device_alert_relations
            if dar[INCIDENT_TIMESTAMP_FIELD] == next_start_time
        ]
        if next_start_time == start_time:
            # start_time == next_start_time which means that all the incidents that were fetched have the same
            # update_time. So I want to keep the current 'latest_ids' for the next run (& extend them with the new IDs)
            # instead of overriding them. By doing so I make sure we don't fetch those incidents again next run.
            next_latest_ids = latest_ids + next_latest_ids
    else:
        next_start_time = _next_tick(start_time)
        next_latest_ids = []

    next_run = {"last_fetch": next_start_time, "latest_ids": next_latest_ids}
    return next_run, incidents


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()

    api_key = params.get('credentials', {}).get('password')

    # get the service API url
    base_url = urljoin(params['url'], '/api/v1')

    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {command}')
    try:
        headers: dict = {"Authorization": f"Bearer {api_key}"}

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
        )

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif command == 'xdome-get-device-alert-relations':
            return_results(get_device_alert_relations_command(client, args))

        elif command == 'xdome-get-device-vulnerability-relations':
            return_results(get_device_vulnerability_relations_command(client, args))

        elif command == 'xdome-set-status-for-device-alert-relations':
            return_results(set_device_alert_relations_command(client, args))

        elif command == 'fetch-incidents':
            initial_fetch_time = params.get('first_fetch').strip()
            fetch_limit = params.get('max_fetch')
            fetch_limit = int(fetch_limit) if fetch_limit is not None else DEFAULT_FETCH_LIMIT
            fetch_limit = min(fetch_limit, MAX_FETCH_LIMIT)
            alert_types = params.get('alert_types')
            fetch_only_unresolved = params.get('fetch_only_unresolved')
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                initial_fetch_time=initial_fetch_time,
                fetch_limit=fetch_limit,
                alert_types=alert_types,
                fetch_only_unresolved=fetch_only_unresolved,
            )

            demisto.setLastRun(next_run)
            demisto.incidents(incidents or [])

        else:
            raise Exception('Unrecognized command: ' + command)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
