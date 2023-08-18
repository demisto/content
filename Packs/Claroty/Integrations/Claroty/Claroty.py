import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
""" IMPORTS """
from distutils.util import strtobool
from typing import List, Tuple, Dict, Any, Union
import json
import requests
import dateparser
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


class Filter():
    def __init__(self, filter: str, value: Any, lookup: str = "exact"):
        self.filter = filter
        self.value = value
        self.lookup = lookup

    def build_filter(self):
        return f"{self.filter}__{self.lookup}={self.value}"


''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
DEFAULT_HEADERS = {'content-type': 'application/json'}
CTD_TO_DEMISTO_SEVERITY = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4
}
ALERT_CTD_FIELD_TO_DEMISTO_FIELD = {
    'resource_id': "ResourceID",
    'type': "AlertTypeID",
    'type__': "AlertType",
    'severity__': "Severity",
    'network_id': "NetworkID",
    'resolved': "Resolved",
    'description': "Description",
    'actionable_assets': "RelatedAssets",
    'alert_indicators': "Indicator",
    'category__': "Category",
    'timestamp': "Timestamp"
}
ASSET_CTD_FIELD_TO_DEMISTO_FIELD = {
    'id': "AssetID",
    'name': "Name",
    'insight_names': "InsightName",
    'vendor': "Vendor",
    "criticality__": "Criticality",
    'asset_type__': "AssetType",
    "last_seen": "LastSeen",
    "ipv4": "IP",
    "mac": "MAC",
    'virtual_zone_name': "VirtualZone",
    "class_type": "ClassType",
    'site_name': "SiteName",
    "project_parsed": "WasParsed",
    "risk_level": "RiskLevel",
    "firmware": "FirmwareVersion",
    "resource_id": "ResourceID",
    "site_id": "SiteID",
    "insights": "Insights"
}
RESOLVE_STRING_TO_TYPE = {
    "resolve": 1,
    "archive": 2
}
DEFAULT_ALERT_FIELD_LIST = ["resource_id", "type", "severity", "network_id", "resolved", "description",
                            "alert_indicators", "actionable_assets", "category"]
DEFAULT_ASSET_FIELD_LIST = ["id", "name", "insight_names", "vendor", "criticality", "asset_type", "last_seen", "ipv4",
                            "mac", "virtual_zone_name", "class_type", "site_name", "site_id", "project_parsed",
                            "risk_level", "firmware", "resource_id"]
WINDOWS_CVE_BASE_URL = "ranger/insight_details/Windows%20CVEs?&format=asset_page&sort=-Score%20(CVSS)" \
                       "&per_page=1000&page=1&id__exact="
FULL_MATCH_BASE_URL = "ranger/insight_details/Full%20Match%20CVEs?&format=asset_page&sort=-Score%20(CVSS)" \
                      "&per_page=1000&page=1&id__exact="
DEFAULT_RESOLVE_ALERT_COMMENT = "Resolved by Demisto"
# MAX_ASSET_LIMIT = 75
# MAX_ALERT_LIMIT = 75
MAX_PER_PAGE = 200
DEFAULT_PER_PAGE = 10
DEFAULT_ALERTS_FILTERS = [Filter("is_qualified", "true", "exact")]
DEFAUL_ASSETS_FILTERS = [Filter("valid", "true", "exact"), Filter("approved", "true", "exact"), Filter("ghost", "false", "exact")]


class Client(BaseClient):
    def __init__(self, **kwargs):
        self._credentials = kwargs.pop("credentials", (None, None))
        super().__init__(**kwargs)
        self._headers = DEFAULT_HEADERS
        self._generate_token()
        self._list_to_filters: dict = {'alerts': [], 'assets': []}

    def _request_with_token(self, url_suffix: str, method: str = "GET", data=None):
        try:
            return self._http_request(method, url_suffix=url_suffix, data=data)
        except DemistoException:
            demisto.setIntegrationContext({'jwt_token': None})
            self._headers.pop('Authorization', None)
            # assuming it was just the token that expired, retrying to send the request with the new token
            self._generate_token()

            return self._http_request(method, url_suffix=url_suffix, data=data)

    def _generate_token(self):
        if not demisto.getIntegrationContext().get("jwt_token"):
            res = self._http_request(
                'POST',
                url_suffix="auth/authenticate",
                data=json.dumps({"username": self._credentials[0], "password": self._credentials[1]}),
            )

            if res.get('password_expired', None):
                raise DemistoException("Password expired, please update credentials")

            demisto.setIntegrationContext({'jwt_token': res['token']})
            self._headers['Authorization'] = demisto.getIntegrationContext()['jwt_token']
            return self._headers['Authorization']
        else:
            return demisto.getIntegrationContext()

    def list_incidents(self, fields: list, sort_by: dict, fetch_from_date: str, page_number: int,
                       **extra_filters) -> dict:
        extra_filters_list = [Filter("timestamp", fetch_from_date, "gte")]
        extra_filters_list += DEFAULT_ALERTS_FILTERS

        for extra_filter in extra_filters:
            if extra_filter == "severity":
                extra_filters_list.append(Filter(extra_filter, extra_filters[extra_filter], "gte"))
            else:
                extra_filters_list.append(Filter(extra_filter, extra_filters[extra_filter]))

        if bool(demisto.params().get("exclude_resolved_alerts", False)):
            extra_filters_list = _add_exclude_resolved_alerts_filters(extra_filters_list)

        return self.get_alerts(fields=fields, sort_by=sort_by, filters=extra_filters_list, page_number=page_number)

    def get_assets(self, fields: list, sort_by: dict, filters: list, limit: int = 10):
        url_suffix = self._add_extra_params_to_url('ranger/assets', fields, sort_by, filters, limit)
        return self._request_with_token(url_suffix, 'GET')

    def get_alerts(self, fields: list, sort_by: dict, filters: list, limit: int = 10, page_number: int = 1):
        url_suffix = self._add_extra_params_to_url('ranger/alerts', fields, sort_by, filters, limit, page_number)
        return self._request_with_token(url_suffix, 'GET')

    def get_alert(self, rid: str) -> Union[Dict, str, requests.Response]:
        return self._request_with_token(f'ranger/alerts/{rid}', 'GET')

    def get_ranger_table_filters(self, table: str) -> dict:
        if not self._list_to_filters[table]:
            self._list_to_filters[table] = self._request_with_token(f'ranger/{table}/filters', 'GET')['filters']
        return self._list_to_filters[table]

    def resolve_alert(self, selected_alerts: list, filters: dict, resolve_type: int, resolve_comment: str):
        return self._request_with_token(
            'ranger/ranger_api/resolve_alerts',
            'POST',
            data=json.dumps({
                "selection_params": {
                    "select_all": False,
                    "selected": selected_alerts,
                    "excluded": [],
                    "filters": filters
                },
                "resolved_as": resolve_type,
                "comment": resolve_comment
            })
        )

    @staticmethod
    def _add_extra_params_to_url(url_suffix: str, fields: list, sort_by: dict, filters: List[Filter], limit: int = 10,
                                 page_number: int = 1) -> str:
        url_suffix += "?fields=" + ',;$'.join(fields)
        url_suffix += f"&page={page_number}&per_page={limit}"

        if sort_by:
            url_suffix += f"&sort={sort_by['order']}{sort_by['field']}"

        for query_filter in filters:
            url_suffix += f"&{query_filter.build_filter()}"
        return url_suffix

    def enrich_asset_results(self, assets: dict) -> dict:
        for asset in assets['objects']:
            full_match_cves = self._request_with_token(f"{FULL_MATCH_BASE_URL}{asset['resource_id']}", 'GET')
            windows_cves = self._request_with_token(f"{WINDOWS_CVE_BASE_URL}{asset['resource_id']}", 'GET')
            assets_cves = [*full_match_cves["rows"], *windows_cves["rows"]]
            asset["insights"] = [{"CVE-ID": cve["cells"][0], "Score": cve["cells"][1], "Description": cve["cells"][2],
                                 "Published": cve["cells"][3], "Modified": cve["cells"][4]} for cve in assets_cves]
        return assets


def test_module(client: Client):
    authentication_result = client._generate_token()
    if not authentication_result.get("jwt_token", False):
        return f'Token getter failed, adding result - {authentication_result}'

    query_alerts_result = client.get_alerts(DEFAULT_ALERT_FIELD_LIST, get_sort("timestamp"), [], limit=1)
    if query_alerts_result.get("count_total", "Failed") == "Failed":
        return f"Failed getting alerts, json result - {query_alerts_result}"

    return 'ok'


def get_assets_command(client: Client, args: dict) -> Tuple:
    relevant_fields, sort_by, limit = _init_request_values("asset", "id", "asset_limit", args)
    filters = []

    filters += DEFAUL_ASSETS_FILTERS

    criticality_str = args.get("criticality", None)
    criticality_int = CTD_TO_DEMISTO_SEVERITY.get(criticality_str, None)
    if criticality_int:
        filters.append(Filter("criticality", criticality_int - 1))

    insight_name = args.get("insight_name", None)
    if insight_name:
        filters.extend([Filter("insight_name", insight_name), Filter("insight_status", 0)])

    assets_last_seen = args.get("assets_last_seen", None)
    if assets_last_seen:
        filters.append(Filter("last_seen", assets_last_seen, "gte"))

    site_id = demisto.params().get("site_id", None)
    if site_id:
        filters.append(Filter("site_id", site_id, "exact"))

    result = client.get_assets(relevant_fields, sort_by, filters, limit)

    should_enrich_assets = strtobool(args.get("should_enrich_assets", "False"))
    if should_enrich_assets:
        result = client.enrich_asset_results(result)
        relevant_fields.append("insights")

    parsed_results_assets, parsed_cves = _parse_assets_result(result, relevant_fields)
    outputs = {
        'Claroty.Asset(val.AssetID == obj.AssetID)': parsed_results_assets
    }

    if parsed_cves and len(parsed_cves) > 0:
        outputs['CVE(val.ID == obj.ID)'] = parsed_cves

    readable_output = tableToMarkdown('Claroty Asset List', parsed_results_assets)
    return (
        readable_output,
        outputs,
        result
    )


def resolve_alert_command(client: Client, args: dict) -> Tuple:
    bad_input = False
    selected_alerts_arg = args.get("selected_alerts", [])
    selected_alert_list = selected_alerts_arg.split(",") \
        if isinstance(selected_alerts_arg, str) else selected_alerts_arg
    for alert in selected_alert_list:
        split_alert = alert.split("-")
        if len(split_alert) != 2 or not split_alert[0].isnumeric() or not split_alert[1].isnumeric():
            bad_input = True

    resolve_type = RESOLVE_STRING_TO_TYPE[args.get("resolve_as", "resolve")]

    resolve_comment = args.get("resolve_comment", DEFAULT_RESOLVE_ALERT_COMMENT)

    if not bad_input:
        result = client.resolve_alert(selected_alert_list, args.get("filters", {}), resolve_type, resolve_comment)

        outputs = {
            "Claroty.Resolve_out": result
        }
        if result['success']:
            readable_output = "## Alert was resolved successfully"
        else:
            readable_output = "## Alert was not resolved"
    else:
        result = {}
        outputs = {}
        readable_output = "## Bad input"

    return (
        readable_output,
        outputs,
        result
    )


def get_single_alert_command(client: Client, args: dict) -> Tuple:
    relevant_fields = get_fields("alert", args.get("fields", "").split(","))
    alert_rid = args.get("alert_rid", None)
    result = client.get_alert(alert_rid)
    parsed_results = _parse_single_alert(result, relevant_fields)

    outputs = {
        'Claroty.Alert(val.ResourceID == obj.ResourceID)': parsed_results
    }
    readable_output = tableToMarkdown('Claroty Alert List', parsed_results)
    return (
        readable_output,
        outputs,
        result
    )


def query_alerts_command(client: Client, args: dict) -> Tuple:
    relevant_fields, sort_by, limit = _init_request_values("alert", "timestamp", "alert_limit", args, True)
    filters = []

    filters += DEFAULT_ALERTS_FILTERS
    alert_type = args.get("type", "").lower().replace(" ", "")
    alert_type_exists = False
    if alert_type:
        alert_filters = client.get_ranger_table_filters('alerts')
        filters_url_suffix = transform_filters_labels_to_values(alert_filters, "type", alert_type)
        if filters_url_suffix:
            for filter_type in filters_url_suffix:
                filters.append(Filter(filter_type[0], filter_type[1]))
                alert_type_exists = True

    alert_time = args.get("date_from", None)
    if alert_time:
        filters.append(Filter("timestamp", alert_time, "gte"))

    alert_severity = args.get("minimal_severity", None)
    if alert_severity:
        filters.append(Filter("severity", get_severity_filter(alert_severity), "gte"))

    if strtobool(args.get("exclude_resolved_alerts", "False")):
        filters = _add_exclude_resolved_alerts_filters(filters)

    site_id = demisto.params().get("site_id", None)
    if site_id:
        filters.append(Filter("site_id", site_id, "exact"))

    if bool(alert_type) == alert_type_exists:
        result = client.get_alerts(relevant_fields, sort_by, filters, limit)
        parsed_results = _parse_alerts_result(result, relevant_fields)
    else:
        result = {}
        parsed_results = []

    outputs = {
        'Claroty.Alert(val.ResourceID == obj.ResourceID)': parsed_results
    }
    readable_output = tableToMarkdown('Claroty Alert List', parsed_results)
    return (
        readable_output,
        outputs,
        result
    )


def _add_exclude_resolved_alerts_filters(filters: List[Filter]):
    if not filters:
        return [Filter("resolved", "false", "exact")]

    filters += [Filter("resolved", "false", "exact")]
    return filters


def _init_request_values(obj_name: str, sort_by_default_value: str, limit_arg: str, args: dict,
                         get_sort_order_arg: bool = False) -> Tuple[List, Dict, int]:
    relevant_fields = get_fields(obj_name, args.get("fields", "").split(","))

    sort_order = False
    if get_sort_order_arg:
        sort_order = get_sort_order(args.get("sort_order", "asc"))

    sort_by = get_sort(args.get("sort_by", sort_by_default_value), sort_order)
    limit = demisto.params().get("per_page", str(DEFAULT_PER_PAGE)) or args.get(limit_arg, str(DEFAULT_PER_PAGE))

    if limit.isdigit() and int(limit) <= MAX_PER_PAGE:
        limit = int(limit)
    else:
        limit = DEFAULT_PER_PAGE

    return relevant_fields, sort_by, limit


def _parse_alerts_result(alert_result: dict, fields: list) -> List[dict]:
    if 'objects' not in alert_result:
        return []
    obj = alert_result.get('objects', [])
    alerts = []

    for obj_fields in obj:
        alert = _parse_single_alert(obj_fields, fields)
        alerts.append(alert)
    return alerts


def _parse_single_alert(alert_obj, fields: list):
    parsed_alert_result = {}
    if alert_obj:
        for field in fields:
            if field == "type":
                parsed_alert_result[ALERT_CTD_FIELD_TO_DEMISTO_FIELD[field]] = alert_obj.get(field)
                alert_type_value = alert_obj.get("type__", [])
                parsed_alert_result[ALERT_CTD_FIELD_TO_DEMISTO_FIELD["type__"]] = alert_type_value[1:] \
                    if alert_type_value else None

            elif field == "alert_indicators":
                indicator_str_result = ""
                for indicator in alert_obj.get(field, []):
                    indicator_str_result += f"Alert ID - {indicator['alert_id']}\r\n"
                    indicator_str_result += f"Description - {indicator['indicator_info']['description']}\r\n"
                    indicator_str_result += f"Points - {indicator['indicator_info']['points']}\r\n\n"
                parsed_alert_result[ALERT_CTD_FIELD_TO_DEMISTO_FIELD[field]] = indicator_str_result

            elif field == "severity":
                alert_severity_value = alert_obj.get("severity__")
                parsed_alert_result[ALERT_CTD_FIELD_TO_DEMISTO_FIELD["severity__"]] = alert_severity_value[1:]\
                    if alert_severity_value else None

            elif field == "category":
                alert_category_value = alert_obj.get("category__")
                parsed_alert_result[ALERT_CTD_FIELD_TO_DEMISTO_FIELD["category__"]] = alert_category_value[1:]\
                    if alert_category_value else None

            elif field == "actionable_assets":
                assets = alert_obj.get(field, [])
                parsed_assets = []

                for asset in assets:
                    parsed_assets.append(_parse_single_asset(asset["asset"], DEFAULT_ASSET_FIELD_LIST))
                parsed_alert_result[ALERT_CTD_FIELD_TO_DEMISTO_FIELD[field]] = parsed_assets
            else:
                parsed_alert_result[ALERT_CTD_FIELD_TO_DEMISTO_FIELD[field]] = alert_obj.get(field)

    return parsed_alert_result


def _parse_assets_result(assets_result: dict, fields: list) -> Tuple:
    if 'objects' not in assets_result:
        return [], []
    obj = assets_result.get('objects', [])
    assets = []
    cves = []

    for obj_fields in obj:
        asset = _parse_single_asset(obj_fields, fields)
        assets.append(asset)
        if asset.get("CVE", None):
            cves.append(asset.get("CVE"))
    return assets, cves


def _parse_single_asset(asset_obj: dict, fields: list) -> dict:
    parsed_asset_result = {}
    if asset_obj:
        for field in fields:
            if field == "asset_type":
                asset_type_value = asset_obj.get("asset_type__")
                parsed_asset_result[ASSET_CTD_FIELD_TO_DEMISTO_FIELD["asset_type__"]] = asset_type_value[1:] \
                    if asset_type_value else None

            elif field == "criticality":
                asset_criticality_value = asset_obj.get("criticality__")
                parsed_asset_result[ASSET_CTD_FIELD_TO_DEMISTO_FIELD["criticality__"]] = asset_criticality_value[1:]\
                    if asset_criticality_value else None

            elif field == "insights":
                cves = []
                highest_cve_score = 0.0
                for insight in asset_obj.get(field, []):
                    cve = {
                        'ID': insight['CVE-ID'],
                        'CVSS': insight['Score'],
                        'Published': insight['Published'],
                        'Modified': insight['Modified'],
                        'Description': insight['Description'],
                    }
                    if float(insight['Score']) > highest_cve_score:
                        highest_cve_score = float(insight['Score'])
                    cves.append(cve)
                parsed_asset_result['CVE'] = cves
                parsed_asset_result['HighestCVEScore'] = highest_cve_score

            else:
                parsed_asset_result[ASSET_CTD_FIELD_TO_DEMISTO_FIELD[field]] = asset_obj.get(field)

    return parsed_asset_result


def get_sort(field_to_sort_by: str, order_by_desc: bool = False) -> dict:
    order_by_direction = "-" if order_by_desc else ""
    return {"field": field_to_sort_by, "order": order_by_direction}


def get_sort_order(sort_order: str) -> bool:
    return False if sort_order == "asc" else True


def get_fields(obj_name: str, fields: List[str]) -> list:
    if obj_name == "alert":
        fields.append("resource_id")
        if "all" in fields:
            fields.pop(fields.index("all"))
            fields.extend(DEFAULT_ALERT_FIELD_LIST)

    elif obj_name == "asset":
        fields.extend(["id", "resource_id", "site_id"])
        if "all" in fields:
            fields.pop(fields.index("all"))
            fields.extend(DEFAULT_ASSET_FIELD_LIST)

    fields = set(fields)
    return list(fields)


def add_filter(filter_name: str, filter_value: Any, filter_operation: str = "exact"):
    return {
        "field": filter_name,
        "value": filter_value,
        "operator": filter_operation,
    }


def transform_filters_labels_to_values(table_filters, filter_name: str, filter_val: str):
    chosen_filters = []
    for table_filter in table_filters:
        if table_filter['name'].lower() == filter_name:
            table_filter_value = next((table_filter_value['value'] for table_filter_value in table_filter['values']
                                      if filter_val == table_filter_value['label'].lower().replace(" ", "")), None)
            if table_filter_value:
                chosen_filters.append((table_filter['name'], table_filter_value))

    return chosen_filters


def get_severity_filter(severity: str) -> str:
    severity_values = []
    for severity_key, severity_value in CTD_TO_DEMISTO_SEVERITY.items():
        if severity_value >= CTD_TO_DEMISTO_SEVERITY.get(severity, 0):
            severity_values.append(str(severity_value))
    return ",;$".join(severity_values)


def get_list_incidents(client: Client, latest_created_time: str, page_number: int):
    field_list = DEFAULT_ALERT_FIELD_LIST + ["timestamp"]
    extra_filters = {}

    severity = demisto.params().get("severity", None)
    if severity:
        extra_filters["severity"] = get_severity_filter("".join(severity))

    site_id = demisto.params().get("site_id", None)
    if site_id:
        extra_filters["site_id"] = site_id

    alert_type = demisto.params().get("alert_type", None)
    alert_type_exists = False
    if alert_type:
        alert_filters = client.get_ranger_table_filters('alerts')
        filters_url_suffix = transform_filters_labels_to_values(alert_filters, "type",
                                                                alert_type.lower().replace(" ", ""))
        if filters_url_suffix:
            for filter_type in filters_url_suffix:
                extra_filters["type"] = filter_type[1]
                alert_type_exists = True

    if bool(alert_type) == alert_type_exists:
        response = client.list_incidents(field_list, get_sort("timestamp"), latest_created_time, page_number,
                                         **extra_filters)
    else:
        response = {}

    return response, field_list


def fetch_incidents(client: Client, last_run, first_fetch_time):
    """
    This function will execute each interval (default is 1 minute).
    """
    last_fetch = last_run.get('last_fetch', None)
    last_run_rids = last_run.get('last_run_rids', {})
    page_to_query = last_run.get('page_to_query', 1)

    if not last_fetch:
        last_fetch, _ = parse_date_range(first_fetch_time, date_format=DATE_FORMAT, utc=True)

    current_rids = []
    incidents = []
    response, field_list = get_list_incidents(client, last_fetch, page_to_query)
    items = _parse_alerts_result(response, field_list)

    # Check last queried item's timestamp
    latest_created_time = None
    if items:
        parsed_date = dateparser.parse(items[-1]['Timestamp'])
        assert parsed_date is not None, f"failed parsing {items[-1]['Timestamp']}"
        latest_created_time = parsed_date.replace(tzinfo=None).strftime(DATE_FORMAT)

    # If timestamp stayed the same than get next 10
    if last_fetch == latest_created_time:
        page_to_query += 1
    else:
        page_to_query = 1

    for item in items:
        # Make datetime object unaware of timezone for comparison
        parsed_date = dateparser.parse(item['Timestamp'])
        assert parsed_date is not None, f"failed parsing {item['Timestamp']}"
        incident_created_time = parsed_date.replace(tzinfo=None)

        # Don't add duplicated incidents
        # if item["ResourceID"] not in last_run_rids:
        incident = {
            'name': item.get('Description', None),
            'occurred': incident_created_time.strftime(DATE_FORMAT),
            'severity': CTD_TO_DEMISTO_SEVERITY.get(item.get('Severity', None), None),
            'rawJSON': json.dumps(item)
        }

        incidents.append(incident)
        current_rids.append(item["ResourceID"])

    # If there were no items queried, latest_created_time is the same as last run
    if latest_created_time is None:
        latest_created_time = last_fetch

    # If no new items were retrieved, last_run_rids stay the same
    if not current_rids:
        current_rids = last_run_rids

    next_run = {'last_fetch': latest_created_time, 'last_run_rids': current_rids, "page_to_query": page_to_query}
    return next_run, incidents


def main():
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')

    base_url = demisto.params()['url'].rstrip('/')

    verify_certificate = not demisto.params().get('insecure', True)

    first_fetch_time = demisto.params().get('fetch_time', '7 days').strip()

    proxy = demisto.params().get('proxy', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            credentials=(username, password),
            proxy=proxy,
        )

        if demisto.command() == 'test-module':
            result = test_module(client)
            demisto.results(result)

        elif demisto.command() == 'claroty-get-assets':
            return_outputs(*get_assets_command(client, demisto.args()))

        elif demisto.command() == 'claroty-query-alerts':
            return_outputs(*query_alerts_command(client, demisto.args()))

        elif demisto.command() == 'claroty-get-single-alert':
            return_outputs(*get_single_alert_command(client, demisto.args()))

        elif demisto.command() == 'claroty-resolve-alert':
            return_outputs(*resolve_alert_command(client, demisto.args()))

        elif demisto.command() == 'fetch-incidents':
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time)

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
