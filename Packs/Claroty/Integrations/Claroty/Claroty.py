import demistomock as demisto
from CommonServerPython import *

""" IMPORTS """
from typing import List
import json
import requests
import dateparser

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
DEFAULT_HEADERS = {'content-type': 'application/json'}
CTD_TO_DEMISTO_SEVERITY = {
    None: None,
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
                            "alert_indicators", "actionable_assets"]
DEFAULT_ASSET_FIELD_LIST = ["id", "name", "insight_names", "vendor", "criticality", "asset_type", "last_seen", "ipv4",
                            "mac", "virtual_zone_name", "class_type", "site_name", "site_id", "project_parsed",
                            "risk_level", "firmware", "resource_id"]
FULL_MATCH_BASE_URL = "ranger/insight_details/Windows%20CVEs?&format=asset_page&sort=-Score%20(CVSS)" \
                      "&per_page=1000&page=1&id__exact="
WINDOWS_CVE_BASE_URL = "ranger/insight_details/Full%20Match%20CVEs?&format=asset_page&sort=-Score%20(CVSS)" \
                       "&per_page=1000&page=1&id__exact="
DEFAULT_RESOLVE_ALERT_COMMENT = "Resolved by Demisto"


class Client(BaseClient):
    def __init__(self, **kwargs):
        self._credentials = kwargs.pop("credentials", (None, None))
        not_mock = kwargs.pop("not_mock", True)
        super().__init__(**kwargs)
        self._headers = DEFAULT_HEADERS
        if not_mock:
            self._headers['Authorization'] = self.get_token()
        else:
            self._headers['Authorization'] = "ok"

        self._list_to_filters: dict = {'alerts': [], 'assets': []}

    def jwt(self):
        # TODO: Get jwt - make as wrapper -
        # try and except the requests we are making. If failed on specific return code then retry after getting token

        # once you get the jwt you can store it for later use using something like:
        # demisto.setIntegrationContext({'jwt': jwt, 'expiration': 'whatever'})

        # before you try to get a new jtw, you can check if the one you stored is still valid.
        # to retrieve it, you can do
        # demisto.getIntegrationContext() that will return the dict that you stored previously
        pass

    def get_token(self):
        return self._http_request(
            'POST',
            url_suffix="auth/authenticate",
            data=json.dumps({"username": self._credentials[0], "password": self._credentials[1]}),
        )["token"]

    def list_incidents(self, fields: list, fetch_from: datetime, **extra_filters) -> dict:
        extra_filters_list = [add_filter("timestamp", fetch_from, "gte")]
        for extra_filter in extra_filters:
            if extra_filter == "severity":
                extra_filters_list.append(add_filter(extra_filter, extra_filters[extra_filter], "gte"))
            else:
                extra_filters_list.append(add_filter(extra_filter, extra_filters[extra_filter]))
        return self.get_alerts(fields=fields, sort={}, filters=extra_filters_list)

    def get_assets(self, fields: list, sort: dict, filters: list):
        url_suffix = self._add_extra_params_to_url('ranger/assets', fields, sort, filters)
        # TODO: check whether we want to add this or not (not urgent)
        # return self._http_request('GET', url_suffix=url_suffix + '&ghost__exact=false&special_hint__exact=0,;$9')
        return self._http_request('GET', url_suffix=url_suffix)

    def get_alerts(self, fields: list, sort: dict, filters: list):
        url_suffix = self._add_extra_params_to_url('ranger/alerts', fields, sort, filters)
        return self._http_request('GET', url_suffix=url_suffix)

    def get_alert(self, rid: str):
        return self._http_request('GET', url_suffix=f'ranger/alerts/{rid}')

    def get_ranger_table_filters(self, table: str):
        if not self._list_to_filters[table]:
            self._list_to_filters[table] = self._http_request('GET', url_suffix=f'ranger/{table}/filters')['filters']
        return self._list_to_filters[table]

    def resolve_alert(self, selected_alerts: list, filters: dict, resolve_type: int, resolve_comment: str):
        return self._http_request(
            'POST',
            url_suffix='ranger/ranger_api/resolve_alerts',
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
    def _add_extra_params_to_url(url_suffix: str, fields: list, sort: dict, filters: list):
        url_suffix += "?fields=" + ',;$'.join(fields)

        if sort:
            url_suffix += f"&sort={sort['order']}{sort['field']}"

        for query_filter in filters:
            url_suffix += f"&{query_filter['field']}__{query_filter['operator']}={query_filter['value']}"
        return url_suffix

    def enrich_asset_results(self, assets):
        for asset in assets['objects']:
            full_match_cves = self._http_request('GET', url_suffix=f"{FULL_MATCH_BASE_URL}{asset['resource_id']}")
            windows_cves = self._http_request('GET', url_suffix=f"{WINDOWS_CVE_BASE_URL}{asset['resource_id']}")
            assets_cves = [*full_match_cves["rows"], *windows_cves["rows"]]
            asset["insights"] = [{"CVE-ID": cve["cells"][0], "Score": cve["cells"][1], "Description": cve["cells"][2]}
                                 for cve in assets_cves]
        return assets


def test_module(client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: HelloWorld client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    result = client.say_hello('DBot')
    if 'Hello DBot' == result:
        return 'ok'
    else:
        return 'Test failed because ......'


def get_assets_command(client, args):
    # TODO: Aesthetics - create def init_get_values(filters) to populate fields, sort, filters
    fields = get_fields("asset")
    sort = get_sort(demisto.args().get("sort_by", "id"))
    filters = []

    criticality_str = demisto.args().get("criticality", None)
    criticality_int = CTD_TO_DEMISTO_SEVERITY[criticality_str]
    if criticality_int:
        filters.append(add_filter("criticality", criticality_int - 1))

    insight_name = demisto.args().get("insight_name")
    if insight_name:
        filters.extend([add_filter("insight_name", insight_name), add_filter("insight_status", 0)])

    result = client.get_assets(fields, sort, filters)

    should_enrich_assets = str_to_bool(demisto.args().get("should_enrich_assets", "False"))
    if should_enrich_assets:
        result = client.enrich_asset_results(result)
        fields.append("insights")

    parsed_results = _parse_assets_result(result, fields)

    outputs = {
        'Claroty.Asset(val.AssetID == obj.AssetID)': parsed_results
    }
    readable_output = tableToMarkdown('Claroty Asset List', parsed_results)
    return (
        readable_output,
        outputs,
        result
    )


def resolve_alert_command(client, args):
    selected_alerts_arg = demisto.args().get("selected_alerts", [])
    selected_alert_list = selected_alerts_arg.split(",") \
        if isinstance(selected_alerts_arg, str) else selected_alerts_arg

    resolve_type = RESOLVE_STRING_TO_TYPE[demisto.args().get("resolve_as", "resolve")]

    resolve_comment = demisto.args().get("resolve_comment", DEFAULT_RESOLVE_ALERT_COMMENT)

    result = client.resolve_alert(selected_alert_list, demisto.args().get("filters", {}), resolve_type, resolve_comment)

    outputs = {
        "Claroty.Resolve_out": result
    }
    readable_output = f"## Resolve alert status - {result['success']}"

    return (
        readable_output,
        outputs,
        result
    )


def get_single_alert_command(client, args):
    fields = get_fields("alert")
    alert_rid = demisto.args().get("get_single_alert", None)
    result = client.get_alert(alert_rid)
    parsed_results = _parse_single_alert(result, fields)

    outputs = {
        'Claroty.Alert(val.ResourceID == obj.ResourceID)': parsed_results
    }
    readable_output = tableToMarkdown('Claroty Alert List', parsed_results)
    return (
        readable_output,
        outputs,
        result
    )


def query_alerts_command(client, args):
    fields = get_fields("alert")
    sort_order = get_sort_order(demisto.args().get("sort_order", "asc"))
    sort = get_sort(demisto.args().get("sort_by", "timestamp"), sort_order)
    filters = []

    alert_type = demisto.args().get("type", "").lower()
    if alert_type:
        alert_filters = client.get_ranger_table_filters('alerts')
        # TODO: fix around the way i return values
        filters_url_suffix = transform_filters_labels_to_values(alert_filters, "type", alert_type)
        if filters_url_suffix:
            for filter_type in filters_url_suffix:
                filters.append(add_filter(filter_type[0], filter_type[1]))

    alert_time = demisto.args().get("date_from", None)
    if alert_time:
        filters.append(add_filter("timestamp", alert_time, "gte"))

    result = client.get_alerts(fields, sort, filters)
    parsed_results = _parse_alerts_result(result, fields)

    outputs = {
        'Claroty.Alert(val.ResourceID == obj.ResourceID)': parsed_results
    }
    readable_output = tableToMarkdown('Claroty Alert List', parsed_results)
    return (
        readable_output,
        outputs,
        result
    )


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

        elif field == "actionable_assets":
            related_assets_str_result = ""
            assets = alert_obj.get(field, [])

            for asset in assets:
                parsed_asset = _parse_single_asset(asset["asset"], DEFAULT_ASSET_FIELD_LIST)
                for asset_keys in parsed_asset.keys():
                    if parsed_asset[asset_keys]:
                        related_assets_str_result += f"{asset_keys} - {parsed_asset[asset_keys]}\r\n"
                related_assets_str_result += "\n"

            parsed_alert_result[ALERT_CTD_FIELD_TO_DEMISTO_FIELD[field]] = related_assets_str_result

        else:
            parsed_alert_result[ALERT_CTD_FIELD_TO_DEMISTO_FIELD[field]] = alert_obj.get(field)

    return parsed_alert_result


def _parse_alert_indicators(indicators: list):
    # TODO: Check if can delete (probably yes)
    parsed_indicators = []
    for indicator_param in indicators:
        indicator_info = indicator_param.get('indicator_info', None)
        if not indicator_info:
            continue
        indicator_description = indicator_info.get('description', None)
        indicator_points = indicator_info.get('points', None)
        parsed_indicators.append({
            "Description": indicator_description,
            "Points": indicator_points
        })
    return parsed_indicators


def _parse_assets_result(assets_result: dict, fields: list) -> List[dict]:
    if 'objects' not in assets_result:
        return []
    obj = assets_result.get('objects', [])
    assets = []

    for obj_fields in obj:
        asset = _parse_single_asset(obj_fields, fields)
        assets.append(asset)
    return assets


def _parse_single_asset(asset_obj: dict, fields: list) -> dict:
    parsed_asset_result = {}
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
            insight_str_result = ""
            for insight in asset_obj.get(field, []):
                insight_str_result += f"CVE ID - {insight['CVE-ID']}\r\n"
                insight_str_result += f"Description - {insight['Description']}\r\n"
                insight_str_result += f"Score - {insight['Score']}\r\n\n"
            parsed_asset_result[ASSET_CTD_FIELD_TO_DEMISTO_FIELD[field]] = insight_str_result
        else:
            parsed_asset_result[ASSET_CTD_FIELD_TO_DEMISTO_FIELD[field]] = asset_obj.get(field)

    return parsed_asset_result


def str_to_bool(str_representing_bool: str):
    return str_representing_bool and str_representing_bool.lower() == 'true'


def get_sort(field_to_sort_by: str, order_by_desc: bool = False):
    order_by_direction = "-" if order_by_desc else ""
    return {"field": field_to_sort_by, "order": order_by_direction}


def get_sort_order(sort_order: str) -> bool:
    return True if sort_order == "asc" else False


def get_fields(obj_name: str) -> list:
    fields = demisto.args().get("fields", "").split(",")

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


def add_filter(filter_name: str, filter_value, filter_operation: str = "exact"):
    return {
        "field": filter_name,
        "value": filter_value,
        "operator": filter_operation,
    }


def transform_filters_labels_to_values(table_filters, filter_name: str, filter_val: str):
    chosen_filters = []
    try:
        for table_filter in table_filters:
            if table_filter['name'].lower() == filter_name:
                table_filter_value = next(table_filter_value['value'] for table_filter_value in table_filter['values']
                                          if filter_val == table_filter_value['label'].lower())
                if table_filter_value:
                    chosen_filters.append((table_filter['name'], table_filter_value))
    except Exception:
        # TODO: Make a real exception....
        pass
    return chosen_filters


def fetch_incidents(client, last_run, first_fetch_time):
    """
    This function will execute each interval (default is 1 minute).

    Args:
        client (Client): Claroty CTD Client
        last_run (dateparser.time): The greatest incident created_time we fetched from last fetch
        first_fetch_time (dateparser.time): If last_run is None then fetch all incidents since first_fetch_time

    Returns:
        next_run: This will be last_run in the next fetch-incidents
        incidents: Incidents that will be created in Demisto
    """
    last_fetch = last_run.get('last_fetch')

    if last_fetch is None:
        last_fetch = dateparser.parse(first_fetch_time).replace(tzinfo=None)
    else:
        last_fetch = dateparser.parse(last_fetch).replace(tzinfo=None)

    latest_created_time = last_fetch
    incidents = []
    field_list = DEFAULT_ALERT_FIELD_LIST + ["timestamp", "severity"]
    extra_filters = {}

    severity = demisto.params().get("severity", None)
    if severity:
        severity_filter = ""
        for severity_key in CTD_TO_DEMISTO_SEVERITY:
            if CTD_TO_DEMISTO_SEVERITY[severity_key] >= CTD_TO_DEMISTO_SEVERITY[severity]:
                severity_filter += f"{severity_key},;$"
        extra_filters["severity"] = severity_filter

    site_id = demisto.params().get("site_id", None)
    if site_id:
        extra_filters["site_id"] = site_id

    alert_type = demisto.params().get("alert_type", None)
    if alert_type:
        alert_filters = client.get_ranger_table_filters('alerts')
        # TODO: fix around the way i return values
        filters_url_suffix = transform_filters_labels_to_values(alert_filters, "type", alert_type.lower())
        if filters_url_suffix:
            for filter_type in filters_url_suffix:
                extra_filters["type"] = filter_type[1]

    response = client.list_incidents(field_list, latest_created_time.strftime(DATE_FORMAT), **extra_filters)
    items = _parse_alerts_result(response, field_list)

    for item in items:
        # Make datetime object unaware of timezone for comparison
        incident_created_time = dateparser.parse(item['Timestamp']).replace(tzinfo=None)
        incident = {
            'name': item['Description'],
            'occurred': incident_created_time.strftime(DATE_FORMAT),
            'severity': CTD_TO_DEMISTO_SEVERITY[item['Severity']],
            'rawJSON': json.dumps(item)
        }

        incidents.append(incident)

        if incident_created_time > latest_created_time:
            latest_created_time = incident_created_time

    next_run = {'last_fetch': latest_created_time.strftime(DATE_FORMAT)}
    return next_run, incidents


def main():
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')

    base_url = demisto.params().get('url')

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
            # This is the call made when pressing the integration Test button.
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
