import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

""" IMPORTS """

import requests
import json
import collections
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

""" GLOBALS/PARAMS """

PARAMS = demisto.params()
USERNAME = PARAMS.get("credentials").get("identifier")
PASSWORD = PARAMS.get("credentials").get("password")
API_KEY = PARAMS.get("api-key_creds", {}).get("password") or PARAMS.get("api-key")
FETCH_TIME = int(PARAMS.get("fetch_time", "7"))
SERVER = PARAMS["url"].removesuffix("/")
USE_SSL = not PARAMS.get("insecure", False)
BASE_URL = SERVER + "/v1"

# Remove proxy if not set to true in params
handle_proxy()

STATUSES = {"Not Reviewed": "0", "Investigating": "1", "On hold": "2", "False Positive": "3", "Escalated": "4"}

TLP_MAP = {"WHITE": 0, "GREEN": 1, "AMBER": 2, "RED": 3}

CONFIDENCE_MAP = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

OBSERVABLE_TYPES_MAP = {"IP": 0, "Domain": 1, "URL": 2, "REGEX": 3, "File Hash": 4}

""" HELPER FUNCTIONS """


# Allows nested keys to be accessible
def makehash():
    return collections.defaultdict(makehash)


def http_request(method, url_suffix, params=None, data=None, headers=None):
    try:
        res = requests.request(method, BASE_URL + url_suffix, verify=USE_SSL, params=params, data=data, headers=headers)
        if res.status_code == 403:
            return_error("Connection forbidden. Please verify your API key is valid.")
        elif res.status_code not in {200, 201}:
            return_error(f"Error in API call to Perch Integration [{res.status_code}] - {res.reason}")

    except requests.exceptions.ConnectionError as error:
        return_error(f"Failed to establish a new connection: {type(error)}")

    try:
        response = res.json()
    except Exception as e:
        return_error(f"Failed to parse JSON response: {str(e)}")
    return response


def find_key_by_value(val, dic_map):
    for key, value in dic_map.items():
        if value == val:
            return key
    return None


def format_alerts(alert):
    hr = makehash()  # type: dict
    ec = makehash()  # type: dict
    if alert.get("id"):
        hr["ID"] = alert.get("id")
        ec["ID"] = alert.get("id")
    if alert.get("sensor_id"):
        hr["Sensor ID"] = alert.get("sensor_id")
        ec["SensorID"] = alert.get("sensor_id")
    if alert.get("observable_id"):
        hr["Observable ID"] = alert.get("observable_id")
        ec["ObservableID"] = alert.get("observable_id")
    if alert.get("indicator_id"):
        hr["Indicator ID"] = alert.get("indicator_id")
        ec["IndicatorID"] = alert.get("indicator_id")
    if alert.get("status"):
        hr["Status"] = alert.get("status")
        ec["Status"] = alert.get("status")
    if alert.get("ts"):
        hr["Timestamp"] = alert.get("ts")
        ec["TS"] = alert.get("ts")
    if alert.get("title"):
        hr["Title"] = alert.get("title")
        ec["Title"] = alert.get("title")
    if alert.get("protocol"):
        hr["Protocol"] = alert.get("protocol")
        ec["Protocol"] = alert.get("protocol")
    if alert.get("src_ip"):
        hr["Source IP"] = alert.get("src_ip")
        ec["SrcIP"] = alert.get("src_ip")
    if alert.get("src_port"):
        hr["Source Port"] = alert.get("src_port")
        ec["SrcPort"] = alert.get("src_port")
    if alert.get("src_geo_ip"):
        src_geo = alert["src_geo_ip"]
        if src_geo.get("latitude"):
            hr["Source Geo"]["Latitude"] = src_geo.get("latitude")
            ec["SrcGeo"]["Latitude"] = src_geo.get("latitude")
        if src_geo.get("longitude"):
            hr["Source Geo"]["Longitude"] = src_geo.get("longitude")
            ec["SrcGeo"]["Longitude"] = src_geo.get("longitude")
        if src_geo.get("country_name"):
            hr["Source Geo"]["Country Name"] = src_geo.get("country_name")
            ec["SrcGeo"]["Country"] = src_geo.get("country_name")
    if alert.get("dest_ip"):
        hr["Destination IP"] = alert.get("dest_ip")
        ec["DestIP"] = alert.get("dest_ip")
    if alert.get("dest_port"):
        hr["Destination Port"] = alert.get("dest_port")
        ec["DestPort"] = alert.get("dest_port")
    if alert.get("dest_geo_ip"):
        dest_geo = alert["dest_geo_ip"]
        if dest_geo.get("latitude"):
            hr["Destination Geo"]["Latitude"] = dest_geo.get("latitude")
            ec["DestGeo"]["Latitude"] = dest_geo.get("latitude")
        if dest_geo.get("longitude"):
            hr["Destination Geo"]["Longitude"] = dest_geo.get("longitude")
            ec["DestGeo"]["Longitude"] = dest_geo.get("longitude")
        if dest_geo.get("country_name"):
            hr["Destination Geo"]["Country Name"] = dest_geo.get("country_name")
            ec["DestGeo"]["Country"] = dest_geo.get("country_name")
    return hr, ec


def alerts_params(args):
    params = {}  # type:dict
    if args.get("page"):
        params["page"] = args.get("page")
    if args.get("page_size"):
        params["page_size"] = args.get("page_size")
    if args.get("closed"):
        params["closed"] = args.get("closed")
    if args.get("closed_at"):
        params["closed_at"] = args.get("closed_at")
    if args.get("community_id"):
        params["community_id"] = args.get("community_id")
    if args.get("created_at"):
        params["created_at"] = args.get("created_at")
    if args.get("dest_ip"):
        params["dest_ip"] = args.get("dest_ip")
    if args.get("dest_port"):
        params["dest_port"] = args.get("dest_port")
    if args.get("full_url"):
        params["full_url"] = args.get("full_url")
    if args.get("id"):
        params["id"] = args.get("id")
    if args.get("indicator_id"):
        params["indicator_id"] = args.get("indicator_id")
    if args.get("indicator_loaded"):
        params["indicator_loaded"] = args.get("indicator_loaded")
    if args.get("observable_id"):
        params["observable_id"] = args.get("observable_id")
    if args.get("protocol"):
        params["protocol"] = args.get("protocol")
    if args.get("sensor_id"):
        params["sensor_id"] = args.get("sensor_id")
    if args.get("sensor_name"):
        params["sensor_name"] = args.get("sensor_name")
    if args.get("soc_status"):
        params["soc_status"] = args.get("soc_status")
    if args.get("src_ip"):
        params["src_ip"] = args.get("src_ip")
    if args.get("src_port"):
        params["src_port"] = args.get("src_port")
    if args.get("status"):
        params["status"] = args.get("status")
    if args.get("status_updated_at"):
        params["status_updated_at"] = args.get("status_updated_at")
    if args.get("team_id"):
        params["team_id"] = args.get("team_id")
    if args.get("title"):
        params["title"] = args.get("title")
    if args.get("ts"):
        params["ts"] = args.get("ts")
    if args.get("closed_at__gte"):
        params["closed_at__gte"] = args.get("closed_at__gte")
    if args.get("closed_at__lte"):
        params["closed_at__lte"] = args.get("closed_at__lte")
    if args.get("created_at__gte"):
        params["created_at__gte"] = args.get("created_at__gte")
    if args.get("created_at__lte"):
        params["created_at__lte"] = args.get("created_at__lte")
    if args.get("status_updated_at__gte"):
        params["status_updated_at__gte"] = args.get("status_updated_at__gte")
    if args.get("status_updated_at__lte"):
        params["status_updated_at__lte"] = args.get("status_updated_at__lte")
    if args.get("status_updated_at__gt"):
        params["status_updated_at__gt"] = args.get("status_updated_at__gt")
    if args.get("status_updated_at__lt"):
        params["status_updated_at__lt"] = args.get("status_updated_at__lt")
    if args.get("ordering"):
        params["ordering"] = args.get("ordering")
    return params


def indicator_params(args):
    params = []
    param = {}
    observables = []
    communities = []
    if args.get("communities"):
        community = {"id": args.get("communities")}
        communities.append(community)

        param["communities"] = communities
    if args.get("type"):
        observable = {"type": OBSERVABLE_TYPES_MAP[args.get("type")], "details": {"value": args.get("value")}}
        observables.append(observable)
        param["observables"] = observables
    if args.get("title"):
        param["title"] = args.get("title")
    if args.get("description"):
        param["description"] = args.get("description")
    if args.get("tlp"):
        param["tlp"] = TLP_MAP[args.get("tlp")]  # type: ignore
    if args.get("confidence"):
        param["confidence"] = CONFIDENCE_MAP[args.get("confidence")]  # type: ignore
    if args.get("operator"):
        param["operator"] = args.get("operator")
    if args.get("first_sighting"):
        param["first_sighting"] = args.get("first_sighting")
    if args.get("email_summary"):
        param["email_summary"] = args.get("email_summary")
    params.append(param)

    return params


def authenticate():
    headers = {"Content-Type": "application/json", "x-api-key": API_KEY}
    req_body = json.dumps({"username": USERNAME, "password": PASSWORD})
    url = "/auth/access_token"
    res_body = http_request("POST", url, data=req_body, headers=headers)
    headers["Authorization"] = "Bearer " + res_body["access_token"]
    return headers


def format_indicator(indicator):
    hr = makehash()  # type: dict
    ec = makehash()  # type: dict
    if indicator.get("id"):
        hr["ID"] = indicator.get("id")
        ec["ID"] = indicator.get("id")
    if indicator.get("confidence"):
        hr["Confidence"] = find_key_by_value(indicator.get("confidence"), CONFIDENCE_MAP)
        ec["Confidence"] = find_key_by_value(indicator.get("confidence"), CONFIDENCE_MAP)
    if indicator.get("created_at"):
        hr["Created At"] = indicator.get("created_at")
        ec["CreatedAt"] = indicator.get("created_at")
    if indicator.get("created_by"):
        hr["Created By"] = indicator.get("created_by")
        ec["CreatedBy"] = indicator.get("created_by")
    if indicator.get("description"):
        hr["Description"] = indicator.get("description")
        ec["Description"] = indicator.get("description")
    if indicator.get("email_summary"):
        hr["Email Summary"] = indicator.get("email_summary")
        ec["EmailSummary"] = indicator.get("email_summary")
    if indicator.get("title"):
        hr["Title"] = indicator.get("title")
        ec["Title"] = indicator.get("title")
    if indicator.get("first_sighting"):
        hr["First Sighting"] = indicator.get("first_sighting")
        ec["FirstSighting"] = indicator.get("first_sighting")
    if indicator.get("perch_id"):
        hr["Perch ID"] = indicator.get("perch_id")
        ec["PerchID"] = indicator.get("perch_id")
    if indicator.get("team"):
        hr["Team"] = indicator.get("team")
        ec["Team"] = indicator.get("team")
    if indicator.get("tlp"):
        hr["TLP"] = find_key_by_value(indicator.get("tlp"), TLP_MAP)
        ec["TLP"] = find_key_by_value(indicator.get("tlp"), TLP_MAP)
    if indicator.get("updated_at"):
        hr["Updated At"] = indicator.get("updated_at")
        ec["UpdatedAt"] = indicator.get("updated_at")
    if indicator.get("operator"):
        hr["Operator"] = indicator.get("operator")
        ec["Operator"] = indicator.get("operator")
    return hr, ec


def item_to_incident(item):
    incident = {"name": "Perch Incident: " + item.get("title"), "occurred": item.get("created_at"), "rawJSON": json.dumps(item)}
    return incident


"""COMMAND FUNCTIONS"""


def search_alerts_command():
    headers = authenticate()
    args = demisto.args()
    params = alerts_params(args)
    url = "/alerts"
    res = http_request("GET", url, headers=headers, params=params)
    res_results = res.get("results")
    hr = ""
    ec = {"Perch": {"Alert": []}}  # type: dict
    for alert in res_results:
        alert_hr, alert_ec = format_alerts(alert)
        ec["Perch"]["Alert"].append(alert_ec)
        hr += tableToMarkdown(f'{alert_ec.get("Title")}', alert_hr)
    if len(res_results) == 0:
        demisto.results("No results were found")
    else:
        demisto.results(
            {
                "Type": entryTypes["note"],
                "ContentsFormat": formats["markdown"],
                "Contents": res_results,
                "HumanReadable": hr,
                "EntryContext": ec,
            }
        )


def list_communities_command():
    headers = authenticate()
    args = demisto.args()
    params = alerts_params(args)
    url = "/communities"
    res = http_request("GET", url, headers=headers, params=params)
    res_results = res.get("results")
    hr = tableToMarkdown("Communities Found", res_results, headerTransform=string_to_table_header, removeNull=True)
    ec = {"Perch": {"Community": []}}  # type: dict
    for alert in res_results:
        ec["Perch"]["Community"].append(createContext(alert, keyTransform=string_to_context_key, removeNull=True))
    if len(res_results) == 0:
        demisto.results("No communities were found")
    else:
        demisto.results(
            {
                "Type": entryTypes["note"],
                "ContentsFormat": formats["markdown"],
                "Contents": res_results,
                "HumanReadable": hr,
                "EntryContext": ec,
            }
        )


def get_community_command():
    headers = authenticate()
    args = demisto.args()
    params = alerts_params(args)
    community_id = args.get("id")
    url = f"/communities/{community_id}"
    res = http_request("GET", url, headers=headers, params=params)
    if len(res) > 0:
        hr = tableToMarkdown("Communities Found", res, headerTransform=string_to_table_header, removeNull=True)
        ec = {"Perch": {"Community": createContext(res, keyTransform=string_to_context_key, removeNull=True)}}  # type: dict
        demisto.results(
            {
                "Type": entryTypes["note"],
                "ContentsFormat": formats["markdown"],
                "Contents": res,
                "HumanReadable": hr,
                "EntryContext": ec,
            }
        )
    else:
        demisto.results("No communities were found")


def create_indicator_command():
    headers = authenticate()
    args = demisto.args()
    raw_data = indicator_params(args)
    data = json.dumps(raw_data)
    url = "/indicators"
    res = http_request("POST", url, headers=headers, data=data)
    indicator_hr, indicator_ec = format_indicator(res[0])
    hr = ""
    ec = {"Perch": {"Indicator": []}}  # type: dict
    ec["Perch"]["Indicator"].append(indicator_ec)
    hr += tableToMarkdown(f'{indicator_hr.get("Title")}', indicator_hr)
    demisto.results(
        {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["markdown"],
            "Contents": res,
            "HumanReadable": hr,
            "EntryContext": ec,
        }
    )


def fetch_alerts(last_run, headers):
    last_fetch = last_run.get("time")
    url = "/alerts"
    statuses_to_fetch = PARAMS.get("soc_status", [])
    if statuses_to_fetch:
        items = []
        for status in statuses_to_fetch:
            res = http_request("GET", url, headers=headers, params=alerts_params({"soc_status": STATUSES[status]}))
            items += res.get("results")
    else:
        res = http_request("GET", url, headers=headers)
        items = res.get("results")
    items.sort(key=lambda r: r["created_at"])
    if last_fetch is None:
        last_fetch_raw = datetime.now() - timedelta(days=FETCH_TIME)
        last_fetch = date_to_timestamp(last_fetch_raw, "%Y-%m-%dT%H:%M:%S.%fZ")
    incidents = []
    for item in items:
        incident = item_to_incident(item)
        incident_date = date_to_timestamp(incident["occurred"], "%Y-%m-%dT%H:%M:%S.%fZ")
        if incident_date > last_fetch:
            incidents.append(incident)
            last_fetch = incident_date
    return last_fetch, incidents


def fetch_alerts_command():
    last_run = demisto.getLastRun()
    headers = authenticate()
    last_fetch, incidents = fetch_alerts(last_run, headers)
    demisto.setLastRun({"time": last_fetch})
    demisto.incidents(incidents)


def test_module():
    try:
        headers = authenticate()
        if PARAMS.get("isFetch"):
            last_run = {"time": 1561017202}
            fetch_alerts(last_run, headers)
        demisto.results("ok")
    except Exception as err:
        return_error(str(err))


""" COMMANDS MANAGER / SWITCH PANEL """
demisto.info(f"Command being called is {demisto.command()}")

try:
    if demisto.command() == "perch-search-alerts":
        search_alerts_command()
    elif demisto.command() == "perch-get-community":
        get_community_command()
    elif demisto.command() == "perch-list-communities":
        list_communities_command()
    elif demisto.command() == "perch-create-indicator":
        create_indicator_command()
    elif demisto.command() == "fetch-incidents":
        fetch_alerts_command()
    elif demisto.command() == "test-module":
        test_module()


# Log exceptions
except Exception as e:
    LOG(str(e))
    LOG.print_log()
    raise
