import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import requests
from datetime import datetime
import json
import urllib3
# from CommonServerUserPython import *
# from CommonServerPython import *


urllib3.disable_warnings()


class Client(BaseClient):
    def __init__(self, base_url, verify, proxies):
        self.base_url = base_url
        self.verify = verify
        self.proxies = proxies
        # self.headers =

    def http_request(self, method, url_suffix, data=None, headers=None):
        server = self.base_url + url_suffix
        res = requests.request(method, server, json=data, verify=self.verify, headers=headers, proxies=self.proxies)
        return res


def test_module(client, headers=None):
    headers = {} if headers is None else headers
    response = client.http_request("GET", "/v4/user/tokens/verify", headers=headers)

    if response.status_code == 200:
        return 'ok'
    else:
        return "Bad status from server: ({}) {}".format(response.status_code, response.text)


def get_zone_ids(client, headers=None):
    params = {
        'page': 1,
        'per_page': 50
    }

    page_count = 1
    websites = []
    while True:
        response = client.http_request("GET", "/v4/zones" + f"?page={page_count}", headers=headers)

        if response.status_code == 200:
            data = response.json()
            websites += [(d['id'], d['name']) for d in data["result"]]

            if data["result_info"]["total_pages"] > data["result_info"]["page"]:
                page_count += 1
            else:
                break
        else:
            raise Exception(f"Error: {response.status_code}, {response.text}")

    return websites


def get_zone_details(client, zone_id, headers=None):

    act_result = {
        "response": None,
        "success": True,
        "name": None
    }
    endpoint = "/v4/zones/{}".format(zone_id)
    response = client.http_request("GET", endpoint, headers=headers)

    if response.status_code == 200:
        act_result["zone_details"] = response.json()
        act_result["name"] = response.json().get("result").get("name")
    else:
        act_result["response"] = "{} -- {}".format(response.status_code, response.text)
        act_result["success"] = False

    return_results(CommandResults(outputs=act_result, readable_output=act_result))

    return act_result


# def parse_list_to_table(data_list):

#     table_data = []
#     headers = list(data_list[0].keys())

#     # Prepare rows for the table
#     table_data = [{header: entry.get(header, "") for header in headers} for entry in data_list]
#     return table_data


def get_firewall_events(client, start_time, end_time, source_ip, zone_ids=None, headers=None):
    # start_time = datetime(2025, 2, 25, 0, 0)
    # end_time = datetime(2025, 3, 15, 23, 59)

    act_result = {
        "cloudflare_events": None
    }

    logs = []
    if not zone_ids:
        websites = get_zone_ids(client, headers)
        zone_ids = [website[0] for website in websites]
        zone_names = [website[1] for website in websites]

    if zone_ids:
        zone_id = ",".join(zone_ids)
        websites = get_zone_details(client, zone_id, headers)
        zone_names = argToList(websites["name"])

    # for i, zone_id in enumerate(zone_ids):
    for i in range(len(zone_ids)):
        query = """
        query ListFirewallEvents($zoneTag: String, $filter: FirewallEventsAdaptiveFilter_InputObject) {
            viewer {
            zones(filter: { zoneTag: $zoneTag }) {
                firewallEventsAdaptive(
                filter: $filter
                limit: 100
                orderBy: [datetime_DESC]
                ) {
                action
                clientAsn
                clientCountryName
                clientIP
                clientRequestPath
                clientRequestQuery
                datetime
                source
                userAgent
                }
            }
            }
        }
        """

        payload = {
            "query": query,
            "variables": {
                "zoneTag": zone_ids[i],
                "filter": {
                    "datetime_geq": start_time,    # .strftime("%Y-%m-%dT%H:%M:%SZ")
                    "datetime_leq": end_time,    # .strftime("%Y-%m-%dT%H:%M:%SZ")
                    "clientIP": source_ip
                }
            }
        }

        headers = {} if headers is None else headers
        response = client.http_request("POST", url_suffix="/v4/graphql", headers=headers, data=payload)

        if response.status_code == 200:
            cloudflare_events = response.json().get("data")["viewer"]
            act_result["cloudflare_events"] = cloudflare_events

            return_results(CommandResults(outputs=act_result, readable_output=act_result))

            human_readable = tableToMarkdown(
                "Query " + zone_names[i].upper() + " Logs:",
                act_result["cloudflare_events"]["zones"][0]["firewallEventsAdaptive"],
                ["action", "clientAsn", "clientCountryName", "clientIP", "clientRequestPath",
                    "clientRequestQuery", "datetime", "source", "userAgent"],
                removeNull=True,
            )

            # data_to_table = parse_list_to_table(act_result["cloudflare_events"]["zones"][0]["firewallEventsAdaptive"])
            # return_results(
            #     "Type": entryTypes["note"],
            #     "Contents": data_to_table,
            #     "ContentsFormat": formats["table"]
            # )

            return_results(
                {
                    "Type": entryTypes["note"],
                    "ContentsFormat": formats["json"],
                    "Contents": act_result,
                    "ReadableContentsFormat": formats["markdown"],
                    "HumanReadable": human_readable,
                    "IgnoreAutoExtract": False
                }
            )

            if not cloudflare_events['zones'][0]['firewallEventsAdaptive']:
                continue
            print("Zone_name: {}".format(zone_names[i]), zone_id)
        else:
            raise Exception(f"Error: {response.status_code}, {response.text}")
            return_error(f"Error: {response.status_code}, {response.text}")

    return logs


def main():
    apikey = demisto.params().get("API-key")
    args = demisto.args()
    # LOG(args)

    zone_id = args.get("ZoneID")
    zone_ids = argToList(args.get("zone_ids"))
    start_time = args.get("start_time")
    end_time = args.get("end_time")
    source_ip = args.get("source_ip")

    baseserver = (
        demisto.params()["url"][:-1]
        if (demisto.params()["url"] and demisto.params()["url"].endswith("/"))
        else demisto.params()["url"]
    )

    verify_certificate = not demisto.params().get("insecure", False)
    proxies = handle_proxy()

    headers = {
        "Authorization": f"Bearer {apikey}",
        "Content-Type": "application/json",
    }

    command = demisto.command()
    try:
        client = Client(baseserver, verify_certificate, proxies)
        commands = {
            "get-firewall-events": get_firewall_events,
            "get-zone-details": get_zone_details
        }
        if command == "test-module":
            result = test_module(client, headers)
            return_results(result)
        elif command == "get-firewall-events":

            result = get_firewall_events(
                client, zone_ids=zone_ids, start_time=start_time, end_time=end_time, source_ip=source_ip, headers=headers
            )
            return_results(result)
        elif command == "get-zone-ids":
            result = get_zone_ids(client, headers)
            return_results(result)
        elif command == "get-zone-details":
            result = get_zone_details(client, zone_id=zone_id, headers=headers)
            return_results(result)

    except Exception as e:
        return_error(str(e))


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
