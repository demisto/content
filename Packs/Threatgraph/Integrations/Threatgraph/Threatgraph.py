# v2.1.2 no change, just reversioned following git restructuring and changed tags for deployment
# v1.1.1 fix bugs where multiple items not working
# v1.1.0 Threatgraph api for the deprecated Crowdstrike Threatgraph
# as soon as Crowdstrike create a replacement then this integration can be removed
import logging

import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401

logging.basicConfig()

BASE_URL = demisto.params()['url'][:-1] if demisto.params()['url'].endswith('/') else demisto.params()['url']
USERNAME = demisto.params().get('apikey')
PASSWORD = demisto.params().get('apisecret')


def get_tree(args):
    sensor_ids = str(args["sensor_ids"])
    process_ids = str(args["process_ids"])

    if isinstance(sensor_ids, List[str]):
        sensor_ids = sensor_ids.replace('[', '').replace(']', '').replace("'", "").replace('"', '')
        sensor_ids = sensor_ids.split(",")

    if isinstance(process_ids, List[str]):
        process_ids = process_ids.replace('[', '').replace(']', '').replace("'", "").replace('"', '')
        process_ids = process_ids.split(",")

    all_results = {}
    all_ips = []
    all_sources = []
    all_destinations = []

    for sensor_id in sensor_ids:
        for process_id in process_ids:
            main_process = query_process(sensor_id, process_id)
            if main_process.status_code != 200:
                continue
            results = {}
            json_response = main_process.json()
            for vertex in json_response["resources"]:
                if vertex["vertex_type"] == "process":
                    # results["main_process"] = {"sensor_id": sensor_id, "process_id": process_id, "properties": vertex["properties"], "indicators": parse_indicators(json_response["resources"][0])}
                    results["main_process"] = {"sensor_id": sensor_id,
                                               "process_id": process_id, "properties": vertex["properties"]}
                    ips, sources, destinations = parse_indicators(json_response["resources"][0])
                    all_ips += ips
                    all_sources += sources
                    all_destinations += destinations
                    for edge in vertex["edges"]:
                        if edge == "parent_process":
                            parent_data = query_process(vertex["edges"][edge][0]["device_id"],
                                                        vertex["edges"][edge][0]["object_id"])
                            if parent_data.status_code == 200:
                                parent_json = parent_data.json()
                                # results["parent_process"] = {"device_id": vertex["edges"][edge][0]["device_id"], "process_id": vertex["edges"][edge][0]["object_id"], "properties": parent_json["resources"][0]["properties"], "indicators": parse_indicators(parent_json["resources"][0])}
                                results["parent_process"] = {"device_id": vertex["edges"][edge][0]["device_id"], "process_id": vertex["edges"]
                                                             [edge][0]["object_id"], "properties": parent_json["resources"][0]["properties"]}
                                ips, sources, destinations = parse_indicators(parent_json["resources"][0])
                                all_ips += ips
                                all_sources += sources
                                all_destinations += destinations
                            else:
                                results["parent_process"] = {"device_id": vertex["edges"][edge][0]["device_id"],
                                                             "process_id": vertex["edges"][edge][0]["object_id"], "properties": "No response for parent"}
                        if edge == "child_process":
                            results["child_processes"] = []
                            for child in vertex["edges"][edge]:
                                child_data = query_process(child["device_id"], child["object_id"])
                                child_json = child_data.json()
                                if child_data.status_code == 200:
                                    # results["child_processes"].append({"device_id": child["device_id"], "process_id": child["object_id"], "properties": child_json["resources"][0]["properties"], "indicators": parse_indicators(child_json["resources"][0])})
                                    results["child_processes"].append(
                                        {"device_id": child["device_id"], "process_id": child["object_id"], "properties": child_json["resources"][0]["properties"]})
                                    ips, sources, destinations = parse_indicators(child_json["resources"][0])
                                    all_ips += ips
                                    all_sources += sources
                                    all_destinations += destinations
                                else:
                                    results["child_processes"].append(
                                        {"device_id": child["device_id"], "process_id": child["object_id"], "properties": "No response for child"})
            if results:
                all_results[process_id] = results

    all_results["ip_addresses"] = all_ips
    ip_string = ''
    for ip in all_sources:
        ip_string += ip + ':s,'
    for ip in all_destinations:
        ip_string += ip + ':d,'
    ip_string = ip_string.rstrip(',')
    all_results["source_ip_addresses"] = all_sources
    all_results["destination_ip_addresses"] = all_destinations
    all_results["ip_type_string"] = ip_string

    result_incident = createContext(all_results, id=None, keyTransform=underscoreToCamelCase, removeNull=True)
    ec = {
        'ThreatGraph_data(val.Id && val.Id === obj.Id)': result_incident
    }
    entry = {
        'Type': entryTypes['note'],
        'Contents': result_incident,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': result_incident,
        'EntryContext': ec
    }
    return entry


def query_process(sensor_id, process_id):
    url = f'{BASE_URL}/threatgraph/combined/processes/summary/v1?ids=pid:{sensor_id}:{process_id}&scope=device'
    return query_threatgraph(url)


def query_threatgraph(url):
    r = requests.get(url, auth=(USERNAME, PASSWORD))
    return r


def parse_indicators(resources):
    indicators = set()
    source = set()
    destination = set()
    for edge in resources["edges"]:
        if edge == "ipv4":
            for ip in resources["edges"][edge]:
                source.add(ip["properties"]["LocalAddressIP4"])
                indicators.add(ip["properties"]["LocalAddressIP4"])
                destination.add(ip["properties"]["RemoteAddressIP4"])
                indicators.add(ip["properties"]["RemoteAddressIP4"])

    return indicators, source, destination


def test():
    try:
        url = f'{BASE_URL}/threatgraph/combined/processes/summary/v1?ids=pid:1:1&scope=device'
        r = requests.get(url, auth=(USERNAME, PASSWORD))

        if r.status_code == 200 or r.status_code == 404:
            return_results('ok')
        else:
            return_results("Failed to login with error: " + str(r.status_code))
    except Exception as e:
        return_results(e)


def main():
    integration_logger = logging.getLogger('threatgraph')
    integration_logger.propagate = False
    LOG(f'Command is {demisto.command}')
    try:
        args = demisto.args()
        if demisto.command() == 'test-module':
            test()
        if demisto.command() == 'bt-get-tree':
            demisto.results(get_tree(args))
    except Exception as e:
        LOG(e)
        LOG.print_log()
        raise


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
