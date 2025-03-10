import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests
import json
import time
import os
from typing import Any, Dict

import urllib3

from urllib3.exceptions import InsecureRequestWarning

urllib3.disable_warnings(InsecureRequestWarning)

if not demisto.params()["proxy"]:
    del os.environ["HTTP_PROXY"]
    del os.environ["HTTPS_PROXY"]
    del os.environ["http_proxy"]
    del os.environ["https_proxy"]

""" GLOBAL VARS """
URL = demisto.getParam("url") + "/aellaelastic"
USERNAME = demisto.getParam("credentials")["identifier"]
PASSWORD = demisto.getParam("credentials")["password"]
FETCH_INTERVAL = demisto.getParam("fetch_interval")
VALIDATE_CERT = not demisto.params().get("insecure", True)

""" HELPER FUNCTIONS """


def make_rest_call(end_point, username, password, action_result, headers={}, params=None, data=None, method="get"):
    headers.update({"Accept": "application/json"})
    headers.update({"Content-Type": "application/json"})

    resp_json = None
    request_func = getattr(requests, method)
    if not request_func:
        action_result["status"] = "Unsupported method {}".format(method)
        return
    try:
        r = request_func(
            end_point,
            auth=(username, password),
            data=json.dumps(data) if data else None,
            headers=headers,
            verify=VALIDATE_CERT,
            params=params,
        )
    except Exception as e:
        action_result["status"] = "Server REST API exception {}".format(e)
        return

    if r is not None:
        action_result["r_text"] = r.text
        action_result["headers"] = r.headers
        action_result["r_status_code"] = r.status_code

    try:
        resp_json = r.json()
    except Exception as e:
        demisto.debug(f"Error while parsing response JSON: {e}")
        action_result["status"] = "Json parse error {}".format(r.text.replace("{", " ").replace("}", " "))
        return

    if 200 <= r.status_code <= 399:
        action_result["status"] = "Success"
    else:
        action_result["status"] = "Failed"

    action_result["data"] = resp_json
    return


""" FUNCTIONS """


def fetch_incidents_command():
    fetch_interval = demisto.getParam("fetch_interval")
    if fetch_interval is None:
        fetch_interval = 15 * 60  # 15 minutes
    else:
        try:
            fetch_interval = int(fetch_interval) * 60
            if fetch_interval < 15 * 60:
                # Min is 15 minutes
                fetch_interval = 15 * 60
        except ValueError as e:
            demisto.debug(f"Error in parsing fetch_interval: {e}")
            fetch_interval = 15 * 60

    cur_t = time.time()

    checkTime = cur_t - fetch_interval

    event = demisto.getParam("event_name")
    if event is None:
        event = "*"

    score = demisto.getParam("severity")
    if score:
        try:
            score = int(score)
            if score < 0 or score > 100:
                score = 50
        except ValueError:
            demisto.debug(f"Failed to convert the value of severity to an integer: {score}")
            score = 50
    else:
        # Default score
        score = 50

    index_str = "aella-ser*"

    query_str = "event_name:{}  AND severity:>{}".format(event, score)

    ts_str = str(int(checkTime * 1000))

    query_json = {
        "query": {
            "bool": {
                "must": [
                    {"query_string": {"query": query_str, "analyze_wildcard": True}},
                    {"range": {"timestamp": {"gt": ts_str}}},
                ]
            }
        }
    }

    end_point = URL + "/{0}/{1}/_search".format(index_str, "amsg")

    action_result: Dict[Any, Any] = {}
    make_rest_call(end_point, USERNAME, PASSWORD, action_result, data=query_json)

    if action_result["status"] == "Success":
        demisto.info("Poll incidents ok")
        data = action_result.get("data")
        if not isinstance(data, dict):
            demisto.error("Data returned in wrong format {}".format(data))
            demisto.incidents([])
            return
        hits = data.get("hits", {}).get("hits", [])
        incidents = []

        try:
            cached_event = demisto.getLastRun().get("cached_event", {})
        except Exception as e:
            demisto.debug("Error while accessing the last run data: {}".format(e))
            cached_event = {}

        new_cached_event = {}

        for hit in hits:
            source = hit.get("_source", None)
            if not source:
                continue
            event_name = source.get("event_name", None)
            try:
                event_severity = int(source.get("severity", None))
                if event_severity > 75:
                    severity = 3
                elif event_severity > 50:
                    severity = 2
                else:
                    severity = 1
            except ValueError as e:
                demisto.debug("Error while converting the severity value to int: {}".format(e))
                severity = 0

            if not event_name:
                continue
            eid = hit["_id"]

            new_cached_event[eid] = True
            if cached_event.get(eid, False):
                continue

            sdi = "{}_{}".format(event_name, eid)
            incident = {
                "name": sdi,
                "severity": severity,
                "rawJSON": json.dumps(
                    {
                        "name": sdi,
                        "label": "Starlight event",
                        "aella_eid": eid,
                        "aella_event": event_name,
                        "event_severity": event_severity,
                    }
                ),
            }
            incidents.append(incident)
        demisto.info("Incidents is {}".format(incidents))
        demisto.setLastRun({"cached_event": new_cached_event})
        demisto.incidents(incidents)

    else:
        demisto.info("Poll incidents failed {}".format(action_result))
        demisto.incidents([])


def aella_get_event_command():
    demisto.info("Aella started get-event with {}".format(demisto.args()["event_id"]))
    event_id = demisto.args()["event_id"]
    query_json = {"query": {"match": {"_id": event_id}}}
    end_point = URL + "/{0}/{1}/_search".format("aella-ser*", "amsg")

    action_result: Dict[Any, Any] = {}

    make_rest_call(end_point, USERNAME, PASSWORD, action_result, data=query_json)
    if action_result["status"] == "Success":
        demisto.info("Run Query is successful")
        response = action_result.get("data", {})
        timed_out = response.get("timed_out", False)
        hits = response.get("hits", {}).get("hits", [])
        source = {}
        dbot_scores = []
        if len(hits) == 0:
            demisto.info("Get event got empty result")
        for item in hits:
            index = item.get("_index", "")
            source = item.get("_source", {})
            if index:
                source["_index"] = index
                source["timed_out"] = timed_out
                demisto.debug("This is my run_query result aellaEvent {}".format(source))

                # Check url reputation
                url_str = source.get("url", "")
                if url_str:
                    url_reputation = source.get("url_reputation", "")
                    if url_reputation and url_reputation != "Good":
                        dbot_score = {
                            "Vendor": "Aella Data",
                            "Indicator": url_str,
                            "Type": "url",
                            "Score": 3,
                            "Malicious": {
                                "Vendor": "Aella Data",
                                "Detections": "URL reputation {0}".format(url_reputation),
                                "URL": url_str,
                            },
                        }
                    else:
                        dbot_score = {"Vendor": "Aella Data", "Indicator": url_str, "Type": "url", "Malicious": None}
                        if url_reputation is None:
                            # Unknonw
                            dbot_score["Score"] = 0
                        else:
                            # Good
                            dbot_score["Score"] = 1
                    dbot_scores.append(dbot_score)

                # Check src ip reputation
                srcip_str = source.get("srcip", "")
                if srcip_str:
                    srcip_reputation = source.get("srcip_reputation", "")
                    if srcip_reputation and srcip_reputation != "Good":
                        dbot_score = {
                            "Vendor": "Aella Data",
                            "Indicator": srcip_str,
                            "Type": "ip",
                            "Score": 3,
                            "Malicious": {
                                "Vendor": "Aella Data",
                                "Detections": "Source IP reputation {0}".format(srcip_reputation),
                                "IP": srcip_str,
                            },
                        }
                    else:
                        dbot_score = {"Vendor": "Aella Data", "Indicator": srcip_str, "Type": "ip", "Malicious": None}
                        if srcip_reputation is None:
                            # Unknonw
                            dbot_score["Score"] = 0
                        else:
                            # Good
                            dbot_score["Score"] = 1
                    dbot_scores.append(dbot_score)

                # Check dst ip reputation
                dstip_str = source.get("dstip", "")
                if dstip_str:
                    dstip_reputation = source.get("dstip_reputation", "")
                    if dstip_reputation and dstip_reputation != "Good":
                        dbot_score = {
                            "Vendor": "Aella Data",
                            "Indicator": dstip_str,
                            "Type": "ip",
                            "Score": 3,
                            "Malicious": {
                                "Vendor": "Aella Data",
                                "Detections": "Destination IP reputation {0}".format(dstip_reputation),
                                "IP": dstip_str,
                            },
                        }
                    else:
                        dbot_score = {"Vendor": "Aella Data", "Indicator": dstip_str, "Type": "ip", "Malicious": None}
                        if dstip_reputation is None:
                            # Unknonw
                            dbot_score["Score"] = 0
                        else:
                            # Good
                            dbot_score["Score"] = 1
                    dbot_scores.append(dbot_score)

            break
        demisto.results(
            {
                "Type": entryTypes["note"],
                "ContentsFormat": formats["json"],
                "Contents": source,
                "HumanReadable": tableToMarkdown("Aella Star Light Event <{0}>".format(event_id), source),
                "EntryContext": {
                    "Aella.Event(val._id==obj._id)": source,
                    "DBotScore": createContext(dbot_scores, removeNull=True),
                },
            }
        )
    else:
        demisto.info("Get event failed {}".format(action_result))
        demisto.results(return_error("Failed to get event"))


""" EXECUTION CODE """
demisto.info("Command is {}".format(demisto.command()))

if demisto.command() == "test-module":
    # This is the call made when pressing the integration test button.
    action_result: Dict[Any, Any] = {}

    make_rest_call(URL + "/_cluster/health", USERNAME, PASSWORD, action_result)

    if action_result["status"] == "Success":
        demisto.results("ok")
    else:
        demisto.results("failed")

if demisto.command() == "fetch-incidents":
    fetch_incidents_command()

if demisto.command() == "aella-get-event":
    aella_get_event_command()
