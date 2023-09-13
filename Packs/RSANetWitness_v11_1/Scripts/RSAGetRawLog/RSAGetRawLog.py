import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json


''' STANDALONE FUNCTION '''


class RSAError(Exception):
    # exception when an element is not found
    pass


def is_json(myjson):
    try:
        json_object = json.loads(myjson)
        return json_object
    except ValueError:
        return None


def merge_dict(first_dict: dict, second_dict: dict):
    res = first_dict.copy()
    for key, value in second_dict.items():
        if key in res:
            if isinstance(res[key], list):
                if isinstance(value, list):
                    res[key] = list(set(res[key] + value))
                elif value not in res[key]:
                    res[key].append(value)
            elif value != res[key]:
                if isinstance(value, list):
                    res[key] = list({res[key], *value})
                else:
                    res[key] = [res[key], value]
        else:
            res[key] = value
    return res


def get_raw_log(event_source_id: str, concentrator_ip: str, concentrator_port: str) -> list:
    if isCommandAvailable("netwitness-packets") is False:
        return [{"log": "Please add RSA Netwitness Packet & Logs to see more details"}]

    params = {
        "sessions": event_source_id,
        "concentratorIP": concentrator_ip,
        "concentratorPort": concentrator_port,
        "render": "application/json",
        "renderToContext": "true"
    }
    res = demisto.executeCommand("netwitness-packets", params)

    if type(res[0]["Contents"]) is str:
        raise RSAError(res[0]["Contents"])

    return res[0]["Contents"].get("logs")


def get_metas_log(event_source_id: str, concentrator_ip: str, concentrator_port: str) -> list:
    if isCommandAvailable("netwitness-packets") is False:
        return ["Please add/configure RSA Netwitness Packet & Logs to see more details"]

    params = {
        "query": f"select * where sessionid={event_source_id}",
        "concentratorIP": concentrator_ip,
        "concentratorPort": concentrator_port
    }
    res = demisto.executeCommand("netwitness-query", params)

    if type(res[0]["Contents"]) is str:
        raise RSAError(res[0]["Contents"])

    return res[0]["EntryContext"]["NetWitness.Events"]


def create_id_set(list_metas):
    id_found = []
    for meta in list_metas:
        if "id" in meta:
            id_found.append(meta["id"])
    return id_found


''' MAIN FUNCTION '''


def main():
    inc = demisto.incident()
    rsa_alerts = inc.get("CustomFields", {}).get("rsaalerts", [])
    rsa_rawlogs = inc.get("CustomFields", {}).get("rsarawlogslist", [])
    rsa_nb_meta = 1
    rsa_metas = inc.get("CustomFields", {}).get("rsametasevents", [])
    # check in case we forgot to set XSOAR parameter right
    if not rsa_alerts:
        return_results(CommandResults(readable_output="No alert/event was found in this incident."))
        return

    id_set_alerts = create_id_set(rsa_alerts)
    id_set_rawlogs = create_id_set(rsa_rawlogs)
    tmp_nb_meta = len(rsa_metas)

    # in order to get only the new raw log, we only get the nb of changed line
    if set(id_set_alerts) == set(id_set_rawlogs):
        return_results(CommandResults(readable_output="Nothing has changed !"))
        return

    change = 0
    for alert in rsa_alerts:
        # alert already registered and raw log extracted
        if alert["id"] in id_set_rawlogs:
            continue
        rsa_rawlogs.append({"date": alert["created"], "id": alert["id"], "name": alert["title"], "type": "Alert"})
        for event in alert["events"]:
            session = event.get("eventSourceId")
            res = event.get("eventSource").split(":")
            concentrator_ip = res[0]
            concentrator_port = f"5010{res[1][-1]}"
            try:
                raw_log = get_raw_log(session, concentrator_ip, concentrator_port)
                if raw_log and len(raw_log) >= 1:
                    rsa_rawlogs.append({
                        "date": alert["created"],
                        "id": alert["id"],
                        "name": raw_log[0]["log"],
                        "type": "Raw event"
                    })
            except RSAError as e:
                return_error(f"Error: {e}")
            except ValueError as e:
                return_results(f"Warning: {e}")
        change += 1

        # get only x raw log
        if tmp_nb_meta < rsa_nb_meta:
            try:
                metas = get_metas_log(session, concentrator_ip, concentrator_port)
                tmp_nb_meta += 1
                # rsa_metas => grid = list
                if len(rsa_metas) >= 1:
                    rsa_metas = [merge_dict(rsa_metas[0], metas[0])]
                else:
                    rsa_metas = [merge_dict({}, metas[0])]
            except RSAError as e:
                return_error(f"Error: {e}")
            except ValueError as e:
                return_results(f"Warning: {e}")

    demisto.executeCommand("setIncident", {'customFields': {"rsarawlogslist": rsa_rawlogs, "rsametasevents": rsa_metas}})
    return_results(CommandResults(readable_output=f"{change} raw log inserts !"))


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
