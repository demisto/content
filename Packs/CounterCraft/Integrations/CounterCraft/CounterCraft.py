import demistomock as demisto
from CommonServerPython import *


""" IMPORTS """
import json
import urllib.parse
import requests
import hmac
from datetime import datetime
import time
import binascii
import uuid
import urllib3

from typing import Dict, List
from hashlib import sha1

# Disable insecure warnings
urllib3.disable_warnings()

""" GLOBALS"""

X_API_KEY_AUTHENTICATION_HEADER_PREFIX = "X-API-Key-Auth-"
SERVER = demisto.params().get("server").rstrip("/") + "/api"
API_KEY = demisto.params().get("api_key")
SECRET_KEY = demisto.params().get("secret_key")
VERIFY_CERTIFICATE = not demisto.params().get("insecure", False)
PROXY = demisto.params().get('proxy', False)
FETCH_DELTA = "24 hours"

DEF_HEADERS = {"Accept": "application/json", "Content-Type": "application/json"}

ERR_DICT = {
    400: 'Bad request. Please check your arguments and Deception Director API manual',
    401: 'User does not have the right permission',
    404: 'Entity not found. Please make sure the entity does exist',
    500: 'Bad request. Please check your arguments and Deception Director API manual',
}

CAMPAIGN_FIELDS = {
    "id": "ID",
    "name": "Name",
    "description": "Description",
    "status_code": "StatusCode",
}

DSN_FIELDS = {
    "id": "ID",
    "name": "Name",
    "description": "Description",
    "hostname": "Hostname",
    "port": "Port",
}

HOST_FIELDS = {
    "id": "ID",
    "name": "Name",
    "description": "Description",
    "type_code": "TypeCode",
    "status_code": "StatusCode",
}

SERVICE_FIELDS = {
    "id": "ID",
    "name": "Name",
    "description": "Description",
    "type_code": "TypeCode",
    "status_code": "StatusCode",
}

BREADCRUMB_FIELDS = {
    "id": "ID",
    "name": "Name",
    "description": "Description",
    "type_code": "TypeCode",
    "status_code": "StatusCode",
}

PROVIDER_FIELDS = {
    "id": "ID",
    "name": "Name",
    "description": "Description",
    "type_code": "TypeCode",
    "status_code": "StatusCode",
}

INCIDENT_FIELDS = {
    "id": "ID",
    "name": "Name",
    "description": "Description",
    "status_code": "StatusCode",
    "tlp_code": "TLPCode",
}

OBJECT_FIELDS = {
    "id": "ID",
    "value": "Value",
    "hits": "Hits",
    "score": "Score",
    "type_code": "TypeCode",
    "first_seen": "FirstSeen",
    "last_seen": "LastSeen",
    "events_count": "EventsCount",
    "tags": "Tags",
}

EVENT_FIELDS = {
    "id": "ID",
    "campaign_name": "CampaignName",
    "category_code": "CategoryCode",
    "host_name": "HostName",
    "service_name": "ServiceName",
    "event_date": "EventDate",
    "score": "Score",
    "type_code": "TypeCode",
    "data": "Data",
    "tags": "Tags",
}

""" HELPERS """


def sign(secret_key, data):
    """
    @param $secret_key the secret key to use for the HMAC-SHA digesting
    @param $data the string to sign
    @return string base64 encoding of the HMAC-SHA1 hash of the data parameter using {@code secret_key} as cipher key.
    """

    sha1_hash = hmac.new(secret_key.encode(), data.encode(), sha1)

    return binascii.b2a_base64(sha1_hash.digest())[
        :-1
    ]  # strip \n from base64 string result


def get_signature(request_method, request_headers, path, query_string, private_key):
    """
    Calculate the authentication headers to be sent with a request to the API
    @param $request_method the HTTP method (GET, POST, etc.)
    @param $path the urlencoded string including the path (from the first forward slash) and the parameters
    @param $x_headers HTTP headers specific to CounterCraft API
    @return array a map with the Authorization and Date headers needed to sign a Latch API request
    """

    x_headers = {
        k: v
        for k, v in request_headers.items()
        if k.lower().startswith(X_API_KEY_AUTHENTICATION_HEADER_PREFIX.lower())
    }

    string_to_sign = (
        request_method.upper().strip()
        + "\n"
        + get_serialized_headers(x_headers)
        + "\n"
        + (
            path
            if query_string.strip() == b""
            else "%s?%s" % (path, query_string.strip().decode("utf-8"))
        )
    )

    return sign(private_key, string_to_sign).decode("utf-8")


def get_serialized_headers(x_headers):
    """
    Generate a string ready to be signed based on HTTP headers received
    @param $x_headers a non neccesarily ordered map (array without duplicates) of the HTTP headers to be ordered.
    @return string The serialized headers, an empty string if no headers are passed
    """

    res = {}  # type: Dict[str, List]

    for k, v in x_headers.items():

        if not k.strip().lower() in res:

            res[k.lower()] = []

        res[k.strip().lower()].append(v.strip())

    return "\n".join(
        "%s:%s" % (k, v)
        for k, v in sorted({k: ",".join(v) for k, v in res.items()}.items())
    )


def http_request(request_method, path, data={}, params=""):
    """
    Send an HTTP request
    @param $request_method the request method GET, POST, etc.
    @param $path the HTTP path
    @param $data the data included in the POST request
    @param $params the URL params to be included
    @return string A dict containing the response in JSON format or an error
    """

    headers = {
        X_API_KEY_AUTHENTICATION_HEADER_PREFIX
        + "Date": time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
    }
    headers.update(DEF_HEADERS)
    signature = get_signature(
        request_method,
        headers,
        path,
        urllib.parse.urlencode(params).encode("utf-8"),
        SECRET_KEY,
    )
    headers["Authorization"] = "APIKey %s:%s" % (API_KEY, signature)
    url = SERVER + path

    proxies = None
    if PROXY:
        proxies = handle_proxy()

    res = requests.request(
        request_method,
        url,
        data=json.dumps(data),
        params=params,
        headers=headers,
        verify=VERIFY_CERTIFICATE,
        proxies=proxies
    )

    if res.status_code not in [200, 201, 204]:
        demisto.debug("Error doing the HTTP query. We got a %s: %s" % (res.status_code, res.text))
        return_error(ERR_DICT[res.status_code])

    try:
        res_json = res.json()
        return res_json
    except Exception as ex:
        demisto.debug(str(ex))
        return_error(str(ex))


def return_host_standard_context(host):

    host_standard_context = {}

    if host['type_code'] == 'MACHINE':

        host_standard_context["ID"] = host['uuid']
        host_standard_context["IP"] = host['data']['ip_address']

        if 'ansible_facts' in host['data']:

            host_standard_context["Domain"] = host['data']['ansible_facts']['ansible_domain']
            host_standard_context["Hostname"] = host['data']['ansible_facts']['ansible_hostname']
            host_standard_context["BIOSVersion"] = host['data']['ansible_facts']['ansible_bios_version']
            host_standard_context["Memory"] = host['data']['ansible_facts']['ansible_memtotal_mb']
            host_standard_context["Model"] = host['data']['ansible_facts']['ansible_product_name']
            host_standard_context["OS"] = host['data']['ansible_facts']['ansible_os_family']
            host_standard_context["OSVersion"] = host['data']['ansible_facts']['ansible_distribution_version']
            host_standard_context["Processor"] = ' '.join(host['data']['ansible_facts']['ansible_processor'])
            host_standard_context["Processors"] = len(host['data']['ansible_facts']['ansible_processor'])

    return host_standard_context


def return_entry_results(title, content, human_readable, context, headers):
    """
    Generic function that receives a result json, and turns it into an entryObject
    @param $title the table title
    @param $content the object contents in JSON format
    @param $human_readable human readable data for the table
    @param $context the entry context
    @param $headers table headers
    @return dict the entryObject
    """

    if len(content) == 0:
        return_outputs(
            readable_output="There is no output result",
            outputs=context,
            raw_response=content,
        )
        return

    if headers:
        if isinstance(headers, str):
            headers = headers.split(",")

    else:
        if isinstance(content, dict):
            headers = list(set(headers).intersection(set(content.keys())))

    readable_output = tableToMarkdown(
        title,
        human_readable,
        headers,
        lambda h: h.title().replace("_", " ").replace(".", ":"),
    )

    return_outputs(
        readable_output=readable_output, outputs=context, raw_response=content
    )


""" COMMANDS """


def test_module_command():

    http_request("GET", "/campaigns")
    demisto.results("ok")


def list_dsns_command():
    """
    Retrieve all deception support nodes
    """

    res = http_request("GET", "/deception_support_nodes")

    new_dsns = []
    for o in res["data"]:
        new_dsns.append(
            {
                new_key: o[old_key] if old_key in o else None
                for old_key, new_key in DSN_FIELDS.items()
            }
        )
    context = createContext(new_dsns, removeNull=True)

    return_entry_results(
        "Deception Support Node",
        res["data"],
        new_dsns,
        {"CounterCraft.DSN(val.ID && val.ID === obj.ID)": context},
        headers=["ID", "Name", "Description", "Hostname", "Port"],
    )


def list_providers_command():
    """
    Retrieve all providers
    """

    res = http_request("GET", "/providers")

    new_providers = []
    for o in res["data"]:
        new_providers.append(
            {
                new_key: o[old_key] if old_key in o else None
                for old_key, new_key in PROVIDER_FIELDS.items()
            }
        )
    context = createContext(new_providers, removeNull=True)

    return_entry_results(
        "Providers",
        res["data"],
        new_providers,
        {"CounterCraft.Provider(val.ID && val.ID === obj.ID)": context},
        headers=["ID", "Name", "Description", "TypeCode", "StatusCode"],
    )


def list_campaigns_command():
    """
    Retrieve all campaigns
    """

    name = demisto.args().get("name")

    if name is not None:
        criteria = {"criteria": f"name:\"{name}\""}
    else:
        criteria = {}

    res = http_request("GET", "/campaigns", params=criteria)

    new_campaigns = []
    for o in res["data"]:
        new_campaigns.append(
            {
                new_key: o[old_key] if old_key in o else None
                for old_key, new_key in CAMPAIGN_FIELDS.items()
            }
        )
    context = createContext(new_campaigns, removeNull=True)

    return_entry_results(
        "Campaigns",
        res["data"],
        new_campaigns,
        {"CounterCraft.Campaign(val.ID && val.ID === obj.ID)": context},
        headers=["ID", "Name", "Description", "StatusCode"],
    )


def list_hosts_command():
    """
    Retrieve all hosts
    """

    campaign_id = demisto.args().get("campaign_id")

    if campaign_id is not None:
        criteria = {"criteria": "campaigns.id:" + campaign_id}
    else:
        criteria = {}

    res = http_request("GET", "/hosts", params=criteria)

    new_hosts = []
    for o in res["data"]:
        new_hosts.append(
            {
                new_key: o[old_key] if old_key in o else None
                for old_key, new_key in HOST_FIELDS.items()
            }
        )

    context = createContext(new_hosts, removeNull=True)
    contextHosts = createContext([return_host_standard_context(x) for x in res["data"]], removeNull=True)

    return_entry_results(
        "Hosts",
        res["data"],
        new_hosts,
        {"CounterCraft.Host(val.ID && val.ID === obj.ID)": context, "Host(val.IP && val.IP === obj.IP)": contextHosts},
        headers=["ID", "Name", "Description", "StatusCode", "TypeCode"],
    )


def list_services_command():
    """
    Retrieve all services
    """

    host_id = demisto.args().get("host_id")

    if host_id is not None:
        criteria = {"criteria": "hosts.id:" + host_id}
    else:
        criteria = {}

    res = http_request("GET", "/services", params=criteria)

    new_services = []
    for o in res["data"]:
        new_services.append(
            {
                new_key: o[old_key] if old_key in o else None
                for old_key, new_key in SERVICE_FIELDS.items()
            }
        )
    context = createContext(new_services, removeNull=True)

    return_entry_results(
        "Services",
        res["data"],
        new_services,
        {"CounterCraft.Service(val.ID && val.ID === obj.ID)": context},
        headers=["ID", "Name", "Description", "StatusCode", "TypeCode"],
    )


def list_breadcrumbs_command():
    """
    Retrieve all breadcrumbs
    """

    campaign_id = demisto.args().get("campaign_id")

    if campaign_id is not None:
        criteria = {"criteria": "campaigns.id:" + campaign_id}
    else:
        criteria = {}

    res = http_request("GET", "/breadcrumbs", params=criteria)

    new_breadcrumbs = []
    for o in res["data"]:
        new_breadcrumbs.append(
            {
                new_key: o[old_key] if old_key in o else None
                for old_key, new_key in BREADCRUMB_FIELDS.items()
            }
        )
    context = createContext(new_breadcrumbs, removeNull=True)

    return_entry_results(
        "Breadcrumbs",
        res["data"],
        new_breadcrumbs,
        {"CounterCraft.Breadcrumb(val.ID && val.ID === obj.ID)": context},
        headers=["ID", "Name", "Description", "StatusCode", "TypeCode"],
    )


def list_incidents_command():
    """
    Retrieve all incidents
    """

    campaign_id = demisto.args().get("campaign_id")

    if campaign_id is not None:
        criteria = {"criteria": "campaigns.id:" + campaign_id}
    else:
        criteria = {}

    res = http_request("GET", "/incidents", params=criteria)

    new_incidents = []
    for o in res["data"]:
        new_incidents.append(
            {
                new_key: o[old_key] if old_key in o else None
                for old_key, new_key in INCIDENT_FIELDS.items()
            }
        )
    context = createContext(new_incidents, removeNull=True)

    return_entry_results(
        "Incidents",
        res["data"],
        new_incidents,
        {"CounterCraft.Incident(val.ID && val.ID === obj.ID)": context},
        headers=["ID", "Name", "Description", "StatusCode", "TLPCode", "Tags"],
    )


def get_object_command():
    """
    Retrieve all objects
    """

    value = demisto.args().get("value")

    if value is not None:
        criteria = {"criteria": "objects.value:" + value}
    else:
        criteria = {}

    res = http_request("GET", "/objects", params=criteria)

    for entry in res["data"]:
        entry["first_seen"] = formatEpochDate(entry["first_seen"])
        entry["last_seen"] = formatEpochDate(entry["last_seen"])

    new_objects = []
    for o in res["data"]:
        new_objects.append(
            {
                new_key: o[old_key] if old_key in o else None
                for old_key, new_key in OBJECT_FIELDS.items()
            }
        )
    context = createContext(new_objects, removeNull=True)

    return_entry_results(
        "Objects",
        res["data"],
        new_objects,
        {"CounterCraft.Object(val.ID && val.ID === obj.ID)": context},
        headers=[
            "ID",
            "Value",
            "Hits",
            "EventsCount",
            "TypeCode",
            "Score",
            "FirstSeen",
            "LastSeen",
            "Tags",
        ],
    )


def get_events_command():
    """
    Retrieve all events
    """

    sfilter = demisto.args().get("criteria")
    per_page = demisto.args().get("max_results")

    criteria = {
        "criteria": sfilter,
        "order": "-event_date",
        "page": 1,
        "per_page": per_page,
    }

    res = http_request("GET", "/events", params=criteria)

    for entry in res["data"]:
        entry["event_date"] = formatEpochDate(entry["event_date"])

    new_events = []
    for o in res["data"]:
        new_events.append(
            {
                new_key: o[old_key] if old_key in o else None
                for old_key, new_key in EVENT_FIELDS.items()
            }
        )
    context = createContext(new_events, removeNull=True)

    return_entry_results(
        "Events",
        res["data"],
        new_events,
        {"CounterCraft.Event(val.ID && val.ID === obj.ID)": context},
        headers=[
            "ID",
            "CampaignName",
            "CategoryCode",
            "HostName",
            "ServiceName",
            "EventDate",
            "Score",
            "TypeCode",
            "Data",
            "Tags",
        ],
    )


def list_notifications(last_fetched):
    """
    Retrieve all Notifications
    """

    criteria = {
        "criteria": 'plugin_code:CONSOLE AND notifications.ctime:["%s" TO *]'
        % last_fetched,
        "order": "-ctime",
        "with_stats": True,
    }

    res = http_request("GET", "/notifications", params=criteria)

    return res["data"]


def create_campaign_command():
    """
    Create a campaign
    """
    name = demisto.args().get("name")
    description = demisto.args().get("description")

    data = {"name": name, "description": description}

    res = http_request("POST", "/campaigns", data=data)

    campaign = {
        new_key: res[old_key] if old_key in res else None
        for old_key, new_key in CAMPAIGN_FIELDS.items()
    }

    context = createContext(campaign, removeNull=True)

    return_entry_results(
        "Campaign",
        res,
        campaign,
        {"CounterCraft.Campaign(val.ID && val.ID === obj.ID)": context},
        headers=["ID", "Name", "Description", "StatusCode"],
    )


def manage_campaign_command():
    """
    Operate a campaign
    """
    campaign_id = demisto.args().get("campaign_id")
    operation = demisto.args().get("operation")

    data = {"action": operation}

    res = http_request("PATCH", "/campaigns/" + campaign_id, data=data)

    message = [{"ID": campaign_id, "Message": res["message"]}]

    context = createContext(message, removeNull=True)

    return_entry_results(
        "Campaign Management",
        res,
        message,
        {"CounterCraft.Campaign(val.ID && val.ID === obj.ID)": context},
        headers=["ID", "Message"],
    )


def create_host_machine_command():
    """
    Create a host of type MACHINE
    """

    name = demisto.args().get("name")
    description = demisto.args().get("description")
    provider_id = demisto.args().get("provider_id")
    type_code = "MACHINE"
    deception_support_node_id = demisto.args().get("deception_support_node_id")
    campaign_id = demisto.args().get("campaign_id")

    ip_address = demisto.args().get("ip_address")
    port = demisto.args().get("port")
    username = demisto.args().get("username")
    password = demisto.args().get("password")

    host_data = {
        "ip_address": ip_address,
        "port": port,
        "username": username,
        "password": password,
        "os_family_usr": "linux",
    }

    _uuid = str(uuid.uuid4())

    data = {
        "name": name,
        "description": description,
        "provider_id": provider_id,
        "deception_support_node_id": deception_support_node_id,
        "campaign_id": campaign_id,
        "type_code": type_code,
        "uuid": _uuid,
        "data": host_data,
    }

    res = http_request("POST", "/hosts", data=data)

    host = {
        new_key: res[old_key] if old_key in res else None
        for old_key, new_key in HOST_FIELDS.items()
    }

    context = createContext(host, removeNull=True)

    return_entry_results(
        "Hosts",
        res,
        host,
        {"CounterCraft.Host(val.ID && val.ID === obj.ID)": context},
        headers=["ID", "Name", "Description", "StatusCode", "TypeCode"],
    )


def manage_host_command():
    """
    Operate a host
    """
    host_id = demisto.args().get("host_id")
    operation = demisto.args().get("operation")

    data = {"action": operation}

    res = http_request("PATCH", "/hosts/" + host_id, data=data)

    message = {"ID": host_id, "Message": res["message"]}

    context = createContext(message, removeNull=True)

    return_entry_results(
        "Host Management",
        res,
        message,
        {"CounterCraft.Host(val.ID && val.ID === obj.ID)": context},
        headers=["ID", "Message"],
    )


def manage_service_command():
    """
    Operate a service
    """
    service_id = demisto.args().get("service_id")
    operation = demisto.args().get("operation")

    data = {"action": operation}

    res = http_request("PATCH", "/services/" + service_id, data=data)

    message = {"ID": service_id, "Message": res["message"]}

    context = createContext(message, removeNull=True)

    return_entry_results(
        "Service Management",
        res,
        message,
        {"CounterCraft.Service(val.ID && val.ID === obj.ID)": context},
        headers=["ID", "Message"],
    )


def manage_breadcrumb_command():
    """
    Operate a breadcrumb
    """
    breadcrumb_id = demisto.args().get("breadcrumb_id")
    operation = demisto.args().get("operation")

    data = {"action": operation}

    res = http_request("PATCH", "/breadcrumbs/" + breadcrumb_id, data=data)

    message = {"ID": breadcrumb_id, "Message": res["message"]}

    context = createContext(message, removeNull=True)

    return_entry_results(
        "Breadcrumb Management",
        res,
        message,
        {"CounterCraft.Breadcrumb(val.ID && val.ID === obj.ID)": context},
        headers=["ID", "Message"],
    )


def fetch_incidents_command():
    """
    Fetch incidents (user notifications)
    """

    last_run = demisto.getLastRun()
    if not last_run:
        last_run = {}
    if "time" not in last_run:
        # get timestamp in seconds
        timestamp, _ = parse_date_range(FETCH_DELTA, to_timestamp=True)
        timestamp /= 1000
    else:
        timestamp = last_run["time"]

    max_timestamp = timestamp

    # All alerts retrieved from get_alerts are newer than last_fetch and are in a chronological order
    notifications = list_notifications(timestamp)

    incidents = []

    for notification in notifications:
        if int(notification["ctime"]) > timestamp:
            incidents.append(
                {
                    "name": notification["data"]["subject"],
                    "occurred": datetime.utcfromtimestamp(
                        int(notification["ctime"])
                    ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "details": notification["data"]["html"],
                    "rawJSON": json.dumps(notification),
                }
            )
            if int(notification["ctime"]) > max_timestamp:
                max_timestamp = int(notification["ctime"])

    demisto.incidents(incidents)
    demisto.setLastRun({"time": max_timestamp})


def main():
    try:
        if demisto.command() == "test-module":
            test_module_command()
        elif demisto.command() == "countercraft-list-providers":
            list_providers_command()
        elif demisto.command() == "countercraft-list-dsns":
            list_dsns_command()
        elif demisto.command() == "countercraft-list-campaigns":
            list_campaigns_command()
        elif demisto.command() == "countercraft-list-hosts":
            list_hosts_command()
        elif demisto.command() == "countercraft-list-services":
            list_services_command()
        elif demisto.command() == "countercraft-list-breadcrumbs":
            list_breadcrumbs_command()
        elif demisto.command() == "countercraft-list-incidents":
            list_incidents_command()
        elif demisto.command() == "countercraft-get-object":
            get_object_command()
        elif demisto.command() == "countercraft-get-events":
            get_events_command()
        elif demisto.command() == "countercraft-create-campaign":
            create_campaign_command()
        elif demisto.command() == "countercraft-create-host-machine":
            create_host_machine_command()
        elif demisto.command() == "countercraft-manage-campaign":
            manage_campaign_command()
        elif demisto.command() == "countercraft-manage-host":
            manage_host_command()
        elif demisto.command() == "countercraft-manage-service":
            manage_service_command()
        elif demisto.command() == "countercraft-manage-breadcrumb":
            manage_breadcrumb_command()
        elif demisto.command() == "fetch-incidents":
            fetch_incidents_command()
    except Exception as e:
        return_error(
            "Unable to perform command : {}, Reason: {}".format(demisto.command(), e)
        )


if __name__ in ("__main__", "builtin", "builtins"):
    main()
