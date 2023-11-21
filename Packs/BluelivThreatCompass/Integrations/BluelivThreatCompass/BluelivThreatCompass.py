import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
''' IMPORTS '''
from CommonServerUserPython import *
import json
import urllib3
from datetime import datetime

''' PARAM DEFINITION '''
MAX_RESOURCES = 100
STATUS_VALUES = ["NOT_AVAILABLE", "NOT_IMPORTANT", "NOT_PROCESSABLE", "POSITIVE", "NEGATIVE",
                 "INFORMATIVE", "IMPORTANT"]
MODULES = {"Hacktivism": "hacktivism", "MobileApps": "mobile_apps", "Credentials": "credentials",
           "DarkWeb": "dark_web", "MediaTracker": "media_tracker", "Malware": "malware",
           "DomainProtection": "domain_protection", "DataLeakage": "data_leakage", "CreditCards": "credit_card"}

'''FETCH PARAMETERS'''
BLUELIV_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"


class Client(BaseClient):
    def __init__(self, base_url, verify=True, proxy=False, ok_codes=tuple(), headers=None, auth=None,
                 organization=0, module=0, module_type=""):
        BaseClient.__init__(self, base_url, verify=verify, proxy=proxy, ok_codes=ok_codes, headers=headers, auth=auth)

        self.module_type = module_type
        self._organization = organization
        self._module = module
        self._module_url = "/organization/{}/module/{}/{}".format(organization, module, MODULES[module_type])

    def authenticate(self, username: str, password: str):
        body = {
            'username': username,
            'password': password
        }
        res = self._http_request(method='POST', url_suffix='/auth', json_data=body)
        self._headers = {"Content-Type": "application/json", "x-cookie": str(res.get('token'))}
        return str(res.get('token'))

    def resource_select(self, args):
        params = create_search_query(args)
        path = "/resource"

        res = self._http_request(method='GET', url_suffix=self._module_url + path, params=params)
        return res

    def resource_get(self, args):
        resource_id = args.get("id", "")
        path = "/resource/{}".format(resource_id)

        res = self._http_request(method='GET', url_suffix=self._module_url + path)
        return res

    def module_get_labels(self):
        path = "/resource/label"

        res = self._http_request(method='GET', url_suffix=self._module_url + path)
        return res

    def resource_label(self, args):
        path = "/resource/label"
        body = {"label": args.get("labelId", 0), "resources": [str(args.get("id", 0))]}

        res = self._http_request(method='PUT', url_suffix=self._module_url + path, json_data=body)
        return res

    def resource_user_result(self, args):
        resource_id = args.get("id", "")
        user_result = args.get("status", "")

        path = "/resource/{}/userResult/{}".format(resource_id, user_result)

        res = self._http_request(method='PUT', url_suffix=self._module_url + path)
        return res

    def resource_set_tlp(self, args):
        resource_id = args.get("id", "")
        tlp = args.get("tlp", "")

        path = "/resource/{}/tlpStatus/{}".format(resource_id, tlp.upper())

        res = self._http_request(method='PUT', url_suffix=self._module_url + path)
        return res

    def resource_read_result(self, args):
        resource_id = args.get("id", 0)
        read_result = args.get("read", "true")
        read_result = read_result == "true"

        data = {"resources": [resource_id], "read": read_result}
        path = "/resource/markAs"

        res = self._http_request(method='PUT', url_suffix=self._module_url + path, json_data=data)
        return res

    def resource_fav(self, args):
        resource_id = args.get("id", 0)
        fav = args.get("favourite", "group")
        fav = fav + "_STARRED"

        data = {"resource": resource_id, "status": fav.upper()}
        path = "/resource/fav"

        res = self._http_request(method='PUT', url_suffix=self._module_url + path, json_data=data)
        return res

    def resource_rating(self, args):
        resource_id = args.get("id", 0)
        read_result = args.get("rating", "1")

        data = {"resource": resource_id, "rate": read_result}
        path = "/resource/rating"
        res = self._http_request(method='PUT', url_suffix=self._module_url + path, json_data=data)
        return res

    def test_module_connection(self):
        path = "/resource/total"
        res = self._http_request(method='GET', url_suffix=self._module_url + path)
        return res


def create_search_query(args):
    params = {}

    # Pagination
    limit = int(args.get("limit", MAX_RESOURCES))
    limit = min(limit, MAX_RESOURCES)
    page = int(args.get("page", 1)) if int(args.get("page", 0)) != 0 else 1

    params["page"] = str(page)
    params["maxRows"] = str(limit)

    # Time filter
    ini_date = args.get("iniDate", "")
    fin_date = args.get("finDate", "")
    params["granularity"] = "DAY"

    if fin_date:
        params["to"] = blueliv_date_to_timestamp(fin_date)
    if ini_date:
        params["since"] = blueliv_date_to_timestamp(ini_date)

    # Search parameters
    if "read" in args and args["read"].lower() in ["both", "read", "unread"]:
        number = {"both": "0", "read": "1", "unread": "2"}
        params["read"] = number[args['read'].lower()]
    if "search" in args:
        params["q"] = args['search']
    if "since" in args:
        params["since"] = args['since']
    if "to" in args:
        params["to"] = args['to']
    if "rows" in args:
        params["maxRows"] = args['rows']
    if "page" in args:
        params["page"] = args['page']

    if "status" in args and all(status in STATUS_VALUES for status in args["status"].split(",")):
        params["analysisCalcResult"] = args['status']

    params["o"] = "IDASC"

    return params


# This function return false when there are no results to display
def not_found():
    return_results({
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': 'No results found.',
        'EntryContext': {"BluelivThreatCompass": {}}
    })


# Possible inputs dateTime: yyyy-mm-dd / yyyy-mm-ddThh:mm:ss / yyyy-mm-dd hh:mm:ss
def blueliv_date_to_timestamp(now):
    if "/" in now:
        now = now.replace("/", "-")
    try:
        if 'T' in now:
            str_date = datetime.strptime(now, "%Y-%m-%dT%H:%M:%S")
        elif len(now) == 10:
            now = now + "T00:00:00"
            str_date = datetime.strptime(now, "%Y-%m-%dT%H:%M:%S")
        elif ' ' in now and len(now) == 19:
            now = now.replace(" ", "T")
            str_date = datetime.strptime(now, "%Y-%m-%dT%H:%M:%S")
        else:
            now = datetime.now()
            now = str(now).replace(" ", "T")
            str_date = datetime.strptime(now, "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        now = datetime.now()
        now = str(now).replace(" ", "T")
        str_date = datetime.strptime(now, "%Y-%m-%dT%H:%M:%S")

    timestamp = str(datetime.timestamp(str_date))
    if '.' in timestamp:
        timestamp = timestamp.split('.')[0]
    if len(timestamp) == 10:
        timestamp = timestamp + "000"
    return int(timestamp)


def parse_resource(result):
    # Labels
    labels = []
    for lbl in result.get('labels', []):
        label = {"id": lbl.get("id"), "name": lbl.get("name"), "type": lbl.get("type")}
        labels.append(label)
    result["labels"] = labels

    if "module_id" in result:
        del result["module_id"]
    if "module_name" in result:
        del result["module_name"]
    if "module_short_name" in result:
        del result["module_short_name"]
    if "module_type" in result:
        del result["module_type"]

    return result


def parse_label(result):
    labels = []

    for label in result:
        labels.append({"BackgroundColor": label["bgColorHex"], "Id": label["id"], "Name": label["label"],
                       "Protected": label["labelProtected"], "TypeId": label["labelTypeId"],
                       "TypeName": label["labelTypeName"], "Prioritized": label["prioritized"],
                       "TextColor": label["textColorHex"]})

    return labels


def get_all_resources(client: Client, args):
    result = client.resource_select(args)
    total_resources = result['total_resources']

    if total_resources > 0:
        resources_array = []
        for r in result['list']:
            resource = parse_resource(r)
            resources_array.append(resource)

        return_results({
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': resources_array,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown("Blueliv " + client.module_type + " info", resources_array),
            'EntryContext': {'BluelivThreatCompass.' + client.module_type + '(val.id && val.id == obj.id)':
                             resources_array
                             }
        })
    else:
        not_found()


def set_resource_read_status(client: Client, args):
    client.resource_read_result(args)
    return_results({
        'ContentsFormat': formats['text'],
        'Type': entryTypes['note'],
        'Contents': "Read status changed to {}.".format(args.get("read", 0)),
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': "Read status changed to **{}**.".format(args.get("read", 0)),
    })


def set_resource_rating(client: Client, args):
    client.resource_rating(args)
    return_results({
        'ContentsFormat': formats['text'],
        'Type': entryTypes['note'],
        'Contents': "Rating changed to {}.".format(args.get("rating", 0)),
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': "Rating changed to **{}**.".format(args.get("rating", 0)),
    })


def get_resources_fetch(client: Client, ini_date, page, limit, status):
    args = {"page": page, "limit": limit, "since": ini_date, "status": status}
    result = client.resource_select(args)

    total_resources = result['total_resources']
    if total_resources > 0:
        return result['list']
    else:
        return []


def fetch_incidents(client: Client, last_run, first_fetch_time, fetch_limit, fetch_status):
    search_offset = demisto.getLastRun().get('offset', 0)

    last_fetch = last_run.get('last_fetch', None)
    if last_fetch is None:
        last_fetch = blueliv_date_to_timestamp(first_fetch_time)
    else:
        last_fetch = str(last_fetch)
        if len(last_fetch) == 10:
            last_fetch = last_fetch + "000"

    # convert the events to demisto incident
    events = get_resources_fetch(client, last_fetch, search_offset, fetch_limit, fetch_status)

    incidents = []
    for e in events:
        incident = {
            'name': e.get('title', ''),  # name is required field, must be set
            'occurred': timestamp_to_datestring(e.get('created_at', int(time.time()) * 1000)),  # needs ISO8601
            'rawJSON': json.dumps(e)  # the original event
        }
        incidents.append(incident)

    # Check if are there pending events to fetch
    offset = 0
    if len(incidents) < fetch_limit:
        last_run = int(round(time.time() * 1000))
    else:
        offset = search_offset + fetch_limit

    return incidents, {'last_fetch': last_run, 'offset': offset}


def search_resource(client: Client, args):
    result = client.resource_select(args)
    total_resources = result['total_resources']

    if total_resources > 0:
        resource = parse_resource(result)

        return_results({
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': resource["list"],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown("Blueliv " + client.module_type + " info", resource),
            'EntryContext': {'BluelivThreatCompass.' + client.module_type + '(val.id && val.id == obj.id)':
                             resource["list"]
                             }
        })
    else:
        not_found()


def search_resource_by_id(client: Client, args):
    result = client.resource_get(args)
    resource = parse_resource(result)

    if demisto.get(resource, "id"):
        return_results({
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': resource,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown("Blueliv " + client.module_type + " info", resource),
            'EntryContext': {'BluelivThreatCompass.' + client.module_type + '(val.id && val.id == obj.id)': resource}
        })
    else:
        not_found()


def resource_set_tlp(client: Client, args):
    client.resource_set_tlp(args)
    return_results({
        'ContentsFormat': formats['text'],
        'Type': entryTypes['note'],
        'Contents': "TLP changed to {}.".format(args.get("tlp")),
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': "TLP changed to **{}**".format(args.get("tlp")),
    })


def set_resource_status(client: Client, args):
    client.resource_user_result(args)
    return_results({
        'ContentsFormat': formats['text'],
        'Type': entryTypes['note'],
        'Contents': "Status changed to {}.".format(args.get("status")),
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': "Status changed to **{}**".format(args.get("status")),
    })


def resource_add_label(client: Client, args):
    client.resource_label(args)
    return_results({
        'ContentsFormat': formats['text'],
        'Type': entryTypes['note'],
        'Contents': "Label {} correctly added.".format(args.get("labelId", 0)),
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': "Label **{}** correctly added.".format(args.get("labelId", 0)),
    })


def resource_fav(client: Client, args):
    client.resource_fav(args)
    return_results({
        'ContentsFormat': formats['text'],
        'Type': entryTypes['note'],
        'Contents': "Resource favourite masked as {} correctly.".format(args.get("favourite", "group")),
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': "Resource favourite masked as **{}** correctly.".format(args.get("favourite", "group")),
    })


def module_get_labels(client: Client):
    res = client.module_get_labels()
    label_array = parse_label(res)

    return_results({
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': res,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown("Blueliv " + client.module_type + " labels", label_array),
        'EntryContext': {'BluelivThreatCompass.Label(val.Id && val.Id == obj.Id)': label_array}
    })


def test_module(client: Client):
    try:
        res = client.test_module_connection()
        if 'total_resources' not in res:
            return_error(message="Error connecting to module.")
    except DemistoException as exception:
        return_error(message="Error connecting to module.\nPlease check that organization ID, "
                             + "module ID and module type matches.", error=exception)


# DEMISTO command evaluation
def main():
    urllib3.disable_warnings()

    params = demisto.params()
    server_url = params.get('url').rstrip("/")
    verify_ssl = not params.get('unsecure', False)
    proxy = params.get('proxy')
    username = params['credentials']['identifier']
    password = params['credentials']['password']
    organization = params.get('organization', 0)
    module = params.get('module', 0)
    module_type = params.get('type', 0)

    client = Client(server_url, verify_ssl, proxy, headers={'Accept': 'application/json'},
                    organization=organization, module=module, module_type=module_type)
    client.authenticate(username, password)

    args = demisto.args()
    if demisto.command() == 'test-module':
        # Checks if the user is correctly authenticated and organization, module & module_type are correct
        test_module(client)
        return_results("ok")

    elif demisto.command() == 'fetch-incidents':
        last_run = demisto.getLastRun()
        first_fetch_time = demisto.params().get('first_fetch_time', "0000-00-00")
        fetch_limit = max(min(200, int(demisto.params().get("fetch_limit"))), 1)
        fetch_status = demisto.params().get('fetch_status')
        fetch_status = ",".join(fetch_status)

        incidents, next_run = fetch_incidents(client, last_run, first_fetch_time, fetch_limit, fetch_status)
        demisto.setLastRun(next_run)
        demisto.incidents(incidents)

    elif demisto.command() == 'blueliv-resource-search':
        search_resource(client, args)

    elif demisto.command() == 'blueliv-resource-search-by-id':
        search_resource_by_id(client, args)

    elif demisto.command() == 'blueliv-resource-set-status':
        set_resource_status(client, args)

    elif demisto.command() == 'blueliv-resource-set-label':
        resource_add_label(client, args)

    elif demisto.command() == 'blueliv-resource-all':
        get_all_resources(client, args)

    elif demisto.command() == 'blueliv-resource-set-read-status':
        set_resource_read_status(client, args)

    elif demisto.command() == 'blueliv-resource-assign-rating':
        set_resource_rating(client, args)

    elif demisto.command() == 'blueliv-resource-favourite':
        resource_fav(client, args)

    elif demisto.command() == 'blueliv-resource-set-tlp':
        resource_set_tlp(client, args)

    elif demisto.command() == 'blueliv-module-get-labels':
        module_get_labels(client)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
