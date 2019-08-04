import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''
import datetime
import requests
import json

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' ************************** '''
''' *****GLOBAL VARIABLES***** '''
''' ************************** '''

SERVER_URL = demisto.params()['serverUrl']
API_URL = SERVER_URL + "/api"
API_TOKEN_URL = API_URL + "/token"
CLIENT_ID = demisto.params()['client_id']
EMAIL = demisto.getParam('credentials').get('identifier')
PASSWORD = demisto.getParam('credentials').get('password')
USE_SSL = not demisto.params().get('insecure', False)
THRESHOLD = int(demisto.params().get('threshold'))

REGEX_MAP = {
    'ipv4': re.compile(ipv4Regex, regexFlags),
    'ipv6': re.compile(r"", regexFlags),
    'email': re.compile(emailRegex, regexFlags),
    'url': re.compile(urlRegex, regexFlags),
    'md5': re.compile(r'\b[0-9a-fA-F]{32}\b', regexFlags),
    'sha1': re.compile(r'\b[0-9a-fA-F]{40}\b', regexFlags),
    'sha256': re.compile(r'\b[0-9a-fA-F]{64}\b', regexFlags)
}

IOC_MAP = {
    'ip': ['IP Address', 'IPv6 Address'],
    'url': ['URL'],
    'file': ['MD5', 'SHA-1', 'SHA256'],
    'email': ['Email Address'],
    'domain': ['FQDN']
}

DBOTSCORE_TYPES = {
    'IP Address': 'ip',
    'IPv6 Address': 'ip',
    'Email Address': 'email',
    'URL': 'url',
    'MD5': 'file',
    'SHA-1': 'file',
    'SHA-256': 'file',
    'FQDN': 'domain'
}

STATUS_MAP = {
    1: "Active",
    2: "Expired",
    3: "Indirect",
    4: "Review",
    5: "Whitelisted"
}

IOCTYPE_MAP = {
    1: "Binary String",
    2: "CIDR Block",
    3: "CVE",
    4: "Email Address",
    5: "Email Attachment",
    6: "Email Subject",
    7: "File Mapping",
    8: "File Path",
    9: "Filename",
    10: "FQDN",
    11: "Fuzzy Hash",
    12: "GOST Hash",
    13: "Hash ION",
    14: "IP Address",
    15: "IPv6 Address",
    16: "MD5",
    17: "Mutex",
    18: "Password",
    19: "Registry Key",
    20: "Service Name",
    21: "SHA-1",
    22: "SHA-256",
    23: "SHA-384",
    24: "SHA-512",
    25: "String",
    26: "x509 Serial",
    27: "x509 Subject",
    28: "URL",
    29: "URL Path",
    30: "User-agent",
    31: "Username",
    32: "X-Mailer",
}

EVENTTYPE_MAP = {
    1: "Spearphish",
    2: "Watering Hole",
    3: "SQL Injection Attack",
    4: "DoS Attack",
    5: "Malware",
    6: "Watchlist",
    7: "Command and Control",
    8: "Anonymization",
    9: "Exfiltration",
    10: "Host Characteristics",
    11: "Compromised PKI Certificate",
    12: "Login Compromise",
    13: "Incident"
}

HEADERS = {
    "indicator": ["ID", "IndicatorType", "Value", "Description", "Status",
                  "TQScore", "CreatedAt", "UpdatedAt", "DBotScore", "URL"],
    "adversary": ["ID", "Name", "CreatedAt", "UpdatedAt", "URL"],
    "event": ["ID", "EventType", "Title", "Description", "Occurred", "CreatedAt", "UpdatedAt", "URL"],
    "attributes": ["ID", "Name", "Value"],
    "sources": ["ID", "Name"]
}

SEARCH_OBJECT = 0
SEARCH_TWO_OBJS = 1
SEARCH_PIVOT = 2
SEARCH_ATTRIBUTE = 3
UNLINK_OBJS = 4

ERRORS_MAP = {
    SEARCH_OBJECT: "Object was not found.",
    SEARCH_TWO_OBJS: "One of the objects was not found.",
    SEARCH_PIVOT: "Objects are not linked.",
    SEARCH_ATTRIBUTE: "Attribute was not found.",
    UNLINK_OBJS: "Could not unlink the objects."
}

DIRECTORY_MAP = {
    "indicator": "indicators",
    "adversary": "adversaries",
    "event": "events"
}


''' ************************** '''
''' *****HELPER FUNCTIONS***** '''
''' ************************** '''


''' AUTHORIZARION FUNCTIONS '''


def get_errors_string_from_bad_request(bad_request_results):
    errors_list = bad_request_results.json().get("errors", [])
    errors_string = ""
    error_num = 1
    if errors_list:
        errors_string = "Errors from server: \n"
        for error in errors_list:
            errors_string += "Error #{0}: {1}\n".format(error_num, error)
            error_num += 1
    return errors_string


# ThreatQ auth based on OAuth 2.0 credential grand method
def get_tq_access_token():
    data = {'grant_type': 'password', 'email': EMAIL, 'password': PASSWORD, 'client_id': CLIENT_ID}
    access_token_response = requests.post(API_TOKEN_URL, data=data, verify=False, allow_redirects=False)

    tokens = json.loads(access_token_response.text)
    if int(access_token_response.status_code) >= 400:
        errors_string = get_errors_string_from_bad_request(access_token_response)
        error_message = "Authentication failed, unable to retrieve an access token.\n {}".format(errors_string)
        return_error(error_message)

    new_integration_context = {
        "access_token": tokens['access_token'],
        "access_token_creation_time": int(time.time()) - 1,  # decrementing one second to be on the safe side
        "access_token_expires_in": tokens['expires_in']
    }
    demisto.setIntegrationContext(new_integration_context)
    tok = tokens['access_token']
    return tok


def access_token_not_expired():
    epoch_time_now = time.time()
    epoch_time_when_token_granted = demisto.getIntegrationContext().get("access_token_creation_time")
    token_time_until_expiration = demisto.getIntegrationContext().get("access_token_expires_in")
    return int(epoch_time_now) - int(epoch_time_when_token_granted) < int(token_time_until_expiration)


def get_access_token():
    existing_access_token = demisto.getIntegrationContext().get("access_token")
    if existing_access_token and access_token_not_expired():
        return existing_access_token
    else:
        new_access_token = get_tq_access_token()
        return new_access_token


''' COMMANDS HELPER FUNCTIONS '''


def tq_request(method, url_suffix, params=None, func=None, files=None):
    access_token = get_access_token()
    api_call_headers = {'Authorization': 'Bearer ' + access_token}
    res = None

    if method == "GET":
        res = requests.get(API_URL + url_suffix, headers=api_call_headers, verify=False)
    elif method == "POST":
        res = requests.post(API_URL + url_suffix, data=json.dumps(params), headers=api_call_headers, verify=False,
                            files=files)
    elif method == "PUT":
        res = requests.put(API_URL + url_suffix, data=json.dumps(params), headers=api_call_headers, verify=False)
    elif method == "DELETE":
        res = requests.delete(API_URL + url_suffix, data=json.dumps(params), headers=api_call_headers, verify=False)

    check_errors(res, func)

    if method != "DELETE":
        return json.loads(res.text)


def check_errors(res, func=None):
    if res.status_code == 400:
        if func is not None:
            return_error(ERRORS_MAP[func])
        else:
            return_error(pull_errors_from_response(json.loads(res.text)))
    elif res.status_code == 404:
        if func is not None:
            return_error(ERRORS_MAP[func])
        return_error("Error 404 - Object not found.")
    elif res.status_code == 500:
        return_error("Error 500 - Could not complete the request.")


def pull_errors_from_response(res):
    errors_str = "Error 400 - Could not complete the request."  # default error
    errors = None
    if "data" in res:
        errors = res["data"]["errors"]
    if "errors" in res:
        errors = res["errors"]
    if isinstance(errors, list):
        errorslst = ["\n".join(lst) for lst in errors]
        errors_str = "\n".join(errorslst)
    elif isinstance(errors, dict):
        errorslst = ["\n".join(lst) for lst in errors.values()]
        errors_str = "\n".join(errorslst)
    return errors_str


def get_dbot_context(indicator, ind_type, ind_score):
    """ This function converts a TQ scoring value of an indicator into a DBot score.

    Args:
        indicator (str): The indicator name
        ind_type (str): The indicator type
        ind_score (int): The indicator TQ score

    Returns:
        (dict). The indicator's DBotScore.

    """
    #  Score mapping function: [0,3] -> 1, [4,7] -> 2, [8,10] -> 3
    dbot_score = ind_score // 4 + 1 if ind_score != -1 else 0

    return {
        'Vendor': 'ThreatQ',
        'Indicator': indicator,
        'Type': ind_type,
        'Score': 3 if ind_score >= THRESHOLD else dbot_score
    }


def get_tq_score(score_data):
    if isinstance(score_data, dict):
        gen_score = score_data["generated_score"]
        manual_score = score_data["manual_score"] if score_data["manual_score"] is not None else 0
        return max(float(gen_score), float(manual_score))
    else:
        return float(score_data)


def clean_html(raw_html):
    """ This function receives an HTML string of a text, and retrieves a clean string of its content.

    Args:
        raw_html: An HTML format text

    Returns:
        (string). A clean text
    """
    if not raw_html:
        return None
    clean_r = re.compile('<.*?>')
    clean_text = re.sub(clean_r, '', raw_html)
    return clean_text


def get_sources_array(sources):
    if not sources:
        return []
    if not isinstance(sources, list):
        sources = sources.split(',')
    return [{"name": source} for source in sources]


def get_attrs_array(attrs, vals):
    if not attrs and not vals:
        return []
    if not attrs or not vals:
        return_error("Invalid input: attr_lst and attr_vals should have the same length")
    if not isinstance(attrs, list):
        attrs = attrs.split(',')
    if not isinstance(vals, list):
        vals = vals.split(',')
    if len(attrs) != len(vals):
        return_error("Invalid input: attr_lst and attr_vals should have the same length")

    return [{"name": name, "value": val} for name, val in zip(attrs, vals)]


def parse_date(text):
    """
        Returns a date string in ISO 6801 format.

        :type text: ``str``
        :param text: A string represents a date in one of the formats presented in fmts list.

        :return: A date in ISO 6801 format.
        :rtype: ``str``
    """
    fmts = ['%m-%d-%Y %H:%M:%S', '%m/%d/%Y %H:%M:%S', '%m.%d.%Y %H:%M:%S', '%m-%d-%Y', '%m/%d/%Y', '%m.%d.%Y']
    for fmt in fmts:
        try:
            return str(datetime.datetime.strptime(text, fmt))
        except ValueError:
            pass
    return_error("Time data '{0}' does not match any valid format.".format(text))


def filter_dicts(lst, attributes=False):
    if attributes:
        return [{"Name": elem["name"], "Value": elem["value"], "ID": elem["id"]} for elem in lst]
    else:  # sources
        return [{"Name": elem["name"], "ID": None if "pivot" not in elem else elem["pivot"]["id"]} for elem in lst]


def data_to_demisto_format(data, obj_type):
    if obj_type == "indicator":
        return indicator_data(data)
    elif obj_type == "event":
        return event_data(data)
    elif obj_type == "adversary":
        return adversary_data(data)


def indicator_data(data):
    if isinstance(data, list):
        data = data[0]
    return {
        "Type": "indicator",
        "ID": data["id"],
        "Sources": None if "sources" not in data else filter_dicts(data["sources"]),
        "Attributes": None if "attributes" not in data else filter_dicts(data["attributes"], True),
        "UpdatedAt": data["updated_at"],
        "CreatedAt": data["created_at"],
        "Description": None if "description" not in data else clean_html(data["description"]),
        "Value": data["value"],
        "Status": STATUS_MAP[data["status_id"]],
        "IndicatorType": IOCTYPE_MAP[data["type_id"]],
        "TQScore": None if "score" not in data else get_tq_score(data["score"]),
        "URL": "{0}/indicators/{1}/details".format(SERVER_URL, data['id'])
    }


def adversary_data(data):
    if isinstance(data, list):
        data = data[0]
    return {
        "Type": "adversary",
        "ID": data["id"],
        "Sources": None if "sources" not in data else filter_dicts(data["sources"]),
        "Attributes": None if "attributes" not in data else filter_dicts(data["attributes"], True),
        "UpdatedAt": data["updated_at"],
        "CreatedAt": data["created_at"],
        "Name": data["name"],
        "URL": "{0}/indicators/{1}/details".format(SERVER_URL, data['id'])
    }


def event_data(data):
    if isinstance(data, list):
        data = data[0]
    return {
        "Type": "event",
        "ID": data["id"],
        "Sources": None if "sources" not in data else filter_dicts(data["sources"]),
        "Attributes": None if "attributes" not in data else filter_dicts(data["attributes"], True),
        "UpdatedAt": data["updated_at"],
        "CreatedAt": data["created_at"],
        "Description": None if "description" not in data else clean_html(data["description"]),
        "Title": data["title"],
        "Occurred": data["happened_at"],
        "EventType": EVENTTYPE_MAP[data["type_id"]],
        "URL": "{0}/indicators/{1}/details".format(SERVER_URL, data['id'])
    }


def get_pivot_id(obj1_type, obj1_id, obj2_type, obj2_id):
    url_suffix = "/{0}/{1}/{2}".format(DIRECTORY_MAP[obj1_type], obj1_id, DIRECTORY_MAP[obj2_type])
    res = tq_request("GET", url_suffix, func=SEARCH_PIVOT)

    for conn in res["data"]:
        if int(conn["id"]) != int(obj2_id):
            continue
        return int(conn["pivot"]["id"])


def mark_as_malicious(generic_context, dbotscore):
    if dbotscore == 3:
        generic_context["Malicious"] = {
            "Vendor": "ThreatQ",
            "Description": "High risk"
        }


def validate_ioc(val, *format_types):
    for fmt in format_types:
        if REGEX_MAP[fmt].match(val):
            return fmt
    return_error("Argument {0} is not valid.".format(val))


def get_ioc_reputation(keyword, ioc_type):
    # search for the IOC ID
    url_suffix = "/search?query={0}&limit=1".format(keyword)
    res = tq_request("GET", url_suffix, SEARCH_OBJECT)

    if not res["data"]:
        raw = {}
        dbot = get_dbot_context(keyword, ioc_type, -1)  # set dbot score to 0
        return raw, dbot

    # search for detailed information about the IOC
    url_suffix = "/indicators/{0}?with=attributes,sources,score,type".format(res['data'][0]['id'])
    res = tq_request("GET", url_suffix)

    raw = data_to_demisto_format(res["data"], "indicator")

    # Update the EntryContext
    dbot = get_dbot_context(raw["Value"], DBOTSCORE_TYPES[raw["IndicatorType"]], raw["TQScore"])
    raw["DBotScore"] = dbot["Score"]

    return raw, dbot


def set_ioc_entry_context(ioc_type, raw, dbot, generic):
    mark_as_malicious(generic, dbot["Score"])
    ec = {
        outputPaths[ioc_type]: generic,
        'DBotScore': dbot
    }
    if raw:
        ec['ThreatQ(val.ID === obj.ID && val.Type === obj.Type)'] = raw
    return ec


def build_readable(title, obj_type, raw):
    if "Related" not in raw.keys():
        readable = tableToMarkdown(title, raw, headers=HEADERS[obj_type], headerTransform=pascalToSpace,
                                   removeNull=True)
        if "Attributes" in raw:
            readable += tableToMarkdown("Attributes", raw["Attributes"], headers=HEADERS["attributes"],
                                        removeNull=True)
        if "Sources" in raw:
            readable += tableToMarkdown("Sources", raw["Sources"], headers=HEADERS["sources"],
                                        removeNull=True)
        # set URL in markdown format:
        if "URL" in raw:
            readable = readable.replace(raw["URL"], "[{0}]({1})".format(raw['URL'], raw['URL']))
    else:
        # in get-related-objs commands, we won't show attributes and sources (as same as the UI)
        readable = tableToMarkdown(title, raw["Related"], headers=HEADERS[obj_type], headerTransform=pascalToSpace,
                                   removeNull=True)
        # set URL in markdown format:
        for elem in raw["Related"]:
            readable = readable.replace(elem["URL"], "[{0}]({1})".format(elem['URL'], elem['URL']))

    # not relevant under ThreatQ - was there only for the readable
    if "DBotScore" in raw.keys():
        raw.pop("DBotScore")
    return readable


''' COMMANDS '''


def test_module():
    token = get_tq_access_token()
    if token:
        demisto.results('ok')
    else:
        demisto.results('test failed')


def create_ioc_command(ioc_type, status, value, source_lst=None, attr_lst=None, attr_vals=None):
    if ioc_type not in IOCTYPE_MAP.values():
        return_error("Invalid indicator type.")

    params = {
        "type": ioc_type,
        "status": status,
        "value": value,
        "sources": get_sources_array(source_lst),
        "attributes": get_attrs_array(attr_lst, attr_vals)
    }
    res = tq_request("POST", "/indicators", params)

    raw = data_to_demisto_format(res["data"], "indicator")
    entry_context = {'ThreatQ(val.ID === obj.ID && val.Type === obj.Type)': createContext(raw, removeNull=True)}
    readable = build_readable("Successfully created {0} {1}".format(ioc_type, value), "indicator", raw)

    return_outputs(readable, entry_context, raw)


def create_adversary_command(name, source_lst=None, attr_lst=None, attr_vals=None):
    params = {
        "name": name,
        "sources": get_sources_array(source_lst),
        "attributes": get_attrs_array(attr_lst, attr_vals)
    }
    res = tq_request("POST", "/adversaries", params)

    raw = data_to_demisto_format(res["data"], "adversary")
    entry_context = {'ThreatQ(val.ID === obj.ID && val.Type === obj.Type)': createContext(raw, removeNull=True)}
    readable = build_readable("Successfully created adversary {0}".format(name), "adversary", raw)

    return_outputs(readable, entry_context, raw)


def create_event_command(event_type, title, date, source_lst=None, attr_lst=None, attr_vals=None):
    params = {
        "title": title,
        "type": event_type,
        "happened_at": parse_date(date),
        "sources": get_sources_array(source_lst),
        "attributes": get_attrs_array(attr_lst, attr_vals)
    }
    res = tq_request("POST", "/events", params)

    raw = data_to_demisto_format(res["data"], "event")
    entry_context = {'ThreatQ(val.ID === obj.ID && val.Type === obj.Type)': createContext(raw, removeNull=True)}
    readable = build_readable("Successfully created event {0}".format(title), "event", raw)

    return_outputs(readable, entry_context, raw)


def delete_object_command(obj_type, obj_id):
    if isinstance(obj_id, str) and not obj_id.isdigit():
        return_error("Invalid argument fot object ID.")

    url_suffix = "/{0}/{1}".format(DIRECTORY_MAP[obj_type], obj_id)
    tq_request("DELETE", url_suffix, SEARCH_OBJECT)
    demisto.results("Successfully deleted {0} #{1}.".format(obj_type, obj_id))


def search_by_name_command(keyword, limit):
    """ This function searches for objects by a keyword and returns their id and type.

    Returns:
        (dict). A list of dictionaries contain the objects' types, IDs and values.
    """
    url_suffix = "/search?query={0}&limit={1}".format(keyword, limit)
    res = tq_request("GET", url_suffix, SEARCH_OBJECT)

    raw = [{"ID": e["id"], "Type": e["object"], "Value": e["value"]} for e in res["data"]]
    entry_context = {'ThreatQ(val.ID === obj.ID && val.Type === obj.Type)': raw} if raw else None

    human_readable = tableToMarkdown("Search results", raw)
    return_outputs(human_readable, entry_context, raw)


def search_by_id_command(obj_type, obj_id, returns_output=True, func=None):
    """ This function searches an object by its type and ID.

    Returns:
        The object's details (depend on its type).
    """
    if isinstance(obj_id, str) and not obj_id.isdigit():
        return_error("Invalid argument for object ID.")

    url_suffix = "/{0}/{1}?with=attributes,sources".format(DIRECTORY_MAP[obj_type], obj_id)
    if obj_type == "indicator":
        url_suffix += ",score,type"

    res = tq_request("GET", url_suffix, func=func)
    raw = data_to_demisto_format(res["data"], obj_type)

    if not returns_output:
        return raw

    # Update the EntryContext
    ec = {}
    if obj_type == "indicator" and raw["Type"] in DBOTSCORE_TYPES.keys():
        dbot = get_dbot_context(raw["Value"], DBOTSCORE_TYPES[raw["IndicatorType"]], raw["TQScore"])
        raw["DBotScore"] = dbot["Score"]
        ec['DBotScore'] = dbot
    if raw:
        ec['ThreatQ(val.ID === obj.ID && val.Type === obj.Type)'] = createContext(raw, removeNull=True)

    readable = build_readable("Search results for {0} #{1}".format(obj_type, obj_id), obj_type, raw)

    return_outputs(readable, ec, raw)


def get_related_objs_command(related_type, obj_type, obj_id):
    if isinstance(obj_id, str) and not obj_id.isdigit():
        return_error("Invalid argument for object ID.")

    # returns error if object does not exist
    search_by_id_command(obj_type, obj_id, returns_output=False)

    url_suffix = "/{0}/{1}/{2}?with=attributes".format(DIRECTORY_MAP[obj_type], obj_id, DIRECTORY_MAP[related_type])
    url_suffix += ",score" if related_type == "indicator" else ",sources"
    res = tq_request("GET", url_suffix)

    info = [data_to_demisto_format(obj, related_type) for obj in res["data"]]
    raw = {
        "Related": createContext(info, removeNull=True),
        "ID": int(obj_id),
        "Type": obj_type
    }
    ec = {'ThreatQ(val.ID === obj.ID && val.Type === obj.Type)': raw} if info else {}
    readable = build_readable("Search results for {0} #{1}".format(obj_type, obj_id), related_type, raw)

    return_outputs(readable, ec, raw)


def link_objects_command(obj1_id, obj1_type, obj2_id, obj2_type):
    if isinstance(obj1_id, str) and not obj1_id.isdigit() or isinstance(obj2_id, str) and not obj2_id.isdigit():
        return_error("Invalid argument for one of the objects' ID.")

    if obj1_type == obj2_type and obj1_id == obj2_id:
        return_error("Cannot link an object to itself.")

    # returns error if one of the objects does not exist
    search_by_id_command(obj1_type, obj1_id, returns_output=False, func=SEARCH_TWO_OBJS)
    search_by_id_command(obj2_type, obj2_id, returns_output=False, func=SEARCH_TWO_OBJS)

    url_suffix = "/{0}/{1}/{2}".format(DIRECTORY_MAP[obj1_type], obj1_id, DIRECTORY_MAP[obj2_type])
    params = {
        "id": obj2_id
    }
    tq_request("POST", url_suffix, params)
    demisto.results("Successfully linked {0} #{1} and {2} #{3}.".format(obj1_type, obj1_id, obj2_type, obj2_id))


def unlink_objects_command(obj1_id, obj1_type, obj2_id, obj2_type):
    if isinstance(obj1_id, str) and not obj1_id.isdigit() or isinstance(obj2_id, str) and not obj2_id.isdigit():
        return_error("Invalid argument for one of the objects' ID.")

    if obj1_type == obj2_type and obj1_id == obj2_id:
        return_error("An object cannot be linked to itself.")

    # returns error if one of the objects does not exist
    search_by_id_command(obj1_type, obj1_id, returns_output=False, func=SEARCH_TWO_OBJS)
    search_by_id_command(obj2_type, obj2_id, returns_output=False, func=SEARCH_TWO_OBJS)

    p_id = get_pivot_id(obj1_type, obj1_id, obj2_type, obj2_id)
    url_suffix = "/{0}/{1}/{2}".format(DIRECTORY_MAP[obj1_type], obj1_id, DIRECTORY_MAP[obj2_type])

    tq_request("DELETE", url_suffix, params=[p_id], func=UNLINK_OBJS)
    demisto.results("Successfully unlinked {0} #{1} and {2} #{3}.".format(obj1_type, obj1_id, obj2_type, obj2_id))


def add_source_command(source, obj_id, obj_type):
    if isinstance(obj_id, str) and not obj_id.isdigit():
        return_error("Invalid argument for object ID.")
    search_by_id_command(obj_type, obj_id, returns_output=False)  # returns error if object was not found

    url_suffix = "/{0}/{1}/sources".format(DIRECTORY_MAP[obj_type], obj_id)
    params = {
        "name": source
    }

    tq_request("POST", url_suffix, params)
    demisto.results("Successfully added source {0} to {1} #{2}.".format(source, obj_type, obj_id))


def delete_source_command(source, obj_id, obj_type):
    if isinstance(obj_id, str) and not obj_id.isdigit():
        return_error("Invalid argument for object ID.")

    res = search_by_id_command(obj_type, obj_id, returns_output=False)  # returns error if object was not found
    sources = [s for s in res["Sources"] if s["Name"] == source]
    if not sources:
        return_error("Source {0} does not exist in {1} #{2}.".format(source, obj_type, obj_id))

    url_suffix = "/{0}/{1}/sources/{2}".format(DIRECTORY_MAP[obj_type], obj_id, sources[0]['ID'])
    demisto.results(url_suffix)
    tq_request("DELETE", url_suffix)
    demisto.results("Successfully deleted source {0} from {1} #{2}.".format(source, obj_type, obj_id))


def add_attr_command(attr_name, attr_value, obj_type, obj_id):
    if isinstance(obj_id, str) and not obj_id.isdigit():
        return_error("Invalid argument for object ID.")
    search_by_id_command(obj_type, obj_id, returns_output=False)  # returns error if object was not found

    url_suffix = "/{0}/{1}/attributes".format(DIRECTORY_MAP[obj_type], obj_id)
    params = {
        "name": attr_name,
        "value": attr_value
    }

    tq_request("POST", url_suffix, params)
    demisto.results("Successfully added attribute to {0} #{1}.".format(obj_type, obj_id))


def modify_attr_command(attr_id, attr_value, obj_type, obj_id):
    if isinstance(obj_id, str) and not obj_id.isdigit():
        return_error("Invalid argument for object ID.")
    if isinstance(attr_id, str) and not attr_id.isdigit():
        return_error("Invalid argument for attribute ID.")
    search_by_id_command(obj_type, obj_id, returns_output=False)  # returns error if object was not found

    url_suffix = "/{0}/{1}/attributes/{2}".format(DIRECTORY_MAP[obj_type], obj_id, attr_id)
    params = {"value": attr_value}

    tq_request("PUT", url_suffix, params)
    demisto.results("Successfully modified attribute #{0} of {1} #{2}.".format(attr_id, obj_type, obj_id))


def delete_attr_command(attr_id, obj_id, obj_type):
    if isinstance(obj_id, str) and not obj_id.isdigit():
        return_error("Invalid argument for object ID.")
    if isinstance(attr_id, str) and not attr_id.isdigit():
        return_error("Invalid argument for attribute ID.")
    search_by_id_command(obj_type, obj_id, returns_output=False)  # returns error if object was not found

    url_suffix = "/{0}/{1}/attributes/{2}".format(DIRECTORY_MAP[obj_type], obj_id, attr_id)

    tq_request("DELETE", url_suffix)
    demisto.results("Successfully deleted attribute #{0} from {1} #{2}.".format(attr_id, obj_type, obj_id))


def upload_file_command():
    try:
        file_info = demisto.getFilePath("825@9da8d636-cf30-42c2-8263-d09f5268be8a")
        files = {'file': (file_info['name'], open(file_info['path'], 'rb'))}
        access_token = get_access_token()
        api_call_headers = {'Authorization': 'Bearer ' + access_token}
        requests.post(API_URL + '/attachments', headers=api_call_headers, verify=False, files=files)
    except Exception:
        return_error("Entry does not contain a file.")

    # return_error(res.status_code)

    '''params = {
        "name": "filetest.rtf",
        "title": "filetest.rtf",
        "type_id": "2",
        "malware_locked": "0",
        "tlp": {
            "name": "GREEN"
        }
    }

    res = tq_post_request('/attachments', params)
    if res.status_code >= 400:
        return_error('Could not upload file.')'''


def update_status_command(ioc_id, status):
    if isinstance(ioc_id, str) and not ioc_id.isdigit():
        return_error("Invalid argument for indicator ID.")

    search_by_id_command("indicator", ioc_id, returns_output=False)  # returns error if object was not found

    url_suffix = "/indicators/{0}".format(ioc_id)
    params = {"status": status}

    tq_request("PUT", url_suffix, params)
    demisto.results("Successfully updated indicator #{0}'s status to {1}.".format(ioc_id, status))


def get_ip_reputation(ip):
    validate_ioc(ip, 'ipv4')  # todo: add ipv6 when there is a validation
    generic = {"Address": ip}
    raw, dbot = get_ioc_reputation(ip, 'ip')
    entry_context = set_ioc_entry_context('ip', raw, dbot, generic)
    readable = build_readable("Search results for IP {0}".format(ip), "indicator", raw)
    return_outputs(readable, entry_context, raw)


def get_url_reputation(url):
    validate_ioc(url, 'url')
    generic = {"Data": url}
    raw, dbot = get_ioc_reputation(url, 'ip')
    entry_context = set_ioc_entry_context('url', raw, dbot, generic)
    readable = build_readable("Search results for URL {0}".format(url), "indicator", raw)
    return_outputs(readable, entry_context, raw)


def get_email_reputation(email):
    validate_ioc(email, 'email')
    generic = {"Address": email}
    raw, dbot = get_ioc_reputation(email, 'email')
    entry_context = set_ioc_entry_context('email', raw, dbot, generic)
    readable = build_readable("Search results for email address {0}".format(email), "indicator", raw)
    return_outputs(readable, entry_context, raw)


def get_domain_reputation(domain):
    # fmt = validate_ioc(domain, 'domain')  # todo: add validation
    generic = {"Name": domain}
    raw, dbot = get_ioc_reputation(domain, 'domain')
    entry_context = set_ioc_entry_context('domain', raw, dbot, generic)
    readable = build_readable("Search results for domain {0}".format(domain), "indicator", raw)
    return_outputs(readable, entry_context, raw)


def get_file_reputation(file):
    fmt = validate_ioc(file, 'md5', 'sha1', 'sha256')
    generic = createContext({
        "MD5": file if fmt == 'md5' else None,
        "SHA1": file if fmt == 'sha1' else None,
        "SHA256": file if fmt == 'sha256' else None
    }, removeNull=True)
    raw, dbot = get_ioc_reputation(file, 'file')
    entry_context = set_ioc_entry_context('file', raw, dbot, generic)
    readable = build_readable("Search results for file {0}".format(file), "indicator", raw)
    return_outputs(readable, entry_context, raw)


''' EXECUTION CODE '''
handle_proxy()
command = demisto.command()
LOG('command is {0}'.format(demisto.command()))
try:
    args = demisto.args()
    if command == 'test-module':
        test_module()
    elif command == 'tq-search-by-name':
        search_by_name_command(**args)
    elif command == 'tq-search-by-id':
        search_by_id_command(**args)
    elif command == 'tq-create-ioc':
        create_ioc_command(**args)
    elif command == 'tq-create-event':
        create_event_command(**args)
    elif command == 'tq-create-adversary':
        create_adversary_command(**args)
    elif command == 'tq-delete-object':
        delete_object_command(**args)
    elif command == 'tq-get-related-ioc':
        get_related_objs_command("indicator", **args)
    elif command == 'tq-get-related-events':
        get_related_objs_command("event", **args)
    elif command == 'tq-get-related-adversaries':
        get_related_objs_command("adversary", **args)
    elif command == 'tq-link-objects':
        link_objects_command(**args)
    elif command == 'tq-unlink-objects':
        unlink_objects_command(**args)
    elif command == 'tq-add-source':
        add_source_command(**args)
    elif command == 'tq-delete-source':
        delete_source_command(**args)
    elif command == 'tq-add-attr':
        add_attr_command(**args)
    elif command == 'tq-modify-attr':
        modify_attr_command(**args)
    elif command == 'tq-delete-attr':
        delete_attr_command(**args)
    elif command == 'tq-upload-file':
        upload_file_command()
    elif command == 'tq-update-status':
        update_status_command(**args)
    elif command == "ip":
        get_ip_reputation(**args)
    elif command == "domain":
        get_domain_reputation(**args)
    elif command == "email":
        get_email_reputation(**args)
    elif command == "url":
        get_url_reputation(**args)
    elif command == "file":
        get_file_reputation(**args)

except Exception as ex:
    raise
    return_error(ex)


# Params are of the type given in the integration page creation.
