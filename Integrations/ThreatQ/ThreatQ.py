import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''
import datetime
import requests
import json

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBAL VARIABLES '''

SERVER_URL = demisto.params()['serverUrl']
API_URL = SERVER_URL + "/api"
API_TOKEN_URL = API_URL + "/token"
CLIENT_ID = demisto.params()['client_id']
EMAIL = demisto.getParam('credentials').get('identifier')
PASSWORD = demisto.getParam('credentials').get('password')
USE_SSL = not demisto.params().get('insecure', False)
THRESHOLD = demisto.params().get('threshold')
if THRESHOLD:
    THRESHOLD = int(THRESHOLD)

domainRegex = r'(?:(?:https?|ftp|hxxps?):\/\/|www\[?\.\]?|ftp\[?\.\]?)(?:[-A-Z0-9]+\[?\.\]?)' \
               r'+[-A-Z0-9]+(?::[0-9]+)?(?:(?:\/|\?)[-A-Z0-9+&@#\/%=~_$?!\-:,.\(\);]*[A-Z0-9+&@#\/%=~_$\(\);])?' \
               r'|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'

REGEX_MAP = {
    'email': re.compile(emailRegex, regexFlags),
    'url': re.compile(urlRegex, regexFlags),
    'md5': re.compile(r'\b[0-9a-fA-F]{32}\b', regexFlags),
    'sha1': re.compile(r'\b[0-9a-fA-F]{40}\b', regexFlags),
    'sha256': re.compile(r'\b[0-9a-fA-F]{64}\b', regexFlags),
    'domain': re.compile(domainRegex, regexFlags)
}

TQ_TO_DEMISTO_IOC_TYPES = {
    'IP Address': 'ip',
    'IPv6 Address': 'ip',
    'Email Address': 'email',
    'URL': 'url',
    'MD5': 'file',
    'SHA-1': 'file',
    'SHA-256': 'file',
    'FQDN': 'domain'
}

STATUS_ID_TO_STATUS = {
    1: "Active",
    2: "Expired",
    3: "Indirect",
    4: "Review",
    5: "Whitelisted"
}

TYPE_ID_TO_IOC_TYPE = {
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

TYPE_ID_TO_EVENT_TYPE = {
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
    "attrs": ["ID", "Name", "Value"],
    "sources": ["ID", "Name"]
}

OBJ_DIRECTORY = {
    "indicator": "indicators",
    "adversary": "adversaries",
    "event": "events"
}


''' HELPER FUNCTIONS '''


def get_errors_string_from_bad_request(bad_request_results):
    # Errors could be retrieved in two forms:
    # 1. A dictionary of fields and errors list related to the fields, all under "data" key in the response json object
    # 2. A list, directly within the response object

    errors_string = "Errors from server:\n\n"

    # First form
    # errors_dict = bad_request_results.json().get("data", {}).get("errors", {})
    return bad_request_results  # todo: delete line
    if errors_dict:
        for error_num, (key, lst) in enumerate(errors_dict.items(), 1):
            curr_error_string = "\n".join(lst) + "\n\n"
            errors_string += "{0}. In '{1}':\n{2}".format(error_num, key, curr_error_string)
        return errors_string

    # Second form
    errors_list = bad_request_results.json().get("errors", [])
    if errors_list:
        for error_num, error in enumerate(errors_list, 1):
            errors_string += "Error #{0}: {1}\n".format(error_num, error)
    return errors_string


# ThreatQ auth based on OAuth 2.0 credential grand method
def request_new_access_token():
    data = {'grant_type': 'password', 'email': EMAIL, 'password': PASSWORD, 'client_id': CLIENT_ID}
    access_token_response = requests.post(API_TOKEN_URL, data=data, verify=USE_SSL, allow_redirects=False)

    res = json.loads(access_token_response.text)
    if int(access_token_response.status_code) >= 400:
        errors_string = get_errors_string_from_bad_request(access_token_response)
        error_message = "Authentication failed, unable to retrieve an access token.\n{}".format(errors_string)
        return_error(error_message)

    updated_integration_context = {
        "access_token": res['access_token'],
        "access_token_creation_time": int(time.time()) - 1,  # decrementing one second to be on the safe side
        "access_token_expires_in": res['expires_in']
    }
    demisto.setIntegrationContext(updated_integration_context)
    threatq_access_token = res['access_token']
    return threatq_access_token


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
        new_access_token = request_new_access_token()
        return new_access_token


def tq_request(method, url_suffix, params=None, files=None):
    access_token = get_access_token()
    api_call_headers = {'Authorization': 'Bearer ' + access_token}
    # data = json.dumps(params) if params else None  # todo: uncomment if needed

    response = requests.request(method, API_URL + url_suffix, data=params,
                                headers=api_call_headers, verify=USE_SSL, files=files)

    if response.status_code >= 400:
        errors_string = get_errors_string_from_bad_request(response)
        error_message = "Received and error - status code [{0}].\n{1}".format(response.status_code, errors_string)
        return_error(error_message)

    if method != "DELETE":  # the DELETE request returns nothing in response
        return json.loads(response.text)


def create_dbot_context(indicator, ind_type, ind_score):
    """ This function converts a TQ scoring value of an indicator into a DBot score.
    Default score mapping function: -1 -> 0, [0,3] -> 1, [4,7] -> 2, [8,10] -> 3.

    If threshold parameter is set, it overrides the default function definition for a
    malicious indicator, so only when TQ score >= threshold the DBot score will be 3.

    Args:
        indicator (str): The indicator name
        ind_type (str): The indicator type
        ind_score (int): The indicator TQ score

    Returns:
        (dict). The indicator's DBotScore.

    """
    #
    dbot_score_map = {
        -1: 0,
        0: 1,
        1: 1,
        2: 1,
        3: 1,
        4: 2,
        5: 2,
        6: 2,
        7: 2,
        8: 2 if THRESHOLD else 3,
        9: 2 if THRESHOLD else 3,
        10: 2 if THRESHOLD else 3
    }

    ret = {
        'Vendor': 'ThreatQ',
        'Indicator': indicator,
        'Type': ind_type
    }

    if THRESHOLD and ind_score >= THRESHOLD:
        ret['Score'] = 3
    else:
        ret['Score'] = dbot_score_map[ind_score]

    return ret


def get_tq_score_from_response(score_data):
    if isinstance(score_data, dict):
        # score will be max(gen_score, manual_score)
        gen_score = score_data.get('generated_score')
        manual_score = score_data.get('manual_score', 0.0)
        if manual_score is None:
            manual_score = -1
        return max(float(gen_score), float(manual_score))
    else:
        # score is already defined as a number
        return float(score_data)


def clean_html_from_string(raw_html):
    """ This function receives an HTML string of a text, and retrieves a clean string of its content.

    Args:
        raw_html: An HTML format text

    Returns:
        (string). A clean text string
    """
    if not raw_html:
        return None
    clean_r = re.compile('<.*?>')
    clean_text = re.sub(clean_r, '', raw_html)
    return clean_text


def sources_to_request_format(sources):
    if not sources:
        return []
    if isinstance(sources, str):
        sources = sources.split(',')
    return [{"name": source} for source in sources]


def sources_to_demisto_format(lst):
    return [{
        "Name": elem.get("name"),
        "ID": elem.get("pivot", {}).get("id")
    } for elem in lst]


def attributes_to_request_format(attr_names_lst, attr_values_lst):
    if not attr_names_lst and not attr_values_lst:
        return []
    if isinstance(attr_names_lst, str):
        attr_names_lst = attr_names_lst.split(',')
    if isinstance(attr_values_lst, str):
        attr_values_lst = attr_values_lst.split(',')
    if not attr_names_lst or not attr_values_lst or len(attr_names_lst) != len(attr_values_lst):
        return_error("Invalid input: attr_names_lst and attr_values_lst should have the same length")

    return [{"name": name, "value": val} for name, val in zip(attr_names_lst, attr_values_lst)]


def attributes_to_demisto_format(lst):
    return [{
        "Name": elem["name"],
        "Value": elem["value"],
        "ID": elem["id"]
    } for elem in lst]


def parse_date(text):
    valid_formats = ['%Y-%m-%d %H:%M:%S', '%Y-%m-%d']
    for fmt in valid_formats:
        try:
            return str(datetime.datetime.strptime(text, fmt))
        except ValueError:
            pass
    return_error("Time data '{0}' does not match any valid format.".format(text))


def data_to_demisto_format(data, obj_type):
    if obj_type == "indicator":
        return indicator_data_to_demisto_format(data)
    elif obj_type == "event":
        return event_data_to_demisto_format(data)
    elif obj_type == "adversary":
        return adversary_data_to_demisto_format(data)


def indicator_data_to_demisto_format(data):
    ret = {
        "Type": "indicator",
        "ID": data["id"],
        "UpdatedAt": data["updated_at"],
        "CreatedAt": data["created_at"],
        "Value": data["value"],
        "Status": STATUS_ID_TO_STATUS[data["status_id"]],
        "IndicatorType": TYPE_ID_TO_IOC_TYPE[data["type_id"]],
        "URL": "{0}/indicators/{1}/details".format(SERVER_URL, data['id'])
    }

    if "score" in data:
        ret["TQScore"] = get_tq_score_from_response(data["score"])
    if "description" in data:
        ret["Description"] = clean_html_from_string(data["description"])
    if "sources" in data:
        ret["Sources"] = sources_to_demisto_format(data["sources"])
    if "attributes" in data:
        ret["Attributes"] = attributes_to_demisto_format(data["attributes"])
    return ret


def adversary_data_to_demisto_format(data):
    ret = {
        "Type": "adversary",
        "ID": data["id"],
        "UpdatedAt": data["updated_at"],
        "CreatedAt": data["created_at"],
        "Name": data["name"],
        "URL": "{0}/indicators/{1}/details".format(SERVER_URL, data['id'])
    }
    if "sources" in data:
        ret["Sources"] = sources_to_demisto_format(data["sources"])
    if "attributes" in data:
        ret["Attributes"] = attributes_to_demisto_format(data["attributes"])
    return ret


def event_data_to_demisto_format(data):
    ret = {
        "Type": "event",
        "ID": data["id"],
        "UpdatedAt": data["updated_at"],
        "CreatedAt": data["created_at"],
        "Title": data["title"],
        "Occurred": data["happened_at"],
        "EventType": TYPE_ID_TO_EVENT_TYPE[data["type_id"]],
        "URL": "{0}/indicators/{1}/details".format(SERVER_URL, data['id'])
    }
    if "description" in data:
        ret["Description"] = clean_html_from_string(data["description"])
    if "sources" in data:
        ret["Sources"] = sources_to_demisto_format(data["sources"])
    if "attributes" in data:
        ret["Attributes"] = attributes_to_demisto_format(data["attributes"])
    return ret


def get_pivot_id(obj1_type, obj1_id, obj2_type, obj2_id):
    # A pivot id represents a connection between two objects.

    url_suffix = "/{0}/{1}/{2}".format(OBJ_DIRECTORY[obj1_type], obj1_id, OBJ_DIRECTORY[obj2_type])
    res = tq_request("GET", url_suffix)

    for related_object in res["data"]:  # res["data"] contains all the related objects of obj_id1
        if int(related_object["id"]) == int(obj2_id):
            return int(related_object["pivot"]["id"])


def add_malicious_data(generic_context):
    generic_context["Malicious"] = {
        "Vendor": "ThreatQ",
        "Description": "High risk"
    }


def get_ioc_reputation(keyword):
    # First, search for the IOC ID by keyword:
    url_suffix = "/search?query={0}&limit=1".format(keyword)
    res = tq_request("GET", url_suffix)

    if not res["data"]:
        return {}

    # Then, search for detailed information about the IOC
    url_suffix = "/indicators/{0}?with=attributes,sources,score,type".format(res['data'][0]['id'])
    res = tq_request("GET", url_suffix)

    return indicator_data_to_demisto_format(res["data"])


def set_ioc_entry_context(ioc_type, raw, dbot, generic):
    if dbot["Score"] == 3:
        add_malicious_data(generic)
    ec = {
        outputPaths[ioc_type]: generic,
        'DBotScore': dbot
    }
    if raw:
        ec['ThreatQ(val.ID === obj.ID && val.Type === obj.Type)'] = raw
    return ec


def build_readable(readable_title, obj_type, data, dbot_score=None):
    if isinstance(data, dict):  # One object data
        data["DBotScore"] = dbot_score  # only for readable output - then we pop it back
        readable = tableToMarkdown(readable_title, data, headers=HEADERS[obj_type],
                                   headerTransform=pascalToSpace, removeNull=True)
        data.pop("DBotScore")

        if "Attributes" in data:
            readable += tableToMarkdown("Attributes", data["Attributes"], headers=HEADERS["attrs"], removeNull=True)
        if "Sources" in data:
            readable += tableToMarkdown("Sources", data["Sources"], headers=HEADERS["sources"], removeNull=True)

        url_in_markdown_format = "[{0}]({1})".format(data['URL'], data['URL'])
        readable = readable.replace(data["URL"], url_in_markdown_format)

    else:  # 'data' is a list of related objects
        readable = tableToMarkdown(readable_title, data, headers=HEADERS[obj_type],
                                   headerTransform=pascalToSpace, removeNull=True)
        for elem in data:
            url_in_markdown_format = "[{0}]({1})".format(elem['URL'], elem['URL'])
            readable = readable.replace(elem["URL"], url_in_markdown_format)

    return readable


''' COMMANDS '''


def test_module():
    token = request_new_access_token()
    threshold = demisto.params().get('threshold')
    threshold_is_integer = isinstance(threshold, int) or (isinstance(threshold, str) and threshold.isdigit())
    threshold_is_valid_int = threshold_is_integer and 0 <= int(threshold) <= 10
    if token and (threshold is None or threshold_is_valid_int):
        demisto.results('ok')
    else:
        demisto.results('test failed')


def create_ioc_command():
    args = demisto.args()
    ioc_type = args.get('ioc_type')
    status = args.get('status')
    value = args.get('value')
    source_lst = args.get('source_lst')
    attr_names_lst = args.get('attr_names_lst')
    attr_values_lst = args.get('attr_values_lst')

    params = {
        "type": ioc_type,
        "status": status,
        "value": value,
        "sources": sources_to_request_format(source_lst),
        "attributes": attributes_to_request_format(attr_names_lst, attr_values_lst)
    }
    res = tq_request("POST", "/indicators", params)

    # For some reason, only while creating an indicator, the response data is a list of dicts with size 1.
    # Creating other objects simply returns one dict, as expected.
    raw = indicator_data_to_demisto_format(res["data"][0])

    entry_context = {'ThreatQ(val.ID === obj.ID && val.Type === obj.Type)': createContext(raw, removeNull=True)}

    readable_title = "Successfully created {0} '{1}'".format(ioc_type, value)
    readable = build_readable(readable_title, "indicator", raw)

    return_outputs(readable, entry_context, raw)


def create_adversary_command():
    args = demisto.args()
    name = args.get('name')
    source_lst = args.get('source_lst')
    attr_names_lst = args.get('attr_names_lst')
    attr_values_lst = args.get('attr_values_lst')

    params = {
        "name": name,
        "sources": sources_to_request_format(source_lst),
        "attributes": attributes_to_request_format(attr_names_lst, attr_values_lst)
    }
    res = tq_request("POST", "/adversaries", params)

    raw = adversary_data_to_demisto_format(res["data"])
    entry_context = {'ThreatQ(val.ID === obj.ID && val.Type === obj.Type)': createContext(raw, removeNull=True)}

    readable_title = "Successfully created adversary '{0}'".format(name)
    readable = build_readable(readable_title, "adversary", raw)

    return_outputs(readable, entry_context, raw)


def create_event_command():
    args = demisto.args()
    event_type = args.get('event_type')
    title = args.get('title')
    date = args.get('date')
    source_lst = args.get('source_lst')
    attr_names_lst = args.get('attr_names_lst')
    attr_values_lst = args.get('attr_values_lst')

    params = {
        "title": title,
        "type": event_type,
        "happened_at": parse_date(date),
        "sources": sources_to_request_format(source_lst),
        "attributes": attributes_to_request_format(attr_names_lst, attr_values_lst)
    }
    res = tq_request("POST", "/events", params)

    raw = event_data_to_demisto_format(res["data"])
    entry_context = {'ThreatQ(val.ID === obj.ID && val.Type === obj.Type)': createContext(raw, removeNull=True)}

    readable_title = "Successfully created event '{0}'".format(title)
    readable = build_readable(readable_title, "event", raw)

    return_outputs(readable, entry_context, raw)


def edit_ioc_command():
    args = demisto.args()
    ioc_id = args.get('ioc_id')
    value = args.get('value')
    ioc_type = args.get('ioc_type')
    description = args.get('description')

    if isinstance(ioc_id, str) and not ioc_id.isdigit():
        return_error("Invalid argument for indicator ID.")

    params = {
        "value": value,
        "type": ioc_type,
        "description": description
    }
    # Remove items with empty values:
    params = {k: v for k, v in params.items() if v is not None}

    url_suffix = "/indicators/{0}".format(ioc_id)
    res = tq_request("PUT", url_suffix, params)

    raw = indicator_data_to_demisto_format(res["data"])
    entry_context = {'ThreatQ(val.ID === obj.ID && val.Type === obj.Type)': createContext(raw, removeNull=True)}

    readable_title = "Successfully edited indicator with id {0}".format(ioc_id)
    readable = build_readable(readable_title, "indicator", raw)

    return_outputs(readable, entry_context, raw)


def edit_adversary_command():
    args = demisto.args()
    adversary_id = args.get('adversary_id')
    name = args.get('name')

    if isinstance(adversary_id, str) and not adversary_id.isdigit():
        return_error("Invalid argument for adversary ID.")

    params = {
        "name": name
    }
    # Remove items with empty values:
    params = {k: v for k, v in params.items() if v is not None}

    url_suffix = "/adversaries/{0}".format(adversary_id)
    res = tq_request("PUT", url_suffix, params)

    raw = adversary_data_to_demisto_format(res["data"])
    entry_context = {'ThreatQ(val.ID === obj.ID && val.Type === obj.Type)': createContext(raw, removeNull=True)}

    readable_title = "Successfully edited adversary with id {0}".format(adversary_id)
    readable = build_readable(readable_title, "adversary", raw)

    return_outputs(readable, entry_context, raw)


def edit_event_command():
    args = demisto.args()
    event_id = args.get('event_id')
    event_type = args.get('event_type')
    title = args.get('title')
    date = args.get('date')
    description = args.get('description')

    if isinstance(event_id, str) and not event_id.isdigit():
        return_error("Invalid argument for event ID.")

    params = {
        "title": title,
        "happened_at": parse_date(date) if date else None,
        "type": event_type,
        "description": description
    }
    # Remove items with empty values:
    params = {k: v for k, v in params.items() if v is not None}

    url_suffix = "/events/{0}".format(event_id)
    res = tq_request("PUT", url_suffix, params)

    raw = event_data_to_demisto_format(res["data"])
    entry_context = {'ThreatQ(val.ID === obj.ID && val.Type === obj.Type)': createContext(raw, removeNull=True)}

    readable_title = "Successfully edited event with id {0}".format(event_id)
    readable = build_readable(readable_title, "event", raw)

    return_outputs(readable, entry_context, raw)


def delete_object_command():
    args = demisto.args()
    obj_type = args.get('obj_type')
    obj_id = args.get('obj_id')

    if isinstance(obj_id, str) and not obj_id.isdigit():
        return_error("Invalid argument for object ID.")

    url_suffix = "/{0}/{1}".format(OBJ_DIRECTORY[obj_type], obj_id)
    tq_request("DELETE", url_suffix)
    demisto.results("Successfully deleted {0} with id {1}.".format(obj_type, obj_id))


def search_by_name_command():
    args = demisto.args()
    keyword = args.get('keyword')
    limit = args.get('limit')

    if limit and isinstance(limit, str) and not limit.isdigit():
        return_error("Invalid value for limit argument.")

    url_suffix = "/search?query={0}&limit={1}".format(keyword, limit)
    res = tq_request("GET", url_suffix)

    raw = [{"ID": e["id"], "Type": e["object"], "Value": e["value"]} for e in res["data"]]
    entry_context = {'ThreatQ(val.ID === obj.ID && val.Type === obj.Type)': raw} if raw else None

    human_readable = tableToMarkdown("Search results", raw)
    return_outputs(human_readable, entry_context, raw)


def search_by_id_command():
    args = demisto.args()
    obj_type = args.get('obj_type')
    obj_id = args.get('obj_id')

    if isinstance(obj_id, str) and not obj_id.isdigit():
        return_error("Invalid argument for object ID.")

    url_suffix = "/{0}/{1}?with=attributes,sources".format(OBJ_DIRECTORY[obj_type], obj_id)
    if obj_type == "indicator":
        url_suffix += ",score,type"

    res = tq_request("GET", url_suffix)
    raw = data_to_demisto_format(res["data"], obj_type)

    ec = {'ThreatQ(val.ID === obj.ID && val.Type === obj.Type)': createContext(raw, removeNull=True)}

    dbot_score = None
    if obj_type == "indicator":
        ioc_type = TQ_TO_DEMISTO_IOC_TYPES.get(raw["IndicatorType"])
        if ioc_type is not None:
            ec['DBotScore'] = create_dbot_context(raw["Value"], ioc_type, raw["TQScore"])
            dbot_score = ec['DBotScore']['Score']

    readable_title = "Search results for {0} with id {1}".format(obj_type, obj_id)
    readable = build_readable(readable_title, obj_type, raw, dbot_score)

    return_outputs(readable, ec, raw)


def get_related_indicators_command():
    args = demisto.args()
    obj_type = args.get('obj_type')
    obj_id = args.get('obj_id')

    if isinstance(obj_id, str) and not obj_id.isdigit():
        return_error("Invalid argument for object ID.")

    url_suffix = "/{0}/{1}/indicators?with=sources,score".format(OBJ_DIRECTORY[obj_type], obj_id)
    res = tq_request("GET", url_suffix)

    info = [indicator_data_to_demisto_format(obj) for obj in res["data"]]
    raw = {
        "RelatedIndicators": createContext(info, removeNull=True),
        "ID": int(obj_id),
        "Type": obj_type
    }
    ec = {'ThreatQ(val.ID === obj.ID && val.Type === obj.Type)': raw} if info else {}

    readable_title = "Related indicators for {0} with id {1}".format(obj_type, obj_id)
    readable = build_readable(readable_title, "indicator", raw["RelatedIndicators"])

    return_outputs(readable, ec, raw)


def get_related_adversaries_command():
    args = demisto.args()
    obj_type = args.get('obj_type')
    obj_id = args.get('obj_id')

    if isinstance(obj_id, str) and not obj_id.isdigit():
        return_error("Invalid argument for object ID.")

    url_suffix = "/{0}/{1}/adversaries?with=sources".format(OBJ_DIRECTORY[obj_type], obj_id)
    res = tq_request("GET", url_suffix)

    info = [adversary_data_to_demisto_format(obj) for obj in res["data"]]
    raw = {
        "RelatedAdversaries": createContext(info, removeNull=True),
        "ID": int(obj_id),
        "Type": obj_type
    }
    ec = {'ThreatQ(val.ID === obj.ID && val.Type === obj.Type)': raw} if info else {}

    readable_title = "Related adversaries for {0} with id {1}".format(obj_type, obj_id)
    readable = build_readable(readable_title, "adversary", raw["RelatedAdversaries"])

    return_outputs(readable, ec, raw)


def get_related_events_command():
    args = demisto.args()
    obj_type = args.get('obj_type')
    obj_id = args.get('obj_id')

    if isinstance(obj_id, str) and not obj_id.isdigit():
        return_error("Invalid argument for object ID.")

    url_suffix = "/{0}/{1}/events?with=sources".format(OBJ_DIRECTORY[obj_type], obj_id)
    res = tq_request("GET", url_suffix)

    info = [event_data_to_demisto_format(obj) for obj in res["data"]]
    raw = {
        "RelatedEvents": createContext(info, removeNull=True),
        "ID": int(obj_id),
        "Type": obj_type
    }
    ec = {'ThreatQ(val.ID === obj.ID && val.Type === obj.Type)': raw} if info else {}

    readable_title = "Related events for {0} with id {1}".format(obj_type, obj_id)
    readable = build_readable(readable_title, "event", raw["RelatedEvents"])

    return_outputs(readable, ec, raw)


def link_objects_command():
    args = demisto.args()
    obj1_type = args.get('obj1_type')
    obj1_id = args.get('obj1_id')
    obj2_type = args.get('obj2_type')
    obj2_id = args.get('obj2_id')

    if isinstance(obj1_id, str) and not obj1_id.isdigit() or isinstance(obj2_id, str) and not obj2_id.isdigit():
        return_error("Invalid argument for one of the objects' ID.")

    if obj1_type == obj2_type and obj1_id == obj2_id:
        return_error("Cannot link an object to itself.")

    url_suffix = "/{0}/{1}/{2}".format(OBJ_DIRECTORY[obj1_type], obj1_id, OBJ_DIRECTORY[obj2_type])
    params = {
        "id": obj2_id
    }
    tq_request("POST", url_suffix, params)
    demisto.results(
        "Successfully linked {0} with id {1} and {2} with id {3}.".format(obj1_type, obj1_id, obj2_type, obj2_id))


def unlink_objects_command():
    args = demisto.args()
    obj1_type = args.get('obj1_type')
    obj1_id = args.get('obj1_id')
    obj2_type = args.get('obj2_type')
    obj2_id = args.get('obj2_id')

    if isinstance(obj1_id, str) and not obj1_id.isdigit() or isinstance(obj2_id, str) and not obj2_id.isdigit():
        return_error("Invalid argument for one of the objects' ID.")

    if obj1_type == obj2_type and obj1_id == obj2_id:
        return_error("An object cannot be linked to itself.")

    p_id = get_pivot_id(obj1_type, obj1_id, obj2_type, obj2_id)
    if p_id is None:
        demisto.results("Command failed - Objects are not related.")
    else:
        url_suffix = "/{0}/{1}/{2}".format(OBJ_DIRECTORY[obj1_type], obj1_id, OBJ_DIRECTORY[obj2_type])
        tq_request("DELETE", url_suffix, params=[p_id])
        demisto.results(
            "Successfully unlinked {0} with id {1} and {2} with id {3}.".format(obj1_type, obj1_id, obj2_type, obj2_id))


def add_source_command():
    args = demisto.args()
    source = args.get('source')
    obj_id = args.get('obj_id')
    obj_type = args.get('obj_type')

    if isinstance(obj_id, str) and not obj_id.isdigit():
        return_error("Invalid argument for object ID.")

    url_suffix = "/{0}/{1}/sources".format(OBJ_DIRECTORY[obj_type], obj_id)
    params = {
        "name": source
    }

    tq_request("POST", url_suffix, params)
    demisto.results("Successfully added source {0} to {1} with id {2}.".format(source, obj_type, obj_id))


def delete_source_command():
    args = demisto.args()
    source_id = args.get('source_id')
    obj_id = args.get('obj_id')
    obj_type = args.get('obj_type')

    if isinstance(obj_id, str) and not obj_id.isdigit():
        return_error("Invalid argument for object ID.")
    if isinstance(source_id, str) and not source_id.isdigit():
        return_error("Invalid argument for source ID.")

    url_suffix = "/{0}/{1}/sources/{2}".format(OBJ_DIRECTORY[obj_type], obj_id, source_id)

    tq_request("DELETE", url_suffix)
    demisto.results("Successfully deleted source #{0} from {1} with id {2}.".format(source_id, obj_type, obj_id))


def add_attr_command():
    args = demisto.args()
    attr_name = args.get('attr_name')
    attr_value = args.get('attr_value')
    obj_type = args.get('obj_type')
    obj_id = args.get('obj_id')

    if isinstance(obj_id, str) and not obj_id.isdigit():
        return_error("Invalid argument for object ID.")

    url_suffix = "/{0}/{1}/attributes".format(OBJ_DIRECTORY[obj_type], obj_id)
    params = {
        "name": attr_name,
        "value": attr_value
    }

    tq_request("POST", url_suffix, params)
    demisto.results("Successfully added attribute to {0} with id {1}.".format(obj_type, obj_id))


def modify_attr_command():
    args = demisto.args()
    attr_id = args.get('attr_id')
    attr_value = args.get('attr_value')
    obj_type = args.get('obj_type')
    obj_id = args.get('obj_id')

    if isinstance(obj_id, str) and not obj_id.isdigit():
        return_error("Invalid argument for object ID.")
    if isinstance(attr_id, str) and not attr_id.isdigit():
        return_error("Invalid argument for attribute ID.")

    url_suffix = "/{0}/{1}/attributes/{2}".format(OBJ_DIRECTORY[obj_type], obj_id, attr_id)
    params = {"value": attr_value}

    tq_request("PUT", url_suffix, params)

    demisto.results("Successfully modified attribute #{0} of {1} with id {2}.".format(attr_id, obj_type, obj_id))


def delete_attr_command():
    args = demisto.args()
    attr_id = args.get('attr_id')
    obj_type = args.get('obj_type')
    obj_id = args.get('obj_id')

    if isinstance(obj_id, str) and not obj_id.isdigit():
        return_error("Invalid argument for object ID.")
    if isinstance(attr_id, str) and not attr_id.isdigit():
        return_error("Invalid argument for attribute ID.")

    url_suffix = "/{0}/{1}/attributes/{2}".format(OBJ_DIRECTORY[obj_type], obj_id, attr_id)

    tq_request("DELETE", url_suffix)
    demisto.results("Successfully deleted attribute #{0} from {1} with id {2}.".format(attr_id, obj_type, obj_id))


def upload_file_command():
    args = demisto.args()
    file_id = args.get('file_id')
    file_info = demisto.getFilePath(file_id)
    with open(file_info['path'], 'rb') as f:
        files = {'file': (file_info['name'], f)}
        url_suffix = '/attachments/upload'
        tq_request("POST", url_suffix, files=files)
        demisto.results("Successfully uploaded the file.")


def update_status_command():
    args = demisto.args()
    ioc_id = args.get('ioc_id')
    status = args.get('status')

    if isinstance(ioc_id, str) and not ioc_id.isdigit():
        return_error("Invalid argument for indicator ID.")

    url_suffix = "/indicators/{0}".format(ioc_id)
    params = {"status": status}

    res = tq_request("PUT", url_suffix, params)

    raw = {
        "Type": "indicator",
        "ID": int(ioc_id),
        "Status": STATUS_ID_TO_STATUS[res["data"]["status_id"]],
    }

    ec = {'ThreatQ(val.ID === obj.ID && val.Type === obj.Type)': raw}

    readable = "Successfully updated status of indicator with id {0} to {1}.".format(ioc_id, status)

    return_outputs(readable, ec, raw)


def update_score_command():
    # Note: We can't update DBot Score because API doesn't retrieve the indicator value.
    args = demisto.args()
    ioc_id = args.get('ioc_id')
    score = args.get('score')

    if isinstance(ioc_id, str) and not ioc_id.isdigit():
        return_error("Invalid argument for indicator ID.")

    if isinstance(score, str) and not score.isdigit():  # User chose 'Generated Score' option
        manual_score = None
    else:
        manual_score = int(score)

    url_suffix = "/indicator/{0}/scores".format(ioc_id)
    params = {"manual_score": manual_score}

    res = tq_request("PUT", url_suffix, params)

    raw = {
        "Type": "indicator",
        "ID": int(ioc_id),
        "TQScore": get_tq_score_from_response(res["data"])
    }

    ec = {'ThreatQ(val.ID === obj.ID && val.Type === obj.Type)': raw}

    readable = "Successfully updated score of indicator with id {0} to {1}. "\
               "Notice that final score is the maximum between " \
               "manual and generated scores.".format(ioc_id, int(raw["TQScore"]))

    return_outputs(readable, ec, raw)


def get_ip_reputation():
    args = demisto.args()
    ip = args.get('ip')

    if not is_ip_valid(ip, accept_v6_ips=True):
        return_error("Argument {0} is not a valid IP address.".format(ip))

    generic_context = {"Address": ip}
    raw_context = get_ioc_reputation(ip)
    if not raw_context:
        demisto.results("No results.")
    else:
        dbot_context = create_dbot_context(ip, 'ip', raw_context.get('TQScore'))
        entry_context = set_ioc_entry_context('ip', raw_context, dbot_context, generic_context)
        readable_title = "Search results for IP {0}".format(ip)
        readable = build_readable(readable_title, "indicator", raw_context)

        return_outputs(readable, entry_context, raw_context)


def get_url_reputation():
    args = demisto.args()
    url = args.get('url')

    if not REGEX_MAP['url'].match(url):
        return_error("Argument {0} is not a valid URL.".format(url))

    generic_context = {"Data": url}
    raw_context = get_ioc_reputation(url)
    if not raw_context:
        demisto.results("No results.")
    else:
        dbot_context = create_dbot_context(url, 'url', raw_context.get('TQScore'))
        entry_context = set_ioc_entry_context('url', raw_context, dbot_context, generic_context)
        readable_title = "Search results for URL {0}".format(url)
        readable = build_readable(readable_title, "indicator", raw_context)

        return_outputs(readable, entry_context, raw_context)


def get_email_reputation():
    args = demisto.args()
    email = args.get('email')

    if not REGEX_MAP['email'].match(email):
        return_error("Argument {0} is not a valid email address.".format(email))

    generic_context = {"Address": email}
    raw_context = get_ioc_reputation(email)
    if not raw_context:
        demisto.results("No results.")
    else:
        dbot_context = create_dbot_context(email, 'email', raw_context.get('TQScore'))
        entry_context = set_ioc_entry_context('email', raw_context, dbot_context, generic_context)
        readable_title = "Search results for email {0}".format(email)
        readable = build_readable(readable_title, "indicator", raw_context)

        return_outputs(readable, entry_context, raw_context)


def get_domain_reputation():
    args = demisto.args()
    domain = args.get('domain')

    if not REGEX_MAP['domain'].match(domain):
        return_error("Argument {0} is not a valid domain.".format(domain))

    generic_context = {"Name": domain}
    raw_context = get_ioc_reputation(domain)
    if not raw_context:
        demisto.results("No results.")
    else:
        dbot_context = create_dbot_context(domain, 'domain', raw_context.get('TQScore'))
        entry_context = set_ioc_entry_context('domain', raw_context, dbot_context, generic_context)
        readable_title = "Search results for domain {0}".format(domain)
        readable = build_readable(readable_title, "indicator", raw_context)

        return_outputs(readable, entry_context, raw_context)


def get_file_reputation():
    args = demisto.args()
    file = args.get('file')

    for fmt in ['md5', 'sha1', 'sha256']:
        if REGEX_MAP[fmt].match(file):
            break
        elif fmt == 'sha256':
            return_error("Argument {0} is not a valid file format.".format(file))

    generic_context = createContext({
        "MD5": file if fmt == 'md5' else None,
        "SHA1": file if fmt == 'sha1' else None,
        "SHA256": file if fmt == 'sha256' else None
    }, removeNull=True)
    raw_context = get_ioc_reputation(file)
    if not raw_context:
        demisto.results("No results.")
    else:
        dbot_context = create_dbot_context(file, 'file', raw_context.get('TQScore'))
        entry_context = set_ioc_entry_context('file', raw_context, dbot_context, generic_context)
        readable_title = "Search results for file {0}".format(file)
        readable = build_readable(readable_title, "indicator", raw_context)

        return_outputs(readable, entry_context, raw_context)


''' EXECUTION CODE '''
handle_proxy()
command = demisto.command()
LOG('command is {0}'.format(demisto.command()))
try:
    if command == 'test-module':
        test_module()
    elif command == 'threatq-search-by-name':
        search_by_name_command()
    elif command == 'threatq-search-by-id':
        search_by_id_command()
    elif command == 'threatq-create-ioc':
        create_ioc_command()
    elif command == 'threatq-create-event':
        create_event_command()
    elif command == 'threatq-create-adversary':
        create_adversary_command()
    elif command == 'threatq-edit-ioc':
        edit_ioc_command()
    elif command == 'threatq-edit-event':
        edit_event_command()
    elif command == 'threatq-edit-adversary':
        edit_adversary_command()
    elif command == 'threatq-delete-object':
        delete_object_command()
    elif command == 'threatq-get-related-ioc':
        get_related_indicators_command()
    elif command == 'threatq-get-related-events':
        get_related_events_command()
    elif command == 'threatq-get-related-adversaries':
        get_related_adversaries_command()
    elif command == 'threatq-link-objects':
        link_objects_command()
    elif command == 'threatq-unlink-objects':
        unlink_objects_command()
    elif command == 'threatq-add-source':
        add_source_command()
    elif command == 'threatq-delete-source':
        delete_source_command()
    elif command == 'threatq-add-attr':
        add_attr_command()
    elif command == 'threatq-modify-attr':
        modify_attr_command()
    elif command == 'threatq-delete-attr':
        delete_attr_command()
    elif command == 'threatq-upload-file':
        upload_file_command()
    elif command == 'threatq-update-status':
        update_status_command()
    elif command == 'threatq-update-score':
        update_score_command()
    elif command == "ip":
        get_ip_reputation()
    elif command == "domain":
        get_domain_reputation()
    elif command == "email":
        get_email_reputation()
    elif command == "url":
        get_url_reputation()
    elif command == "file":
        get_file_reputation()

except Exception as ex:
    return_error(str(ex))


# Params are of the type given in the integration page creation.
