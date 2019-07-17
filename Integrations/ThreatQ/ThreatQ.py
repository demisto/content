import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''
import os
import datetime
import requests
import json

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBAL VARS '''

API_URL = demisto.params()['apiUrl']
API_TOKEN_URL = API_URL + "/token"
CLIENT_ID = demisto.params()['client_id']
EMAIL = demisto.getParam('credentials').get('identifier')
PASSWORD = demisto.getParam('credentials').get('password')
USE_SSL = not demisto.params().get('insecure', False)

INDICATOR = 0
ADVERSARY = 1
EVENT = 2
ATTRIBUTE = 3


''' HELPER FUNCTIONS '''


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


def tq_to_dbot_score(indicator, ind_type, ind_score):
    """ This function converts a TQ scoring value of an indicator into a DBot score.

    Args:
        indicator (str): The indicator name
        ind_score (int): The indicator TQ score

    Returns:
        (dict). The indicator's DBot score.

    """
    if ind_score >= 8:
        dbot_score = 3
        malicious = {
            'Vendor': 'ThreatQ',
            'Detections': 'high risk',
        }
    elif 4 < ind_score < 8:
        dbot_score = 2
        malicious = {
            'Vendor': 'ThreatQ',
            'Detections': 'mid risk',
        }
    elif ind_score <= 2:
        dbot_score = 1
        malicious = {
            'Vendor': 'ThreatQ',
            'Detections': 'low risk',
        }

    return {
        'Vendor': 'ThreatQ',
        'Indicator': indicator,
        'Type': ind_type,
        'Score': dbot_score,
        'Malicious': malicious,
    }


def get_obj_id_and_type(keyword):
    """ This function searches an object by keywords and returns its id and type.

    Args:
        keyword (str): The value string of the wanted object.

    Returns:
        (dict). A dictionary contains the object's id and type.
    """
    tq_url = API_URL + "/search?query=" + keyword
    access_token = get_access_token()
    api_call_headers = {'Authorization': 'Bearer ' + access_token}
    api_call_response = requests.get(tq_url, headers=api_call_headers, verify=False)
    response = json.loads(api_call_response.text)

    if not response["data"]:
        return None
    return {
            "id": response["data"][0]["id"],
            "type": response["data"][0]["object"]
    }


def query_tq(keyword):
    """ This function handles all the querying of ThreatQ.

    Args:
        keyword: The wanted object keyword.

    Returns: The relevant context.
    """
    info = get_obj_id_and_type(keyword)
    if not info:
        results = {
            'ContentsFormat': formats['markdown'],
            'Type': entryTypes['note'],
            'Contents': "No results from ThreatQ"
        }
        return results
    results = describe_by_id(info["id"], info["type"])
    return results


def get_dir(obj_type):
    if obj_type == "indicator":
        return "/indicators"
    elif obj_type == "adversary":
        return "/adversaries"
    elif obj_type == "event":
        return "/events"


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


def describe_by_id(tq_obj_id, tq_obj_type):
    """ This function receives an object id and type, and retrieves the object context.

    Args:
        tq_obj_id (string): The object ID
        tq_obj_type (String): The object type

    Returns: The object context.
    """
    md = ''

    tq_url = API_URL + get_dir(tq_obj_type) + "/" + tq_obj_id

    # get ThreatQ response
    access_token = get_access_token()
    api_call_headers = {'Authorization': 'Bearer ' + access_token}
    api_call_response = requests.get(tq_url, headers=api_call_headers, verify=False)
    response = json.loads(api_call_response.text)

    if not response or len(response['data']) == 0:
        return "Found in ThreatQ, but no context"

    desc = clean_html(response['data']['description'])
    if not desc:
        desc = "No description found in ThreatQ"
    name = response['data']['value']

    tq_attributes = None
    dbot_score = None

    if tq_obj_type == "indicator":
        result = get_indicator(name)
        tq_attributes = result['attributes']
        dbot_score = result['dbotscore']

    last_update = str(response['data']['updated_at'])

    tq_desc = {
        'name': name,
        'last_update': last_update,
        'description': desc,
        'is_indicator': str(tq_obj_type == "indicator")
    }

    md += "## TQ Object: " + tq_obj_type + " ID: " + tq_obj_id + "\n"
    # Build a ThreatQ Response table
    md += tableToMarkdown('ThreatQ Response', tq_desc)

    if tq_obj_type == "indicator":
        if not tq_attributes or len(tq_attributes) == 0:
            md += "Found no attributes"
        else:
            md += tableToMarkdown("Attributes", tq_attributes)
            tq_desc.update(tq_attributes)

    ec = {
        'ThreatQ(val.name && val.name == obj.name)':
            createContext(tq_desc, removeNull=True)
    }

    if dbot_score:
        ec['DBotScore(val.Vendor && val.Indicator && val.Vendor ==obj.Vendor' \
           ' && val.Indicator == obj.Indicator)'] = createContext(dbot_score, removeNull=True)

    context = {
        'Type': entryTypes['note'],
        'Contents': tq_desc,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': ec
    }

    return context


''' Get ThreatQ indicator's score and attributes '''


def get_indicator(indicator):
    """ This function parses all the attributes of an indicator.

    Args:
        indicator (string): A string represents the indicator

    Returns:
         (dict). A dictionary of the attributes of the indicator.
    """
    md = ''
    tq_url = API_URL + "/indicators/?value=" + indicator + "&with=score,attributes,sources"

    # get ThreatQ response on indicators attributes
    access_token = get_access_token()
    api_call_headers = {'Authorization': 'Bearer ' + access_token}
    api_call_response = requests.get(tq_url, headers=api_call_headers, verify=False)
    try:
        response = json.loads(api_call_response.text)
    except requests.exceptions.RequestException as e:
        md += '## TQ could not FIND this indicator\n'
        exit(1)
    # check if any attributes
    attributes = response["data"][0]["attributes"]
    score = response["data"][0]["score"]
    sources = response["data"][0]["sources"][0]
    gen_score = score["generated_score"]
    manual_score = score["manual_score"]
    source = sources["name"]
    if not manual_score:
        manual_score = 0

    ind_score = max(float(gen_score), float(manual_score))
    dbot_score = tq_to_dbot_score(indicator, ind_score)

    md = ''

    try:
        length = len(attributes)
        if length > 0:
            md += "## TQ found " + str(length) + " attributes\n"
        else:
            md += "## TQ found no attributes\n"
        tq_attr = {
            'name': indicator,
            'score': ind_score
        }

        for x in range(length):
            name = str(attributes[x]["name"])
            value = str(attributes[x]["value"])
            tq_attr[name] = value
            md += "Attribute " + name + " is " + value + "\n"
        tq_attr_context = dict(tq_attr)
    except:
        md += '## TQ could not EXTRACT attributes\n'
        pass

    entry3 = {
        'Type': entryTypes['note'],
        'Contents': tq_attr_context,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': {
            'ThreatQ(val.name && val.name == obj.name)': createContext(tq_attr_context, removeNull=True),
            'DBotScore(val.Vendor && val.Indicator && val.Vendor == obj.Vendor && val.Indicator == obj.Indicator)':
                createContext(dbot_score, removeNull=True),
        }
    }
    # demisto.results(entry3)
    return {
        'attributes': tq_attr_context,
        'dbotscore': dbot_score
    }


def tq_post_request(url_suffix, params):
    access_token = get_access_token()
    api_call_headers = {'Authorization': 'Bearer ' + access_token}
    requests.post(API_URL + url_suffix, data=params, headers=api_call_headers, verify=False)


def get_sources_array(source_lst, tlp_lst):
    if not isinstance(source_lst, list):
        source_lst = source_lst.split(',')
    if not isinstance(tlp_lst, list):
        tlp_lst = source_lst.split(',')
    if len(source_lst) != len(tlp_lst):
        return None  # todo: raise error
    return [{"name": source_lst[i], "tlp": {"name": tlp_lst[i]}} for i in range(len(source_lst))]


''' FUNCTIONS '''


def create_ioc_command():
    args = demisto.args()
    params = {
        "type": args.get('type'),
        "status": args.get('status'),
        "value": args.get('value'),
        "sources": get_sources_array(args.get('source_lst'), args.get('tlp_lst'))
    }
    tq_post_request("/indicators", params)


def create_adversary_command():
    args = demisto.args()
    params = {
        "name": args.get('name'),
        "sources": get_sources_array(args.get('source_lst'), args.get('tlp_lst'))
    }
    tq_post_request("/adversaries", params)


def create_event_command():
    args = demisto.args()
    try:
        date = parse_date(args.get('date'))
    except Exception as e:
        return_error(e)
    params = {
        "title": args.get('title'),
        "type": args.get('type'),
        "happened_at": date,
        "sources": get_sources_array(args.get('source_lst'), args.get('tlp_lst'))
    }
    tq_post_request("/events", params)


def test_module():
    token = get_tq_access_token()
    if token:
        demisto.results('ok')
    else:
        demisto.results('test failed')


def search_by_name_command():
    args = demisto.args()
    keyword = demisto.get(args, 'keyword')
    results = query_tq(keyword)
    demisto.results(results)


def add_attribute():
    args = demisto.args()
    obj_keyword = args.get('obj_keyword')
    attr_keyword = args.get('attr_keyword')
    obj = query_tq(obj_keyword)
    # TODO: finish function


def does_obj_exist_command():
    pass


def get_obj_attr_command():
    pass


def get_related_objs_command(obj_type):
    args = demisto.args()
    obj = get_obj_id_and_type(args.get('obj_keyword'))
    url_suffix = get_dir(obj["type"]) + "/" + obj["id"]
    params = {
        "id": obj["id"]
    }
    tq_post_request(url_suffix, params)
    if obj_type == INDICATOR:
        url_suffix += "/indicators"
    elif obj_type == ADVERSARY:
        url_suffix += "/adversaries"
    elif obj_type == EVENT:
        url_suffix += "/events"


def link_objects_command():
    args = demisto.args()
    obj1 = get_obj_id_and_type(args.get('obj1_keyword'))
    obj2 = get_obj_id_and_type(args.get('obj2_keyword'))
    url_suffix = get_dir(obj1["type"]) + "/" + obj1["id"] + get_dir(obj2["type"])
    params = {
        "id": obj2["id"]
    }
    tq_post_request(url_suffix, params)


def create_attr_command():
    args = demisto.args()
    params = {
        "name": args.get('name')
    }
    tq_post_request("/attributes", params)


def link_obj_attr_command():
    pass




def upload_file_command():
    # /api/attachments/upload?resumableChunkNumber=1&resumableChunkSize=1048576&resumableCurrentChunkSize=504&resumableTotalSize=504&resumableType=text%2Fcsv&resumableIdentifier=504-csv_extra_fieldscsv&resumableFilename=csv_extra_fields.csv&resumableRelativePath=csv_extra_fields.csv&resumableTotalChunks=1
    pass


def query_tq_command(ind_type):
    args = demisto.args()
    results = query_tq(args.get(ind_type))
    demisto.results(results)
    # return_outputs()


def update_status_command():
    pass


''' EXECUTION CODE '''
handle_proxy()
command = demisto.command()
LOG(f'command is {demisto.command()}')
try:
    if command == 'test-module':
        test_module()
    elif command == 'tq-search-by-name':
        search_by_name_command()
    elif command == 'does-obj-exist':
        does_obj_exist_command()
    elif command == 'create-ioc':
        create_ioc_command()
    elif command == 'create-event':
        create_event_command()
    elif command == 'create-adversary':
        create_adversary_command()
    elif command == 'get-related-ioc':
        get_related_objs_command(INDICATOR)  # todo: find a more elegant way
    elif command == 'get-related-events':
        get_related_objs_command(EVENT)
    elif command == 'get-related-adversaries':
        get_related_objs_command(ADVERSARY)
    elif command == 'link-objects':
        link_objects_command()
    elif command == 'create-attr':
        create_attr_command()
    elif command == 'link-obj-attr':
        link_obj_attr_command()
    elif command == 'get-obj-attr':
        get_obj_attr_command()
    elif command == 'upload-file':
        upload_file_command()
    elif command in ['ip', 'domain', 'email', 'url', 'file']:
        query_tq_command(command)  # commands and arguments strings are equal

except Exception as ex:
    raise
    return_error(ex)


# Params are of the type given in the integration page creation.
