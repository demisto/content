import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
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


''' HELPER FUNCTIONS '''

def load_proxy():
    # Load the system configured proxy if enabled in configuration
    proxy = {}
    if 'proxy' in demisto.params():
        proxy["http"] = os.environ["http_proxy"]
        proxy["https"] = os.environ["https_proxy"]
    return proxy

PROXY = load_proxy()

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
def tq_access():
    data = {'grant_type': 'password','email': EMAIL, 'password': PASSWORD, 'client_id': CLIENT_ID}
    access_token_response = requests.post(API_TOKEN_URL, data=data, verify=False, allow_redirects=False)

    tokens = json.loads(access_token_response.text)
    if int(access_token_response.status_code) >= 400:
        errors_string = get_errors_string_from_bad_request(access_token_response)
        error_message = "Authentication failed, unable to retrieve an access token.\n {}".format(errors_string)
        return_error(error_message)

    new_integration_context = {
        "access_token": tokens['access_token'],
        "access_token_creation_time": int(time.time()) -1, # decrementing one second to be on the safe side
        "access_token_expires_in": tokens['expires_in']
    }
    demisto.setIntegrationContext(new_integration_context)
    token = tokens['access_token']
    return token


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
        new_access_token = tq_access()
        return new_access_token


# remove html tags from ThreatQ description field
def cleanhtml(raw_html):
  cleanr = re.compile('<.*?>')
  cleantext = re.sub(cleanr, '', raw_html)
  return cleantext


''' Catch-all function for all command '''
def query_tq(keyword):
    '''
    This function handles all the querying of threatq
    '''
    tq_url = API_URL + "/search?query=" + keyword
    access_token = get_access_token()
    api_call_headers = {'Authorization': 'Bearer ' + access_token}
    api_call_response = requests.get(tq_url, headers=api_call_headers, verify=False)

    response = json.loads(api_call_response.text)

    # Find ThreatQ object type and object id based on keyword search results

    try:
        object_type = str(response['data'][0]['object'])
        object_id = str(response['data'][0]['id']) # get the object id from the query results
    except Exception, e:
        results = {'ContentsFormat': formats['markdown'], 'Type': entryTypes['note'], 'Contents': "No results from ThreatQ"}
        return results
    results = describe_by_id(object_type,object_id)
    return results


''' FUNCTIONS '''

''' Get ThreatQ object details '''
def describe_by_id(tq_obj_type,tq_obj_id):
    md = ''

    # build the ThreatQ query url
    if tq_obj_type == "indicator":
        tq_url = API_URL + "/indicators" + "/" + tq_obj_id
    elif tq_obj_type == "adversary":
        tq_url = API_URL + "/adversaries" + "/" + tq_obj_id
    elif tq_obj_type == "event":
        tq_url = API_URL + "/events" + "/" + tq_obj_id
    else:
        tq_url = API_URL + "/" + tq_obj_type + "/" + tq_obj_id

    # get ThreatQ response
    access_token = get_access_token()
    api_call_headers = {'Authorization': 'Bearer ' + access_token}
    api_call_response = requests.get(tq_url, headers=api_call_headers, verify=False)
    response = json.loads(api_call_response.text)

    if not response or len(response['data']) == 0:
        return "Found in ThreatQ, but no context"

    description = response['data']['description']
    name = response['data']['value']

    tq_attributes = None
    dbot_score = None

    if tq_obj_type == "indicator":
        result = tq_indicator(name)
        tq_attributes = result['attributes']
        dbot_score = result['dbotscore']


    # Description in clear text will be sent to War Room
    if description:
        clean_desc = cleanhtml(description)
    else:
        clean_desc = "No description found in ThreatQ"

    last_update = str(response['data']['updated_at'])

    tq_desc = {
        'name': name,
        'last_update' : last_update,
        'description' : clean_desc,
        'is_indicator': str(tq_obj_type == "indicator")
    }


    md += "## TQ Object: " + tq_obj_type + " ID: " + tq_obj_id + "\n"
    # Build a ThreatQ Response table
    md += tableToMarkdown('ThreatQ Response',tq_desc)

    if tq_obj_type == "indicator":
        if not tq_attributes or len(tq_attributes) == 0:
            md += "Found no attributs"
        else:
            md += tableToMarkdown("Attributes", tq_attributes)
            tq_desc.update(tq_attributes)

    entry2 = {
        'Type': entryTypes['note'],
        'Contents': tq_desc,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': {'ThreatQ(val.name && val.name == obj.name)': createContext(tq_desc, removeNull=True)},
        }

    if dbot_score:
        entry2['EntryContext']['DBotScore(val.Vendor && val.Indicator && val.Vendor == obj.Vendor && val.Indicator == obj.Indicator)'] = createContext(dbot_score, removeNull=True)

    return entry2

def create_dbot_score(ind_name, ind_score):

    return dbot_score
''' Get ThreatQ indicator's score and attributes '''

def tq_indicator(indicator):
    '''
    This function parse all the attributes of an indicator
    '''
    tq_url = API_URL + "/indicators/?value=" + indicator + "&with=score,attributes,sources"

    # get ThreatQ response on indicators attributes
    access_token = get_access_token()
    api_call_headers = {'Authorization': 'Bearer ' + access_token}
    api_call_response = requests.get(tq_url, headers=api_call_headers, verify=False)
    try:
        response = json.loads(api_call_response.text)
    except requests.exceptions.RequestException as e:
        md += '## TQ cound not FIND this indicator\n'
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

    ind_score = max(float(gen_score),float(manual_score))

    ''' TBD - ThreatQ score to dbot_score conversion '''
    if ind_score >= 8 :
        dbot_score = 3
        malicious = {
            'Vendor' : 'ThreatQ',
            'Detections' : 'high risk',
        }
    elif 4 < ind_score < 8:
        dbot_score = 2
        malicious = {
            'Vendor' : 'ThreatQ',
            'Detections' : 'mid risk',
        }
    elif ind_score <= 2:
        dbot_score = 1
        malicious = {
            'Vendor' : 'ThreatQ',
            'Detections' : 'low risk',
        }

    dbot_score = {
                'Vendor' : 'ThreatQ',
                'Indicator' : indicator,
                'Type' : 'ip',
                'Score' : dbot_score,
                'Malicious' : malicious,
            }


    md = ''

    try:
        length = len(attributes)
        if length > 0:
            md += "## TQ found " + str(length) + " attributes\n"
        else:
            md += "## TQ found no attributes\n"
        tq_attr = {
            'name' : indicator,
            'score' : ind_score
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
        'EntryContext': {'ThreatQ(val.name && val.name == obj.name)': createContext(tq_attr_context, removeNull=True),
                    'DBotScore(val.Vendor && val.Indicator && val.Vendor == obj.Vendor && val.Indicator == obj.Indicator)' :
                createContext(dbot_score, removeNull=True),
        }
    }
    # demisto.results(entry3)
    return {'attributes': tq_attr_context,
            'dbotscore': dbot_score }


''' EXECUTION CODE '''
LOG('command is %s' % (demisto.command(), ))
try:
    if demisto.command() == 'test-module':
        token = tq_access()
        if token:
            demisto.results('ok')
        else:
            demisto.results('test failed')
    elif demisto.command() == 'tq-search-by-name':
        args = demisto.args()
        keyword = demisto.get(args, 'keyword')
        results = query_tq(keyword)
        demisto.results(results)
    elif demisto.command() == 'ip':
        args = demisto.args()
        ip = demisto.get(args, 'ip')
        results = query_tq(ip)
        demisto.results(results)
    elif demisto.command() == 'url':
        args = demisto.args()
        url = demisto.get(args, 'url')
        results = query_tq(url)
        demisto.results(results)
    elif demisto.command() == 'file':
        args = demisto.args()
        file = demisto.get(args, 'file')
        results = query_tq(file)
        demisto.results(results)

    elif demisto.command() == 'fetch-incidents':
        fetch_incidents()

except Exception, e:
    raise
    return_error(e)


# Params are of the type given in the integration page creation.
