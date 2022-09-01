import json

import requests

from CommonServerPython import *

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' Global Variables '''
APIKEY = demisto.params()['apikey']
VERIFY = not demisto.params()['unsecure']
BASE_URL = 'https://deepsightapi.accenture.com/v1/'
DOMAIN_ACCESS_SUFFIX = 'domains/{0}'
IP_ACCESS_SUFFIX = 'ips/{0}'
URL_ACCESS_SUFFIX = 'urls/{0}'
FILE_ACCESS_SUFFIX = 'files/{0}'
USAGE_LIMIT_STATUS_SUFFIX = 'application/usage_limit_status'
HEADERS = {'API-KEY': APIKEY, 'Accept': 'application/json'}

# dict used to switch names of fields from returned value name to demisto context standards name


if not demisto.getParam('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

''' Helper Functions'''


def convert_deepsight_date_to_demisto_format(date_from_deepsight):
    """Remove 'Z' from the end of the date and return it. If empty date - return unchanged.
    """
    if date_from_deepsight == "":
        return ""
    demisto_format_date = date_from_deepsight[:-1]
    return demisto_format_date


def return_code_match(statusCode):
    if statusCode == 200:
        return "200: Success"
    if statusCode == 400:
        return "400: Invalid Input. Input was incorrect format."
    if statusCode == 403:
        return "403: Access Denied. API key successful, but license does not permit access to the requested resource."
    if statusCode == 404:
        return "404: Data not found"
    if statusCode == 429:
        return "429: License count usage has been exceeded."
    return "503: Server is overloaded.  Try again later"


def calc_dbot_score(url_data_json):
    dbotscore = 0
    if 'reputationValues' in url_data_json:
        reputation_values_data = url_data_json["reputationValues"]
        reputation_score = reputation_values_data["reputation"]
        if reputation_score > 5:
            dbotscore = 3
        else:
            dbotscore = 2
    return dbotscore


def create_behaviour_context(behaviour_data_json):
    behavior_context = {
        "Type": behaviour_data_json.get("type", ""),
        "Behaviour": behaviour_data_json.get("behaviour", ""),
        "Description": behaviour_data_json.get("description", ""),
    }
    return behavior_context


def create_behaviours_context(data_json):
    all_behaviours_contexts = []
    list_of_behaviour_data_jsons = data_json.get("behaviours", [])
    for behaviour_data_json in list_of_behaviour_data_jsons:
        cur_behaviour_context = create_behaviour_context(behaviour_data_json)
        all_behaviours_contexts.append(cur_behaviour_context)

    return all_behaviours_contexts


def create_malicious_data(data_from_api_json):
    malicious_description = ""
    if 'reputationValues' in data_from_api_json:
        reputation = data_from_api_json['reputationValues'].get("reputation", "Unknown")
        malicious_description = 'Reputation: {}'.format(reputation)
    malicious_data = {
        'Description': malicious_description,
        'Vendor': 'Symantec Deepsight Intelligence'
    }
    return malicious_data


def create_reputation_values_context(data_from_api_json):
    reputation_data = data_from_api_json.get("reputationValues", None)
    reputation_values_context = {
        "Reputation": "",
        "Confidence": "",
        "Hostility": ""
    }

    if reputation_data:
        reputation_values_context["Reputation"] = reputation_data.get("reputation", "")
        reputation_values_context["Confidence"] = reputation_data.get("confidence", "")
        reputation_values_context["Hostility"] = reputation_data.get("hostility", "")

    return reputation_values_context


def return_mati_report_entry_context(data_from_api_json):
    mati_reports = data_from_api_json.get('matiReports', [])
    all_mati_reports_contexts = []

    for report in mati_reports:
        mati_report_context = {
            "ID": report.get('id', ""),
            "Title": report.get('title', ""),
            "Date": report.get('date', "")
        }
        all_mati_reports_contexts.append(mati_report_context)
    return all_mati_reports_contexts


def merge_two_dicts(dict_a, dict_b):
    merged_dict = dict_a.copy()
    merged_dict.update(dict_b)
    return merged_dict


def create_deepsight_domain_entry_context(generic_domain_entry_context, domain_data_json):
    network_data = domain_data_json.get("network", None)
    first_seen = domain_data_json.get("firstSeen", "")
    first_seen_date = convert_deepsight_date_to_demisto_format(first_seen)
    last_seen = domain_data_json.get("lastSeen", "")
    last_seen_date = convert_deepsight_date_to_demisto_format(last_seen)
    deepsight_domain_entry_context = {
        'Whitelisted': domain_data_json.get("whitelisted", ""),
        'FirstSeen': first_seen_date,
        'LastSeen': last_seen_date,
        'ReputationValues': create_reputation_values_context(domain_data_json),
        'Report': return_mati_report_entry_context(domain_data_json),
        'ProxyType': "",
        'Behaviour': create_behaviours_context(domain_data_json),
        'Domain': domain_data_json.get("domain", ""),
        'TargetCountries': domain_data_json.get("targetCountries", ""),
    }

    if network_data:
        deepsight_domain_entry_context['ProxyType'] = network_data.get("proxyType", "")

    deepsight_domain_entry_context = merge_two_dicts(deepsight_domain_entry_context, generic_domain_entry_context)
    return deepsight_domain_entry_context


def create_registrant_context(whois_data_from_api):
    registrant_data_dict = {
        'Name': whois_data_from_api.get('person', ""),
        'Email': whois_data_from_api.get('email', "")
    }
    return registrant_data_dict


def create_registrar_context(whois_data_from_api):
    registrar_data_dict = {
        'Name': whois_data_from_api.get('registrar', ""),
    }
    return registrar_data_dict


def get_nameservers_data(whois_data_from_api):
    string_of_name_servers = ""
    array_of_name_servers = whois_data_from_api.get('nameServers', None)
    if array_of_name_servers:
        string_of_name_servers = " ".join(array_of_name_servers)
    return string_of_name_servers


# generate whois data dict
def gen_whois_data_dict(domain_data_json):
    whois_data_for_entry_context = {}
    whois_data_from_api = domain_data_json.get("whois", None)

    if whois_data_from_api:
        created_date = whois_data_from_api.get('created', "")
        created_date = convert_deepsight_date_to_demisto_format(created_date)
        updated_date = whois_data_from_api.get('updated', "")
        updated_date = convert_deepsight_date_to_demisto_format(updated_date)
        expiration_date = whois_data_from_api.get('expires', "")
        expiration_date = convert_deepsight_date_to_demisto_format(expiration_date)

        whois_data_for_entry_context = {
            "CreationDate": created_date,
            "UpdatedDate": updated_date,
            "ExpirationDate": expiration_date,
            "NameServers": get_nameservers_data(whois_data_from_api),
            "Registrant": create_registrant_context(whois_data_from_api),
            "Registrar": create_registrar_context(whois_data_from_api)
        }
    return whois_data_for_entry_context


# generate domain data dict for context in Demisto standard
def create_generic_domain_entry_context(domain_data_json):
    domain_entry_context = {
        'WHOIS': gen_whois_data_dict(domain_data_json),
        'Name': domain_data_json.get('domain', "")
    }
    return domain_entry_context


def calc_file_dbot_score(file_data_json):
    dbotscore = 0
    if 'reputation' in file_data_json:
        file_rep = file_data_json['reputation']
        if file_rep == "Clean" or file_rep == "Trending Clean":
            dbotscore = 1
        elif file_rep == "Trending Bad":
            dbotscore = 2
        elif file_rep == "Malicious":
            dbotscore = 3
    return dbotscore


def create_deepsight_file_entry_context(generic_file_entry_context, file_data_json):
    deepsight_file_entry_context = {
        "Report": return_mati_report_entry_context(file_data_json),
    }
    deepsight_file_entry_context = merge_two_dicts(deepsight_file_entry_context, generic_file_entry_context)
    return deepsight_file_entry_context


def get_generic_file_entry_context(file_data_json):
    entry_context = {
        'MD5': file_data_json.get('MD5', ""),
        'SHA256': file_data_json.get('SHA256', "")
    }
    return entry_context


def gen_file_malicious_data(file_data_json, dbotscore):
    malicious_data = None
    if dbotscore == 3:
        malicious_description = 'Reputation of file: {}'.format(file_data_json.get('reputation', 'Not found')),
        malicious_data = {
            'Description': malicious_description,
            'Vendor': 'Symantec Deepsight Intelligence'
        }
    return malicious_data


def create_deepsight_ip_entry_context(generic_entry_context, ip_data_json):
    network_data = ip_data_json.get("network", None)
    first_seen = ip_data_json.get("firstSeen", "")
    first_seen_date = convert_deepsight_date_to_demisto_format(first_seen)
    last_seen = ip_data_json.get("lastSeen", "")
    last_seen_date = convert_deepsight_date_to_demisto_format(last_seen)

    deepsight_ip_entry_context = {
        'Whitelisted': ip_data_json.get("whitelisted", ""),
        'FirstSeen': first_seen_date,
        'LastSeen': last_seen_date,
        'ReputationValues': create_reputation_values_context(ip_data_json),
        'Report': return_mati_report_entry_context(ip_data_json),
        'ProxyType': "",
        'Behaviour': create_behaviours_context(ip_data_json),
        'Domain': ip_data_json.get("domain", ""),
        'TargetCountries': ip_data_json.get("targetCountries", ""),
    }

    if network_data:
        deepsight_ip_entry_context['ProxyType'] = network_data.get("proxyType", "")

    deepsight_ip_entry_context = merge_two_dicts(deepsight_ip_entry_context, generic_entry_context)
    return deepsight_ip_entry_context


def gen_geo_data_dict(data_from_api):
    geo_data_dict = {}
    geo_data_from_api = data_from_api.get('geolocation', None)
    if geo_data_from_api:
        keys = geo_data_from_api.keys()
        geo_data_dict = {
            'Country': geo_data_from_api.get("country", ""),
            'City': geo_data_from_api.get("city", "")
        }
        if 'latitude' in keys and 'longtitude' in keys:
            geo_data_dict['Location'] = "{0}, {1}".format(geo_data_from_api['latitude'],
                                                          geo_data_from_api['longtitude'])
    return geo_data_dict


def create_generic_ip_entry_context(ip_data_json, ip):
    """Returns an entry context dict with the relevant values for the general !ip context standards.
    """
    entry_context = {
        'Geo': gen_geo_data_dict(ip_data_json),
        'Address': ip,
        'ASN': "",
    }

    network_data = ip_data_json.get("network", None)
    if network_data:
        entry_context['ASN'] = network_data.get("asn", "")

    return entry_context


''' Commands '''


# Build Markdown contextual data for human readable data in war room output
def build_md(jsondata, searchItem):
    mdOutput = "## Symantec Deepsight Intelligence: " + str(searchItem).upper()
    for key in jsondata.keys():
        if isinstance(jsondata[key], dict):
            mdOutput += "\n\n__" + key.upper() + "__"
            for k in jsondata[key]:
                if str(k) != 'uri':
                    mdOutput += "\n- __" + (str(k)).upper() + "__: " + str(jsondata[key][k])
        elif isinstance(jsondata[key], list):
            mdOutput += "\n\n__" + key.upper() + "__"
            for i in range(len(jsondata[key])):
                if isinstance(jsondata[key][i], dict):
                    for x in jsondata[key][i]:
                        if str(x) != 'uri':
                            mdOutput += "\n- __" + (str(x)).upper() + "__: " + str(jsondata[key][i][x])
                else:
                    mdOutput += "\n- __" + (str(i)).upper() + "__: " + str(jsondata[key][i])
        else:
            mdOutput += "\n\n__" + key.upper() + "__: " + str(jsondata[key])
    return mdOutput


def get_domain_data(domain):
    request_url = BASE_URL + DOMAIN_ACCESS_SUFFIX.format(domain)
    dom_req = requests.get(request_url, headers=HEADERS, verify=VERIFY)
    domain_data_json = json.loads(dom_req.content)
    return domain_data_json


def get_domain_data_command():
    domain = demisto.args()['domain']
    domain_data_json = get_domain_data(domain)

    dbotscore = calc_dbot_score(domain_data_json)
    dbotscore_context = {
        'Indicator': domain,
        'Score': dbotscore,
        'Type': 'domain',
        'Vendor': 'Symantec Deepsight Intelligence'
    }

    generic_domain_entry_context = create_generic_domain_entry_context(domain_data_json)
    if dbotscore == 3:
        generic_domain_entry_context["Malicious"] = create_malicious_data(domain_data_json)

    deepsight_domain_entry_context = create_deepsight_domain_entry_context(generic_domain_entry_context,
                                                                           domain_data_json)
    md = build_md(domain_data_json, domain)
    entry_context = {
        'DBotScore': dbotscore_context,
        'Domain(val.Domain && val.Domain == obj.Domain)': generic_domain_entry_context,
        'Deepsight.Domain(val.Domain && val.Domain == obj.Domain)': deepsight_domain_entry_context
    }
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': domain_data_json,
        'ContentsFormat': formats['json'],
        'HumanReadable': md,  # not sure if need to build the md first?
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': entry_context
    })


def get_ip_data(ip):
    request_url = BASE_URL + IP_ACCESS_SUFFIX.format(ip)
    ip_data_from_api = requests.get(request_url, headers=HEADERS, verify=VERIFY)
    ip_data_json = json.loads(ip_data_from_api.content)
    return ip_data_json


def get_ip_data_command():
    ip = demisto.args()['ip']
    ip_data_json = get_ip_data(ip)

    dbotscore = calc_dbot_score(ip_data_json)
    dbotscore_context = {
        'Indicator': ip,
        'Score': dbotscore,
        'Type': 'ip',
        'Vendor': 'Symantec Deepsight Intelligence'
    }
    generic_ip_entry_context = create_generic_ip_entry_context(ip_data_json, ip)

    if dbotscore == 3:
        generic_ip_entry_context['Malicious'] = create_malicious_data(ip_data_json)

    deepsight_ip_entry_context = create_deepsight_ip_entry_context(generic_ip_entry_context, ip_data_json)

    md = build_md(ip_data_json, ip)
    entry_context = {
        'DBotScore': dbotscore_context,
        'IP(val.Address && val.Address == obj.Address)': generic_ip_entry_context,
        'Deepsight.IP(val.Address && val.Address == obj.Address)': deepsight_ip_entry_context,
    }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': ip_data_json,
        'ContentsFormat': formats['json'],
        'HumanReadable': md,  # not sure if need to build the md first?
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': entry_context
    })


def get_file_data(file_hash):
    request_url = BASE_URL + FILE_ACCESS_SUFFIX.format(file_hash)
    file_data_from_api = requests.get(request_url, headers=HEADERS, verify=VERIFY)
    file_data_json = json.loads(file_data_from_api.content)
    return file_data_json


# Return data based on a sha256 or md5 hash search
def get_file_data_command():
    filehash = demisto.args()['file']
    file_data_json = get_file_data(filehash)

    dbotscore = calc_file_dbot_score(file_data_json)
    dbotscore_context = [
        {
            'Indicator': filehash,
            'Type': 'hash',
            'Vendor': 'Symantec Deepsight Intelligence',
            'Score': dbotscore
        },
        {
            'Indicator': filehash,
            'Type': 'file',
            'Vendor': 'Symantec Deepsight Intelligence',
            'Score': dbotscore
        }
    ]

    generic_file_entry_context = get_generic_file_entry_context(file_data_json)

    if dbotscore == 3:
        generic_file_entry_context['Malicious'] = create_malicious_data(file_data_json)

    deepsight_file_entry_context = create_deepsight_file_entry_context(generic_file_entry_context, file_data_json)

    md = tableToMarkdown(filehash, file_data_json, headers=None, headerTransform=None, removeNull=False, metadata=None)
    entry_context = {
        'DBotScore': dbotscore_context,
        'File(val.File && val.File == obj.File)': generic_file_entry_context,
        'Deepsight.File(val.File && val.File == obj.File)': deepsight_file_entry_context
    }
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': file_data_json,
        'ContentsFormat': formats['json'],
        'HumanReadable': md,  # not sure if need to build the md first?
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': entry_context
    })


def get_url_data(url):
    url_to_send_request_to = BASE_URL + URL_ACCESS_SUFFIX.format(url)
    url_data_from_request = requests.get(url_to_send_request_to, headers=HEADERS, verify=VERIFY)
    url_data_json = json.loads(url_data_from_request.content)
    return url_data_json


# Search for intel based on an URL
# if behaviour has value other than SPAM => malicous (possible values are Attack, Bot, CnC, Fraud, Malware, Phish_host or SPAM)
#  else if behaviour is SPAM => suspicious
#  if no behaviour, then unknown
def get_url_data_command():
    url = demisto.args()['url']
    url_data_json = get_url_data(url)

    md = build_md(url_data_json, url)
    dbotscore = calc_dbot_score(url_data_json)

    generic_url_entry_context = {
        'Data': url
    }

    dbotscore_context = {
        'Indicator': url,
        'Score': dbotscore,
        'Type': 'url',
        'Vendor': 'Symantec Deepsight Intelligence'
    }

    entry_context = {
        'DBotScore': dbotscore_context,
        'URL(val.Data && val.Data == obj.Data)': generic_url_entry_context,
        'Deepsight.URL(val.Data && val.Data == obj.Data)': generic_url_entry_context
    }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': url_data_json,
        'ContentsFormat': formats['json'],
        'HumanReadable': md,  # not sure if need to build the md first?
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': entry_context
    })


def get_request_status():
    request_url = BASE_URL + USAGE_LIMIT_STATUS_SUFFIX
    status_data = requests.get(request_url, headers=HEADERS, verify=VERIFY)
    status_data_json = json.loads(status_data.content)
    return status_data_json


# get results of request status - determine current limit usage of the api license
def request_status_command():
    status_data_json = get_request_status()
    md = build_md(status_data_json, "Requests Limit Status")

    entry_context = {
        'Deepsight.RequestLimitPerDay': status_data_json.get("X-License-Limit-Limit", ""),
        'Deepsight.RequestsRemaining': status_data_json.get("X-License-Limit-Remaining", ""),
        'Deepsight.SecondsToLimitReset': status_data_json.get("X-License-Limit-Reset", "")
    }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': status_data_json,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': entry_context
    })


def test_module():
    try:
        result = get_ip_data("5.79.86.16")
    except Exception:
        raise Exception("Test failed: API request did not succeed, result: {}".format(result))
    if result:
        demisto.results('ok')


LOG('command is %s' % (demisto.command(),))
try:
    if demisto.command() == 'test-module':
        test_module()
    elif demisto.command() == 'domain':
        get_domain_data_command()
    elif demisto.command() == 'ip':
        get_ip_data_command()
    elif demisto.command() == 'file':
        get_file_data_command()
    elif demisto.command() == 'url':
        get_url_data_command()
    elif demisto.command() == 'deepsight-get-request-status':
        request_status_command()
except Exception as e:
    return_error(str(e))
