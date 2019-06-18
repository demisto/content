import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import requests
from requests.exceptions import MissingSchema, ConnectionError, InvalidSchema
import json

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

USERNAME = demisto.params().get('username')
API_KEY = demisto.params().get('key')
SERVER = demisto.params().get('url', '').strip('/')
USE_SSL = not demisto.params().get('insecure', False)
BASE_URL = SERVER + '/api/'

HEADERS = {
    'Content-Type': 'application/json'
}

CREDENTIALS = {
    'username': USERNAME,
    'api_key': API_KEY
}

DBOT_SCORE = {
    'low': 2,
    'medium': 2,
    'high': 3,
    'very-high': 3
}

SEVERITY_SCORE = {
    'low': 0,
    'medium': 1,
    'high': 2,
    'very-high': 3
}

DBOT_MAPPING = {
    'value': 'Indicator',
    'type': 'Type',
    'source': 'Vendor',
}

INDICATOR_MAPPING = {
    'asn': 'ASN',
    'value': 'Address',
    'country': 'Country',
    'type': 'Type',
    'modified_ts': 'Modified',
    'confidence': 'Confidence',
    'status': 'Status',
    'org': 'Organization',
    'source': 'Source',
}

INDICATOR_EXTENDED_MAPPING = {
    'value': 'Value',
    'id': 'ID',
    'itype': 'IType',
    'meta': 'Meta',
    'confidence': 'Confidence',
    'country': 'Country',
    'org': 'Organization',
    'asn': 'ASN',
    'status': 'Status',
    'tags': 'Tags',
    'modified_ts': 'Modified',
    'source': 'Source',
    'type': 'Type',
}

THREAT_MODEL_MAPPING = {
    'name': 'Name',
    'id': 'ID',
    'created_ts': 'CreatedTime',
}

if not demisto.params().get('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, params=None, data=None, headers=None, files=None):
    """
        A wrapper for requests lib to send our requests and handle requests and responses better.
    """
    res = requests.request(
        method,
        BASE_URL + url_suffix,
        verify=USE_SSL,
        params=params,
        data=data,
        headers=headers,
        files=files,
    )
    # Handle error responses gracefully
    if res.status_code in {401}:
        return_error("Got unauthorized from the server. Check the credentials.")
    elif res.status_code in {404}:
        command = demisto.command()
        if command == 'threatstream-get-model-description' \
                or command == 'threatstream-get-indicators-by-model' \
                or command == 'threatstream-get-analysis-status' \
                or command == 'threatstream-analysis-report':
            # in order to prevent raising en error in case model/indicator/report was not found
            return {}
        else:
            return_error("The resource not found. Check the endpoint.")
    elif res.status_code not in {200, 201, 202}:
        return_error(f"Error in API call to ThreatStream {res.status_code} - {res.text}")

    return res.json()


def sort_by_severity(ioc):
    """
        Extract the severity value from the indicator and converts to integer.
        The integer is received from SEVERITY_SCORE dictionary with possible values: 0, 1, 2, 3.
        In case the indicator has no severity value, the indicator severity score is set to 0 (low).
    """
    try:
        severity_value = ioc['meta']['severity']
        return SEVERITY_SCORE[severity_value]
    except KeyError:
        return 0


def find_worst_indicator(indicators):
    """
        Sorts list of indicators by severity score and returns one indicator with the highest severity.
    """
    indicators.sort(key=sort_by_severity, reverse=True)
    return indicators[0]


def prepare_args(args):
    # removing empty keys that can be passed from playbook input
    args = {k: v for (k, v) in args.items() if v}
    if 'include_inactive' in args:
        args['status'] = "active,inactive" if args.pop('include_inactive') == 'True' else "active"
    if 'indicator_severity' in args:
        args['meta.severity'] = args.pop('indicator_severity', None)
    if 'tags_name' in args:
        args['tags.name '] = args.pop('tags_name', None)
    if 'indicator_value' in args:
        args['value'] = args.pop('indicator_value', None)

    return args


def build_params(**params):
    """
        Builds query string from key word arguments and appends to it username and api key.
    """
    params.update(CREDENTIALS)
    return params


def get_indicator_severity(indicator):
    """
        Extracts and returns severity value from indicator's nested key.
        In case the severity value was not found in indicator dictionary,
        the severity value will be low.
    """
    try:
        severity = indicator['meta']['severity']
    except KeyError:
        severity = 'low'
    finally:
        return severity


def camelize(src, delim=' '):
    # check with the reviewer if this changes are in the common server python
    # if so, the function can be deleted...
    # the current version doesn't support python 3
    def camelize_str(src_str, delim):
        components = src_str.split(delim)
        return ''.join(map(lambda x: x.title(), components))

    if isinstance(src, list):
        return list(map(lambda x: camelize(x, delim), src))

    src = {camelize_str(k, delim): v for (k, v) in src.items()}
    return src


def get_dbot_context(indicator, threshold):
    """
         Builds and returns dictionary with Indicator, Type, Vendor and Score keys
         and values from the indicator that will be returned to context.
    """
    dbot_context = {DBOT_MAPPING[k]: v for (k, v) in indicator.items() if k in DBOT_MAPPING.keys()}
    indicator_score = DBOT_SCORE[get_indicator_severity(indicator)]
    # the indicator will be considered as malicious in case it's score is greater or equal to threshold
    dbot_context['Score'] = 3 if indicator_score >= DBOT_SCORE[threshold] else indicator_score

    return dbot_context


def mark_as_malicious(indicator, threshold, context):
    """
        Marks indicator as malicious if severity of indicator is greater/equals to threshold and
        adds Malicious key to returned dictionary (context) in such case.
    """
    severity = get_indicator_severity(indicator)

    if SEVERITY_SCORE[severity] >= SEVERITY_SCORE[threshold]:
        context['Malicious'] = {
            'Vendor': 'ThreatStream'
        }


def search_indicator_by_params(params, searchable_value):
    """
        Generic function that searches for indicators from ThreatStream by given query string.
        Returns indicator with the highest severity score.
    """
    indicators_data = http_request("Get", "v2/intelligence/", params=params, headers=HEADERS)

    if not indicators_data['objects']:
        demisto.results(F"No intelligence has been found for {searchable_value}")
        sys.exit()

    return find_worst_indicator(indicators_data['objects'])


def get_ip_context(indicator, threshold):
    """
        Builds and returns dictionary that will be set to IP generic context.
    """
    ip_context = {}
    ip_context['ASN'] = indicator.get('asn', '')
    ip_context['Address'] = indicator.get('value', '')
    ip_context['Geo'] = {
        'Country': indicator.get('country', ''),
        'Location': f"{indicator.get('latitude', '')},{indicator.get('longitude', '')}"
    }
    mark_as_malicious(indicator, threshold, ip_context)

    return ip_context


def get_domain_context(indicator, threshold):
    """
        Builds and returns dictionary that will be set to Domain generic context.
    """
    domain_context = {}
    whois_context = {}
    domain_context['Name'] = indicator.get('value', '')
    domain_context['DNS'] = indicator.get('ip', '')

    whois_context['CreationDate'] = indicator.get('created_ts', '')
    whois_context['UpdatedDate'] = indicator.get('modified_ts', '')
    meta = indicator.get('meta', None)

    if meta:
        registrant = {}
        registrant['Name'] = meta.get('registrant_name', '')
        registrant['Email'] = meta.get('registrant_email', '')
        registrant['Phone'] = meta.get('registrant_phone', '')
    whois_context['Registrant'] = registrant
    domain_context['WHOIS'] = whois_context
    mark_as_malicious(indicator, threshold, domain_context)

    return domain_context


def get_file_context(indicator, threshold):
    """
        Builds and returns dictionary that will be set to File generic context.
    """
    file_context = {'MD5': indicator.get('value', '')}
    mark_as_malicious(indicator, threshold, file_context)

    return file_context


def get_url_context(indicator, threshold):
    """
        Builds and returns dictionary that will be set to URL generic context.
    """
    url_context = {'Data': indicator.get('value', '')}
    mark_as_malicious(indicator, threshold, url_context)

    return url_context


def get_threat_generic_context(indicator):
    """
        Receives indicator and builds new dictionary from values that were defined in
        INDICATOR_MAPPING keys and adds the Severity key with indicator severity value.
    """
    threat_ip_context = {INDICATOR_MAPPING[k]: v for (k, v) in indicator.items() if
                         k in INDICATOR_MAPPING.keys()}
    try:
        threat_ip_context['Severity'] = indicator['meta']['severity']
    except KeyError:
        threat_ip_context['Severity'] = 'low'
    finally:
        return threat_ip_context


def parse_network_elem(element_list, context_prefix):
    """
        Parses the network elements list and returns a new dictionary.
    """
    return list(map(lambda e: {
        F'{context_prefix}Source': e.get('src', ''),
        F'{context_prefix}Destination': e.get('dst', ''),
        F'{context_prefix}Port': e.get('dport', ''),
    }, element_list))


def parse_network_lists(network):
    """
        Parses the network part that was received from sandbox report json.
        In each list, only sublist of 10 elements is taken.
    """
    hosts = [{'Hosts': h} for h in network.get('hosts', [])[:10]]

    if 'packets' in network:
        network = network['packets']

    udp_list = parse_network_elem(network.get('udp', [])[:10], 'Udp')
    icmp_list = parse_network_elem(network.get('icmp', [])[:10], 'Icmp')
    tcp_list = parse_network_elem(network.get('tcp', [])[:10], 'Tcp')
    http_list = parse_network_elem(network.get('http', [])[:10], 'Http')
    https_list = parse_network_elem(network.get('https', [])[:10], 'Https')
    network_result = udp_list + icmp_list + tcp_list + http_list + https_list + hosts

    return network_result


def parse_info(info):
    """
        Parses the info part that was received from sandbox report json
    """
    info.update(info.pop('machine', {}))
    parsed_info = {
        'Category': info.get('category', '').title(),
        'Started': info.get('started', ''),
        'Completed': info.get('ended', ''),
        'Duration': info.get('duration', ''),
        'VmName': info.get('name', ''),
        'VmID': info.get('id', '')

    }
    return parsed_info


def get_report_outputs(report, report_id):
    """
        Returns human readable and entry context of the sandbox report
    """
    info = parse_info(report.get('info', {}))
    info['ID'] = report_id
    _, info['Verdict'] = get_submission_status(report_id, False)
    network = parse_network_lists(report.get('network', {}))

    hm = tableToMarkdown(F"Report {report_id} analysis results", info)
    ec = {
        'ThreatStream.SandboxReport': info,
        'ThreatStream.Network': network
    }

    return hm, ec


def parse_indicators_list(iocs_list):
    """
        Parses the indicator list and returns dictionary that will be set to context.
    """
    iocs_context = list(map(lambda i: {INDICATOR_EXTENDED_MAPPING[k]: v for (k, v) in i.items() if
                                       k in INDICATOR_EXTENDED_MAPPING.keys()}, iocs_list))

    for indicator in iocs_context:
        meta = indicator.pop('Meta', None)
        if meta:
            indicator['Severity'] = meta.get('severity', 'low')
        tags = indicator.get('Tags', [])
        if isinstance(tags, list):
            indicator['Tags'] = ",".join(list(map(lambda t: t.get('name', ''), tags)))

    return iocs_context


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Performs basic get request to get item samples
    """
    params = build_params(limit=1)
    http_request('GET', 'v2/intelligence/', params=params)
    demisto.results('ok')


def get_ip_reputation(ip, threshold="high", status="active,inactive"):
    """
        Checks the reputation of given ip from ThreatStream and
        returns the indicator with highest severity score.
    """
    params = build_params(value=ip, type="ip", status=status, limit=0)
    indicator = search_indicator_by_params(params, ip)
    dbot_context = get_dbot_context(indicator, threshold)
    ip_context = get_ip_context(indicator, threshold)
    threat_ip_context = get_threat_generic_context(indicator)

    ec = {
        'DBotScore(val.Indicator == obj.Indicator)': dbot_context,
        'IP(val.Address == obj.Address)': ip_context,
        'ThreatStream.IP(val.Address == obj.Address)': threat_ip_context
    }
    human_readable = tableToMarkdown(F"IP reputation for: {ip}", threat_ip_context)

    return_outputs(human_readable, ec, indicator)


def get_domain_reputation(domain, threshold="high", status="active,inactive"):
    """
        Checks the reputation of given domain from ThreatStream and
        returns the indicator with highest severity score.
    """
    params = build_params(value=domain, type="domain", status=status, limit=0)
    indicator = search_indicator_by_params(params, domain)
    dbot_context = get_dbot_context(indicator, threshold)
    domain_context = get_domain_context(indicator, threshold)
    threat_domain_context = get_threat_generic_context(indicator)

    ec = {
        'DBotScore(val.Indicator == obj.Indicator)': dbot_context,
        'Domain(val.Name == obj.Name)': domain_context,
        'ThreatStream.Domain(val.Address == obj.Address)': threat_domain_context
    }
    human_readable = tableToMarkdown(F"Domain reputation for: {domain}", threat_domain_context)

    return_outputs(human_readable, ec, indicator)


def get_file_reputation(md5, threshold="high", status="active,inactive"):
    """
        Checks the reputation of given md5 of the file from ThreatStream and
        returns the indicator with highest severity score.
    """
    params = build_params(value=md5, type="md5", status=status, limit=0)
    indicator = search_indicator_by_params(params, md5)
    dbot_context = get_dbot_context(indicator, threshold)
    file_context = get_file_context(indicator, threshold)
    threat_file_context = get_threat_generic_context(indicator)
    threat_file_context['MD5'] = threat_file_context.pop('Address')
    threat_file_context.pop("ASN", None)
    threat_file_context.pop("Organization", None)
    threat_file_context.pop("Country", None)

    ec = {
        'DBotScore(val.Indicator == obj.Indicator)': dbot_context,
        'File(val.MD5 == obj.MD5)': file_context,
        'ThreatStream.File(val.MD5 == obj.MD5)': threat_file_context
    }
    human_readable = tableToMarkdown(F"MD5 reputation for: {md5}", threat_file_context)

    return_outputs(human_readable, ec, indicator)


def get_url_reputation(url, threshold, status="active,inactive"):
    """
        Checks the reputation of given url address from ThreatStream and
        returns the indicator with highest severity score.
    """
    params = build_params(value=url, type="url", status=status, limit=0)
    indicator = search_indicator_by_params(params, url)
    dbot_context = get_dbot_context(indicator, threshold)
    domain_context = get_url_context(indicator, threshold)
    threat_url_context = get_threat_generic_context(indicator)
    del threat_url_context['ASN']

    ec = {
        'DBotScore(val.Indicator == obj.Indicator)': dbot_context,
        'URL(val.Data == obj.Data)': domain_context,
        'ThreatStream.URL(val.Address == obj.Address)': threat_url_context
    }
    human_readable = tableToMarkdown(F"URL reputation for: {url}", threat_url_context)

    return_outputs(human_readable, ec, indicator)


def get_email_reputation(email, threshold="high", status="active,inactive"):
    """
        Checks the reputation of given email address from ThreatStream and
        returns the indicator with highest severity score.
    """
    params = build_params(value=email, type="email", status=status, limit=0)
    indicator = search_indicator_by_params(params, email)
    dbot_context = get_dbot_context(indicator, threshold)
    threat_email_context = get_threat_generic_context(indicator)
    threat_email_context['Email'] = threat_email_context.pop('Address')
    threat_email_context.pop("ASN", None)
    threat_email_context.pop("Organization", None)
    threat_email_context.pop("Country", None)

    ec = {
        'DBotScore(val.Indicator == obj.Indicator)': dbot_context,
        'ThreatStream.EmailReputation(val.Email == obj.Email)': threat_email_context
    }
    human_readable = tableToMarkdown(F"Email reputation for: {email}", threat_email_context)

    return_outputs(human_readable, ec, indicator)


def get_passive_dns(value, type="ip", limit=50):
    """
        Receives value and type of indicator and returns
        enrichment data for domain or ip.
    """
    dns_results = http_request("GET", f"v1/pdns/{type}/{value}/", params=CREDENTIALS).get('results', None)

    if not dns_results:
        demisto.results(F"No Passive DNS enrichment data found for {value}")
        sys.exit()

    dns_results = dns_results[:int(limit)]
    output = camelize(dns_results, delim='_')

    ec = ({
        'ThreatStream.PassiveDNS': output
    })
    human_readable = tableToMarkdown(F"Passive DNS enrichment data for: {value}", output)

    return_outputs(human_readable, ec, dns_results)


def import_ioc_with_approval(import_type, import_value, confidence="50", classification="Private",
                             threat_type="exploit", severity="low"):
    """
        Imports indicators data to ThreatStream.
        The data can be imported using one of three import_types: data-text (plain-text),
        file-id of uploaded file to war room or URL.
    """
    data = {k: v for k, v in locals().items() if k not in ['import_type', 'import_value']}
    files = None
    uploaded_file = None

    if import_type == 'file-id':
        try:
            # import_value will be entry id of uploaded file to war room
            file_info = demisto.getFilePath(import_value)
        except Exception:
            return_error(F"Entry {import_value} does not contain a file.")

        uploaded_file = open(file_info['path'], 'rb')
        files = {'file': (file_info['name'], uploaded_file)}
    else:
        data[import_type] = import_value
    # in case import_type is not file-id, http_requests will receive None as files
    res = http_request("POST", "v1/intelligence/import/", params=CREDENTIALS, data=data, files=files)
    # closing the opened file if exist
    if uploaded_file:
        uploaded_file.close()
    # checking that response contains success key
    if res.get('success', False):
        imported_id = res.get('import_session_id', '')
        ec = {'ThreatStream.Import.ImportID': imported_id}
        return_outputs(F"The data was imported successfully. The ID of imported job is: {imported_id}", ec, res)
    else:
        return_outputs("The data was not imported. Check if valid arguments were passed")


def get_model_list(model, limit="50"):
    """
        Returns list of Threat Model that was specified. By default limit is set to 50 results.
        Possible values for model are : actor, campaign, incident, signature, ttp, vulnerability, tipreport
    """
    # if limit=0 don't put to context
    params = build_params(limit=limit, skip_intelligence="true", skip_associations="true")
    model_list = http_request("GET", F"v1/{model}/", params=params).get('objects', None)

    if not model_list:
        demisto.results(f"No Threat Model {model.title()} found.")
        sys.exit()

    threat_list_context = list(map(lambda m: {THREAT_MODEL_MAPPING[k]: v for (k, v) in m.items() if
                                              k in THREAT_MODEL_MAPPING.keys()}, model_list))
    for m in threat_list_context:
        m['Type'] = model.title()
    # in case that no limit was passed, the stage of set to context is skipped
    ec = {'ThreatStream.List': threat_list_context} if limit != '0' else None
    human_readable = tableToMarkdown(F"List of {model.title()}s", threat_list_context)

    return_outputs(human_readable, ec, model_list)


def get_model_description(model, id):
    """
        Returns a description of Threat Model as html file to the war room.
    """
    params = build_params(skip_intelligence="true", skip_associations="true")
    description = http_request("GET", F"v1/{model}/{id}", params=params)

    if model == 'signature':
        description = description.get('notes', None)
    elif model == 'tipreport':
        description = description.get('body', None)
    else:
        description = description.get('description', None)

    if not description:
        demisto.results(F"No description found for Threat Model {model.title()} with id {id}")
        sys.exit()

    demisto.results(fileResult(F"{model}_{id}.html", description.encode(encoding='UTF-8')))


def get_iocs_by_model(model, id, limit="20"):
    """
        Returns list of indicators associated with specific Threat Model by model id.
    """
    params = build_params(limit=limit)
    iocs_list = http_request("GET", F"v1/{model}/{id}/intelligence/", params=params).get('objects', None)

    if not iocs_list:
        demisto.results(F"No indicators found for Threat Model {model.title()} with id {id}")
        sys.exit()

    iocs_context = parse_indicators_list(iocs_list)

    ec = {
        'ThreatStream.Model(val.ModelID == obj.ModelID && val.ModelType == obj.ModelType)': {'ModelType': model.title(),
                                                                                             'ModelID': id,
                                                                                             'Indicators': iocs_context},
    }
    human_readable = tableToMarkdown(F"Indicators list for Threat Model {model.title()} with id {id}", iocs_context)

    return_outputs(human_readable, ec, iocs_list)


def create_model(model, name, is_public="false", tlp="red", tags=None, intelligence=None, description=None):
    """
        Creates Threat Model with basic parameters.
    """
    data = {k: v for k, v in locals().items() if v and k not in ['model', 'tags', 'intelligence']}
    if tags:
        data['tags'] = [t.strip() for t in tags.split(',')]
    if intelligence:
        data['intelligence'] = [i.strip() for i in intelligence.split(',')]

    created_id = http_request("POST", F"v1/{model}/", data=json.dumps(data), params=CREDENTIALS).get('id', None)

    if created_id:
        ec = {'ThreatStream.CreatedModel': {'ID': created_id, 'Model': model.title()}}
        return_outputs(f"{model.title()} Threat Model was created with {created_id} id", ec, created_id)
    else:
        demisto.results(f"{model.title()} Threat Model was not created. Check the input parameters")


def update_model(model, model_id, name=None, is_public="false", tlp=None, tags=None, intelligence=None,
                 description=None):
    """
        Updates a ThreatStream model with parameters. In case one or more optional parameters are
        defined, the previous data is overridden.
    """
    data = {k: v for k, v in locals().items() if v and k not in ['model', 'model_id', 'tags', 'intelligence']}
    if tags:
        data['tags'] = [t.strip() for t in tags.split(',')]
    if intelligence:
        data['intelligence'] = [i.strip() for i in intelligence.split(',')]

    model_name = http_request("PATCH", f"v1/{model}/{model_id}/", data=json.dumps(data), params=CREDENTIALS).get('name',
                                                                                                                 None)
    if model_name:
        demisto.results(f"The {model.title()} Threat Model with id {model_id} and name {model_name} was updated")
    else:
        demisto.results(
            F"The {model.title()} Threat Model with id {model_id} was not updated. Check the input parameters")


def supported_platforms(sandbox_type="default"):
    """
        Returns list of supported platforms for premium sandbox or default sandbox.
    """
    platform_data = http_request("GET", "v1/submit/parameters/", params=CREDENTIALS)
    available_platforms = platform_data.get('platform_choices', []) if sandbox_type == 'default' else platform_data.get(
        'premium_platform_choices',
        [])

    if available_platforms:
        supported_output = camelize(available_platforms)
        context_path = "ThreatStream.DefaultPlatforms" if sandbox_type == 'default' else "ThreatStream.PremiumPlatforms"

        return_outputs(tableToMarkdown(F"Supported platforms for {sandbox_type} sandbox", supported_output),
                       {context_path: supported_output}, platform_data)
    else:
        demisto.results(F"No supported platforms found for {sandbox_type} sandbox")


def get_submission_status(report_id, output=True):
    """
        Returns the sandbox submission status. If status is not received in report_info
        then status is set to done. Receives output boolean that prints the result to the war room.
        By default the output boolean is set to True.
    """
    report_info = http_request("GET", F"v1/submit/{report_id}/", params=CREDENTIALS, headers=HEADERS)

    if not report_info:
        demisto.results(F"No report found with id {report_id}")
        sys.exit()

    status = report_info.get('status', "done")
    verdict = report_info.get('verdict', '').title()
    platform = report_info.get('platform', '')

    if output:
        report_outputs = {'ID': report_id, 'Status': status, 'Platform': platform, 'Verdict': verdict}
        ec = {'ThreatStream.Sandbox(val.ID == obj.ID)': report_outputs}
        return_outputs(tableToMarkdown(F"The analysis status for id {report_id}", report_outputs), ec, report_info)
    return status, verdict


def submit_report(submission_type, submission_value, submission_classification="private", report_platform="WINDOWS7",
                  premium_sandbox="false", detail=None):
    """
        Detonates URL or file that was uploaded to war room to ThreatStream sandbox.
    """
    uploaded_file = None
    files = None

    data = {
        'report_radio-classification': submission_classification,
        'report_radio-platform': report_platform,
        'use_premium_sandbox': premium_sandbox,
    }
    if detail:
        data['detail'] = detail

    if submission_type == 'file':
        try:
            # submission_value will be entry id of uploaded file to war room
            file_info = demisto.getFilePath(submission_value)
        except Exception:
            return_error(F"Entry {submission_value} does not contain a file.")

        uploaded_file = open(file_info['path'], 'rb')
        files = {'report_radio-file': (file_info['name'], uploaded_file)}
    else:
        data['report_radio-url'] = submission_value

    res = http_request("POST", "v1/submit/new/", params=CREDENTIALS, data=data, files=files)
    # closing the opened file if exist
    if uploaded_file:
        uploaded_file.close()

    if str(res.get('success', '')).lower() == 'true':
        report_info = res['reports'][report_platform]
        report_id = report_info['id']
        report_status, _ = get_submission_status(report_id, False)

        report_outputs = {'ID': report_id, 'Status': report_status, 'Platform': report_platform}
        ec = {'ThreatStream.Sandbox': report_outputs}
        return_outputs(tableToMarkdown(F"The submission info for {submission_value}", report_outputs), ec, report_info)
    else:
        demisto.results(F"The submission of {submission_value} failed")


def get_report(report_id):
    """
        Returns the report from ThreatStream sandbox by id.
    """
    report = http_request("GET", F"v1/submit/{report_id}/report", params=CREDENTIALS, headers=HEADERS)
    if not report:
        demisto.results(F"No report found with id {report_id}")
        sys.exit()
    hm, ec = get_report_outputs(report.get('results', {}), report_id)

    return_outputs(hm, ec, report)


def add_tag_to_model(model_id, tags, model="intelligence"):
    """
        Adds tag to specific Threat Model. By default is set to intelligence (indicators).
    """
    data = {
        'tags': [{'name': t.strip(), 'tlp': 'red'} for t in tags.split(',')]
    }

    res = http_request("POST", F"v1/{model}/{model_id}/tag/", params=CREDENTIALS, data=json.dumps(data))

    if str(res.get('success', '')).lower() == 'true':
        return_outputs(F"Added successfully tags: {tags} to {model} with {model_id}", None, res)
    else:
        return_outputs(F"Failed to add {tags} to {model} with {model_id}", None, res)


def get_indicators(**kwargs):
    """
        Returns filtered indicators by parameters from ThreatStream.
        By default the limit of indicators result is set to 20.
    """
    if 'query' in kwargs:
        params = build_params(q=kwargs['query'], limit=kwargs.get('limit', 20))
    else:
        params = build_params(**kwargs)

    iocs_list = http_request("GET", "v2/intelligence/", params=params).get('objects', None)

    if not iocs_list:
        demisto.results('No indicators found from ThreatStream')
        sys.exit()

    iocs_context = parse_indicators_list(iocs_list)
    ec = {'ThreatStream.Indicators': iocs_context}
    return_outputs(tableToMarkdown("The indicators results", iocs_context), ec, iocs_list)


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))

try:
    args = prepare_args(demisto.args())
    if demisto.command() == 'test-module':
        test_module()
    elif demisto.command() == 'ip':
        get_ip_reputation(**args)
    elif demisto.command() == 'domain':
        get_domain_reputation(**args)
    elif demisto.command() == 'file':
        get_file_reputation(**args)
    elif demisto.command() == 'url':
        get_url_reputation(**args)
    elif demisto.command() == 'threatstream-email-reputation':
        get_email_reputation(**args)
    elif demisto.command() == 'threatstream-get-passive-dns':
        get_passive_dns(**args)
    elif demisto.command() == 'threatstream-import-indicator-with-approval':
        import_ioc_with_approval(**args)
    elif demisto.command() == 'threatstream-import-indicator-without-approval':
        # will be implemented in the future
        pass
    elif demisto.command() == 'threatstream-get-model-list':
        get_model_list(**args)
    elif demisto.command() == 'threatstream-get-model-description':
        get_model_description(**args)
    elif demisto.command() == 'threatstream-get-indicators-by-model':
        get_iocs_by_model(**args)
    elif demisto.command() == 'threatstream-create-model':
        create_model(**args)
    elif demisto.command() == 'threatstream-update-model':
        update_model(**args)
    elif demisto.command() == 'threatstream-submit-to-sandbox':
        submit_report(**args)
    elif demisto.command() == 'threatstream-get-analysis-status':
        get_submission_status(**args)
    elif demisto.command() == 'threatstream-analysis-report':
        get_report(**args)
    elif demisto.command() == 'threatstream-supported-platforms':
        supported_platforms(**args)
    elif demisto.command() == 'threatstream-get-indicators':
        get_indicators(**args)
    elif demisto.command() == 'threatstream-add-tag-to-model':
        add_tag_to_model(**args)

except Exception as e:
    if isinstance(e, MissingSchema):
        return_error("Not valid server url. Check url format")
    elif isinstance(e, InvalidSchema):
        return_error(e)
    elif isinstance(e, ConnectionError):
        return_error("The server is not reachable.")
    else:
        return_error(e)
