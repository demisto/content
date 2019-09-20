from CommonServerPython import *
import requests

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS '''

BASE_URL = 'http://api.domaintools.com'
USERNAME = demisto.params().get('username')
API_KEY = demisto.params().get('apikey')
RISK_THRESHOLD = int(demisto.params().get('risk_threshold'))
PIVOT_COUNT_THRESHOLD = int(demisto.params().get('pivot_count_threshold'))
YOUNG_DOMAIN_TIMEFRAME = int(demisto.params().get('young_domain_timeframe'))

''' HELPER FUNCTIONS '''


def http_request(method, path, other_params=None):
    """
    HTTP request helper function
    """
    params = {'app_partner': 'demisto', 'app_name': 'Iris Plugin', 'app_version': '1', 'api_username': USERNAME,
              'api_key': API_KEY}
    if other_params:
        params.update(other_params)
    url = '{}{}'.format(BASE_URL, path)
    res = requests.request(
        method=method,
        url=url,
        params=params
    )
    res_json = res.json()
    if not res.ok:
        txt = 'error in URL {} status code: {} reason: {}'.format(url, res.status_code,
                                                                  res_json['error'].get('message'))
        demisto.error(txt)
        raise Exception(txt)

    try:
        return res_json.get('response')
    except Exception as ex:
        demisto.debug(str(ex))
        demisto.results({"Type": entryTypes["error"], "ContentsFormat": formats["text"], "Contents": res.text})


def find_age(create_date):
    time_diff = datetime.now() - datetime.strptime(create_date, "%Y-%m-%d")
    return time_diff.days


def get_threat_component(components, threat_type):
    for component in components:
        if component['name'] == threat_type:
            return component
    else:
        return None


def convert_empty_to_null(data_obj):
    # Check for empty lists, dicts, and strs. Set to null if found to be empty.
    if isinstance(data_obj, dict) and (data_obj is None or len(data_obj) != 0):
        for k, v in data_obj.items():
            if isinstance(data_obj[k], dict) or isinstance(data_obj[k], list):
                convert_empty_to_null(data_obj[k])
            if not isinstance(v, int) and (v is None or len(v) == 0):
                data_obj[k] = None
    elif isinstance(data_obj, list) and (data_obj is None or len(data_obj) != 0):
        for index, item in enumerate(data_obj):
            convert_empty_to_null(item)
            if not isinstance(item, int) and (item is None or len(item) == 0):
                data_obj[index] = None


def create_context_output(domain_result):
    domain = domain_result['domain']
    ip_addresses = ', '.join([x['address']['value'] for x in domain_result['ip']])
    create_date = domain_result['create_date']['value']
    expiration_date = domain_result['expiration_date']['value']
    domain_name_servers = ', '.join([x['host']['value'] for x in domain_result['name_server']])
    name_servers = domain_result['name_server']
    domain_status = domain_result['active']

    proximity_risk_score = None
    threat_profile_risk_score = None
    threat_profile_threats = None
    threat_profile_evidence = None

    overall_risk_score = domain_result['domain_risk'].get('risk_score')
    if len(domain_result['domain_risk'].get('components')):
        # The index 0 refers to "proximity" or "blacklist"
        proximity_risk_score = domain_result['domain_risk']['components'][0]['risk_score']
        threat_profile_data = get_threat_component(domain_result['domain_risk']['components'], 'threat_profile')
        if threat_profile_data:
            threat_profile_risk_score = threat_profile_data['risk_score']
            threat_profile_threats = ', '.join(threat_profile_data.get('threats', []))
            threat_profile_evidence = ', '.join(threat_profile_data.get('evidence', []))

    website_response = domain_result['website_response']
    google_adsense = domain_result['adsense']['value']
    google_analytics = domain_result['google_analytics']['value']
    alexa_rank = domain_result['alexa']
    tags = domain_result['tags']

    registrant_name = domain_result['registrant_name']['value']
    registrant_org = domain_result['registrant_org']['value']
    domain_registrant_contact = {
        "Country": domain_result['registrant_contact']['country']["value"],
        "Email": ', '.join([x['value'] for x in domain_result['registrant_contact']['email']]),
        "Name": domain_result['registrant_contact']['name']["value"],
        "Phone": domain_result['registrant_contact']['phone']["value"],
    }
    registrant_contact = {
        "Country": domain_result['registrant_contact']['country'],
        "Email": domain_result['registrant_contact']['email'],
        "Name": domain_result['registrant_contact']['name'],
        "Phone": domain_result['registrant_contact']['phone'],
    }
    admin_contact = {
        "Country": domain_result['admin_contact']['country'],
        "Email": domain_result['admin_contact']['email'],
        "Name": domain_result['admin_contact']['name'],
        "Phone": domain_result['admin_contact']['phone'],
    }
    technical_contact = {
        "Country": domain_result['technical_contact']['country'],
        "Email": domain_result['technical_contact']['email'],
        "Name": domain_result['technical_contact']['name'],
        "Phone": domain_result['technical_contact']['phone'],
    }

    billing_contact = {
        "Country": domain_result['billing_contact']['country'],
        "Email": domain_result['billing_contact']['email'],
        "Name": domain_result['billing_contact']['name'],
        "Phone": domain_result['billing_contact']['phone'],
    }
    soa_email = [x['value'] for x in domain_result['soa_email']]
    ssl_email = [x['value'] for x in domain_result['ssl_email']]
    email_domains = [x['value'] for x in domain_result['email_domain']]
    additional_whois_emails = domain_result['additional_whois_email']
    domain_registrant = domain_result['registrar'].get('value') if isinstance(domain_result['registrar'], dict) else \
        domain_result['registrar']
    registrar_status = domain_result['registrar_status']
    ip_data = domain_result['ip']
    ip_country_code = domain_result['ip'][0] if len(domain_result['ip']) else ''
    mx_servers = domain_result['mx']
    spf_info = domain_result['spf_info']
    ssl_certificates = domain_result['ssl_info']
    redirects_to = domain_result['redirect']

    domain_tools_context = {
        "Name": domain,
        "LastEnriched": datetime.now().strftime('%Y-%m-%d'),
        "Analytics": {
            "OverallRiskScore": overall_risk_score,
            "ProximityRiskScore": proximity_risk_score,
            "ThreatProfileRiskScore": {"RiskScore": threat_profile_risk_score,
                                       "Threats": threat_profile_threats,
                                       "Evidence": threat_profile_evidence},
            "WebsiteResponseCode": website_response,
            "Alexa Rank": alexa_rank,
            "Tags": tags
        },
        "Identity": {
            "RegistrantName": registrant_name,
            "RegistrantOrg": registrant_org,
            "RegistrantContact": registrant_contact,
            "SOAEmail": soa_email,
            "SSLCertificateEmail": ssl_email,
            "AdminContact": admin_contact,
            "TechnicalContact": technical_contact,
            "BillingContact": billing_contact,
            "EmailDomains": email_domains,
            "AdditionalWhoisEmails": additional_whois_emails
        },
        "Registration": {
            "DomainRegistrant": domain_registrant,
            "RegistrarStatus": registrar_status,
            "DomainStatus": domain_status,
            "CreateDate": create_date,
            "ExpirationDate": expiration_date
        },
        "Hosting": {
            "IPAddresses": ip_data,
            "IPCountryCode": ip_country_code,
            "MailServers": mx_servers,
            "SPFRecord": spf_info,
            "NameServers": name_servers,
            "SSLCertificate": ssl_certificates,
            "RedirectsTo": redirects_to,
            "GoogleAdsenseTrackingCode": google_adsense,
            "GoogleAnalyticTrackingCode": google_analytics
        }
    }

    domain_context = {
        "Name": domain,
        "DNS": ip_addresses,
        "Vendor": "DomainTools",
        "CreationDate": create_date,
        "RiskScore": overall_risk_score,
        "DomainStatus": domain_status,
        "ExpirationDate": expiration_date,
        "NameServers": domain_name_servers,
        "Registrant": domain_registrant_contact,
        "DomainTools": domain_tools_context
    }
    if overall_risk_score and overall_risk_score >= RISK_THRESHOLD:
        domain_context["Malicious"] = {
            "Vendor": 'DomainTools',
            "Description": threat_profile_evidence
        }

    return domain_context


def format_domain_profile(response):
    domain_result = response['results'][0]
    domain_context = create_context_output(domain_result)
    outputs = {"Domain(val.Name == obj.Name)": domain_context}
    convert_empty_to_null(outputs)

    human_readable = '### DomainTools Profiled {}. See context data for more info.'.format(domain_result['domain'])
    return human_readable, outputs


def format_domain_analytics(response):
    domain_result = response['results'][0]
    overall_risk_score = domain_result['domain_risk']['risk_score']
    # The index 0 refers to "proximity" or "blacklist"
    proximity_risk_score = domain_result['domain_risk']['components'][0]['risk_score']
    domain_age = find_age(domain_result['create_date']['value'])
    website_response = domain_result['website_response']
    google_adsense = domain_result['adsense']['value']
    google_analytics = domain_result['google_analytics']['value']
    alexa_rank = domain_result['alexa']
    tags = ', '.join(domain_result['tags'])

    human_readable_data = {
        "Overall Risk Score": overall_risk_score,
        "Proximity Risk Score": proximity_risk_score,
        "Domain Age (in days)": domain_age,
        "Website Response": website_response,
        "Google Adsense": google_adsense,
        "Google Analytics": google_analytics,
        "Alexa Rank": alexa_rank,
        "Tags": tags
    }

    convert_empty_to_null(human_readable_data)

    outputs = {}

    headers = ["Overall Risk Score",
               "Proximity Risk Score",
               "Domain Age (in days)",
               "Website Response",
               "Google Adsense",
               "Google Analytics",
               "Alexa Rank",
               "Tags"]
    human_readable = tableToMarkdown('DomainTools Domain Analytics for {}.'.format(domain_result['domain']),
                                     human_readable_data,
                                     headers=headers)
    return human_readable, outputs


def format_threat_profile(response):
    domain_result = response['results'][0]
    domain_risk = domain_result['domain_risk']
    overall_risk_score = domain_risk['risk_score']
    threat_profile_data = get_threat_component(domain_risk['components'], 'threat_profile')
    if threat_profile_data:
        threat_profile_threats = ', '.join(threat_profile_data.get('threats', []))
        threat_profile_evidence = ', '.join(threat_profile_data.get('evidence', []))
    else:
        threat_profile_threats = None
        threat_profile_evidence = None

    human_readable_data = {
        "Overall Risk Score": overall_risk_score,
        "Threat Profile Threats": threat_profile_threats,
        "Threat Profile Evidence": threat_profile_evidence
    }

    outputs = {}

    headers = ['Overall Risk Score', 'Threat Profile Threats', 'Threat Profile Evidence']
    human_readable = tableToMarkdown('DomainTools Threat Profile for {}.'.format(domain_result['domain']),
                                     human_readable_data,
                                     headers=headers)
    return human_readable, outputs


def format_domain_pivot(response, search_type, search_value):
    domain_list = [x['domain'] for x in response['results']]
    human_readable_data = domain_list
    domain_context_list = []

    for domain_result in response['results']:
        domain_context = create_context_output(domain_result)
        domain_context_list.append(domain_context)
    outputs = {"PivotedDomains(val.Name == obj.Name)": domain_context_list}
    convert_empty_to_null(outputs)
    headers = ['Domains']
    human_readable = tableToMarkdown('Domains for {}: {}.'.format(search_type, search_value),
                                     human_readable_data,
                                     headers=headers)
    return human_readable, outputs


''' COMMANDS '''


def domain_profile():
    res = http_request('GET', '/v1/iris-investigate/', {'domain': demisto.args().get('domain')})
    if res.get('results_count'):
        human_readable, outputs = format_domain_profile(res)
        return_outputs(human_readable, outputs, res)
    else:
        demisto.results('No results found.')


def domain_analytics():
    res = http_request('GET', '/v1/iris-investigate/', {'domain': demisto.args().get('domain')})
    if res.get('results_count'):
        human_readable, outputs = format_domain_analytics(res)
        return_outputs(human_readable, outputs, res)
    else:
        demisto.results('No results found.')


def threat_profile():
    res = http_request('GET', '/v1/iris-investigate/', {'domain': demisto.args().get('domain')})
    if res.get('results_count'):
        human_readable, outputs = format_threat_profile(res)
        return_outputs(human_readable, outputs, res)
    else:
        demisto.results('No results found.')


def domain_pivot():
    res = None

    if demisto.args().get('ip'):
        res = http_request('GET', '/v1/iris-investigate/', {'ip': demisto.args().get('ip')})
        search_type, search_value = 'IP', demisto.args().get('ip')
    elif demisto.args().get('email'):
        res = http_request('GET', '/v1/iris-investigate/', {'email': demisto.args().get('email')})
        search_type, search_value = 'E-Mail', demisto.args().get('email')
    elif demisto.args().get('nameserver_ip'):
        res = http_request('GET', '/v1/iris-investigate/', {'nameserver_ip': demisto.args().get('nameserver_ip')})
        search_type, search_value = 'Name Server IP', demisto.args().get('nameserver_ip')
    elif demisto.args().get('ssl_hash'):
        res = http_request('GET', '/v1/iris-investigate/', {'ssl_hash': demisto.args().get('ssl_hash')})
        search_type, search_value = 'SSL Hash', demisto.args().get('ssl_hash')
    elif demisto.args().get('nameserver_host'):
        res = http_request('GET', '/v1/iris-investigate/', {'nameserver_host': demisto.args().get('nameserver_host')})
        search_type, search_value = 'Name Server Host', demisto.args().get('nameserver_host')
    elif demisto.args().get('mailserver_host'):
        res = http_request('GET', '/v1/iris-investigate/', {'mailserver_host': demisto.args().get('mailserver_host')})
        search_type, search_value = 'Mail Server Host', demisto.args().get('mailserver_host')

    if res.get('results_count'):
        human_readable, outputs = format_domain_pivot(res, search_type, search_value)
        return_outputs(human_readable, outputs, res)
    else:
        demisto.results('No results found.')


def test_module():
    res = http_request('GET', '/v1/iris-investigate/', {'domain': 'demisto.com'})
    if res.get('results_count'):
        demisto.results('ok')
    else:
        demisto.results('No results found.')


try:
    if demisto.command() == 'test-module':
        test_module()
    elif demisto.command() == 'domain':
        domain_profile()
    elif demisto.command() == 'domain-analytics':
        domain_analytics()
    elif demisto.command() == 'threat-profile':
        threat_profile()
    elif demisto.command() == 'domain-pivot':
        domain_pivot()
except Exception as e:
    return_error('Unable to perform command : {}, Reason: {}'.format(demisto.command(), e))
