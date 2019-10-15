from CommonServerPython import *
import requests

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS '''

BASE_URL = 'http://api.domaintools.com'
USERNAME = demisto.params().get('username')
API_KEY = demisto.params().get('apikey')
RISK_THRESHOLD = int(demisto.params().get('risk_threshold'))
YOUNG_DOMAIN_TIMEFRAME = int(demisto.params().get('young_domain_timeframe'))

''' HELPER FUNCTIONS '''


def http_request(method, path, other_params=None):
    """
    HTTP request helper function
    Args:
        method: HTTP Method
        path: part of the url
        other_params:

    Returns: request result

    """
    params = {'app_partner': 'demisto',
              'app_name': 'Iris Plugin',
              'app_version': '1',
              'api_username': USERNAME,
              'api_key': API_KEY}
    if other_params:
        params.update(other_params)
    url = '{}{}'.format(BASE_URL, path)
    res = requests.request(
        method=method,
        url=url,
        params=params
    )
    res_json = {}
    try:
        res_json = res.json()
    except json.JSONDecodeError as json_error:
        demisto.error(json_error)

    if not res.ok:
        error_message = res_json.get('error', {}).get('message')
        txt = 'error in URL {} status code: {} reason: {}'.format(url, res.status_code, error_message)
        demisto.error(txt)

    return res_json.get('response')


def get_dbot_score(proximity_score, age, threat_profile_score):
    """
    Gets the DBot score
    Args:
        proximity_score:
        age:
        threat_profile_score:

    Returns: DBot Score

    """
    if proximity_score >= RISK_THRESHOLD or threat_profile_score >= RISK_THRESHOLD:
        return 'Bad'
    elif age < YOUNG_DOMAIN_TIMEFRAME and (proximity_score < RISK_THRESHOLD or threat_profile_score < RISK_THRESHOLD):
        return 'Suspicious'
    else:
        return 'Good'


def find_age(create_date):
    """
    Finds how many days old a domain is given a start date.
    Args:
        create_date: Date in the form of %Y-%m-%d'

    Returns: Number of days

    """
    time_diff = datetime.now() - datetime.strptime(create_date, '%Y-%m-%d')
    return time_diff.days


def get_threat_component(components, threat_type):
    """
    Gets a certain threat component out a list of components
    Args:
        components: List of threat components
        threat_type: Type of threat we are looking for

    Returns: Either the component that we asked for or None

    """
    for component in components:
        if component.get('name') == threat_type:
            return component
    else:
        return None


def convert_empty_to_null(data_obj):
    """
    Does a deep dive through a data object to convert items to null
    Args:
        data_obj: Either a list or dict that needs to be cleaned
    """
    # Check for empty lists, dicts, and strs. Set to null if found to be empty.
    if isinstance(data_obj, dict) and len(data_obj) != 0:
        for k, v in data_obj.items():
            if isinstance(data_obj[k], dict) or isinstance(data_obj[k], list):
                convert_empty_to_null(data_obj[k])
            if not isinstance(v, int) and (v is None or len(v) == 0):
                data_obj[k] = None
    elif isinstance(data_obj, list) and len(data_obj) != 0:
        for index, item in enumerate(data_obj):
            convert_empty_to_null(item)
            if not isinstance(item, int) and (item is None or len(item) == 0):
                data_obj[index] = None


def create_domain_context_outputs(domain_result):
    """
    Creates all the context data necessary given a domain result
    Args:
        domain_result: DomainTools domain data

    Returns: Dict with context data

    """
    domain = domain_result.get('domain')
    ip_addresses = ', '.join([x.get('address').get('value') for x in domain_result.get('ip')])
    create_date = domain_result.get('create_date', {}).get('value')
    expiration_date = domain_result.get('expiration_date', {}).get('value')
    domain_name_servers = ', '.join([x.get('host').get('value') for x in domain_result.get('name_server')])
    name_servers = domain_result.get('name_server')
    domain_status = domain_result.get('active')

    proximity_risk_score = 0
    threat_profile_risk_score = 0
    threat_profile_threats = ''
    threat_profile_evidence = ''

    overall_risk_score = domain_result.get('domain_risk', {}).get('risk_score')
    risk_components = domain_result.get('domain_risk', {}).get('components')
    if risk_components:
        proximity_data = get_threat_component(risk_components, 'proximity')
        blacklist_data = get_threat_component(risk_components, 'blacklist')
        if proximity_data:
            proximity_risk_score = proximity_data.get('risk_score')
        elif blacklist_data:
            proximity_risk_score = blacklist_data.get('risk_score')
        threat_profile_data = get_threat_component(risk_components, 'threat_profile')
        if threat_profile_data:
            threat_profile_risk_score = threat_profile_data.get('risk_score')
            threat_profile_threats = ', '.join(threat_profile_data.get('threats', []))
            threat_profile_evidence = ', '.join(threat_profile_data.get('evidence', []))

    website_response = domain_result.get('website_response')
    google_adsense = domain_result.get('adsense', {}).get('value')
    google_analytics = domain_result.get('google_analytics', {}).get('value')
    alexa_rank = domain_result.get('alexa')
    tags = domain_result.get('tags')

    registrant_name = domain_result.get('registrant_name', {}).get('value')
    registrant_org = domain_result.get('registrant_org', {}).get('value')
    domain_registrant_contact = {
        'Country': domain_result.get('registrant_contact').get('country').get('value'),
        'Email': ', '.join([x.get('value') for x in domain_result.get('registrant_contact').get('email')]),
        'Name': domain_result.get('registrant_contact').get('name').get('value'),
        'Phone': domain_result.get('registrant_contact').get('phone').get('value'),
    }
    registrant_contact = {
        'Country': domain_result.get('registrant_contact').get('country'),
        'Email': domain_result.get('registrant_contact').get('email'),
        'Name': domain_result.get('registrant_contact').get('name'),
        'Phone': domain_result.get('registrant_contact').get('phone'),
    }
    admin_contact = {
        'Country': domain_result.get('admin_contact').get('country'),
        'Email': domain_result.get('admin_contact').get('email'),
        'Name': domain_result.get('admin_contact').get('name'),
        'Phone': domain_result.get('admin_contact').get('phone'),
    }
    technical_contact = {
        'Country': domain_result.get('technical_contact').get('country'),
        'Email': domain_result.get('technical_contact').get('email'),
        'Name': domain_result.get('technical_contact').get('name'),
        'Phone': domain_result.get('technical_contact').get('phone'),
    }

    billing_contact = {
        'Country': domain_result.get('billing_contact').get('country'),
        'Email': domain_result.get('billing_contact').get('email'),
        'Name': domain_result.get('billing_contact').get('name'),
        'Phone': domain_result.get('billing_contact').get('phone'),
    }
    soa_email = [x.get('value') for x in domain_result.get('soa_email')]
    ssl_email = [x.get('value') for x in domain_result.get('ssl_email')]
    email_domains = [x.get('value') for x in domain_result.get('email_domain')]
    additional_whois_emails = domain_result.get('additional_whois_email')
    domain_registrant = domain_result.get('registrar', {}).get('value') if isinstance(domain_result.get('registrar'),
                                                                                  dict) else domain_result.get(
        'registrar')
    registrar_status = domain_result.get('registrar_status')
    ip_data = domain_result.get('ip')
    ip_country_code = domain_result.get('ip')[0] if domain_result.get('ip') else ''
    mx_servers = domain_result.get('mx')
    spf_info = domain_result.get('spf_info')
    ssl_certificates = domain_result.get('ssl_info')
    redirects_to = domain_result.get('redirect')

    domain_tools_context = {
        'Name': domain,
        'LastEnriched': datetime.now().strftime('%Y-%m-%d'),
        'Analytics': {
            'OverallRiskScore': overall_risk_score,
            'ProximityRiskScore': proximity_risk_score,
            'ThreatProfileRiskScore': {'RiskScore': threat_profile_risk_score,
                                       'Threats': threat_profile_threats,
                                       'Evidence': threat_profile_evidence},
            'WebsiteResponseCode': website_response,
            'AlexaRank': alexa_rank,
            'Tags': tags
        },
        'Identity': {
            'RegistrantName': registrant_name,
            'RegistrantOrg': registrant_org,
            'RegistrantContact': registrant_contact,
            'SOAEmail': soa_email,
            'SSLCertificateEmail': ssl_email,
            'AdminContact': admin_contact,
            'TechnicalContact': technical_contact,
            'BillingContact': billing_contact,
            'EmailDomains': email_domains,
            'AdditionalWhoisEmails': additional_whois_emails
        },
        'Registration': {
            'DomainRegistrant': domain_registrant,
            'RegistrarStatus': registrar_status,
            'DomainStatus': domain_status,
            'CreateDate': create_date,
            'ExpirationDate': expiration_date
        },
        'Hosting': {
            'IPAddresses': ip_data,
            'IPCountryCode': ip_country_code,
            'MailServers': mx_servers,
            'SPFRecord': spf_info,
            'NameServers': name_servers,
            'SSLCertificate': ssl_certificates,
            'RedirectsTo': redirects_to,
            'GoogleAdsenseTrackingCode': google_adsense,
            'GoogleAnalyticTrackingCode': google_analytics
        }
    }

    domain_context = {
        'Name': domain,
        'DNS': ip_addresses,
        'Vendor': 'DomainTools',
        'CreationDate': create_date,
        'RiskScore': overall_risk_score,
        'DomainStatus': domain_status,
        'ExpirationDate': expiration_date,
        'NameServers': domain_name_servers,
        'Registrant': domain_registrant_contact
    }
    if overall_risk_score and overall_risk_score >= RISK_THRESHOLD:
        domain_context['Malicious'] = {
            'Vendor': 'DomainTools',
            'Description': threat_profile_evidence
        }
    dbot_score = 'Unknown'
    if create_date != '':
        domain_age = find_age(create_date)
        get_dbot_score(proximity_risk_score, domain_age, threat_profile_risk_score)
    dbot_context = {'Indicator': domain,
                    'Type': 'domain',
                    'Vendor': 'DomainTools',
                    'Score': dbot_score}
    outputs = {'domain': domain_context,
               'domaintools': domain_tools_context,
               'dbotscore': dbot_context}
    return outputs


def domain_profile(domain):
    """
    Profiles domain and gives back all relevant domain data
    Args:
        domain:

    Returns: All data relevant for Demisto command.

    """
    results = {'human_readable': 'No results found.', 'context': {}, 'raw': None}
    response = http_request('GET', '/v1/iris-investigate/', {'domain': domain})
    results['raw'] = response
    if response.get('results_count'):
        domain_result = response.get('results')[0]
        context = create_domain_context_outputs(domain_result)
        outputs = {'Domain(val.Name && val.Name == obj.Name)': context.get('domain'),
                   'DomainTools.Domains(val.Name && val.Name == obj.Name)': context.get('domaintools'),
                   'DBotScore': context.get('dbotscore')}
        convert_empty_to_null(outputs)

        human_readable_data = {
            'Name': domain,
            'Last Enriched': datetime.now().strftime('%Y-%m-%d'),
            'Overall Risk Score': context.get('domaintools').get('Analytics').get('OverallRiskScore'),
            'Proximity Risk Score': context.get('domaintools').get('Analytics').get('ProximityRiskScore'),
            'Threat Profile Risk Score': context.get('domaintools').get('Analytics').get('ThreatProfileRiskScore').get(
                'RiskScore'),
            'Threat Profile Threats': context.get('domaintools').get('Analytics').get('ThreatProfileRiskScore').get(
                'Threats'),
            'Threat Profile Evidence': context.get('domaintools').get('Analytics').get('ThreatProfileRiskScore').get(
                'Evidence'),
            'Website Response Code': context.get('domaintools').get('Analytics').get('WebsiteResponseCode'),
            'Alexa Rank': context.get('domaintools').get('Analytics').get('AlexaRank'),
            'Tags': context.get('domaintools').get('Analytics').get('Tags'),
            'Registrant Name': context.get('domaintools').get('Identity').get('RegistrantName'),
            'Registrant Org': context.get('domaintools').get('Identity').get('RegistrantOrg'),
            'Registrant Contact': context.get('domaintools').get('Identity').get('RegistrantContact'),
            'SOA Email': context.get('domaintools').get('Identity').get('SOAEmail'),
            'SSL Certificate Email': context.get('domaintools').get('Identity').get('SSLCertificateEmail'),
            'Admin Contact': context.get('domaintools').get('Identity').get('AdminContact'),
            'Technical Contact': context.get('domaintools').get('Identity').get('TechnicalContact'),
            'Billing Contact': context.get('domaintools').get('Identity').get('BillingContact'),
            'Email Domains': context.get('domaintools').get('Identity').get('EmailDomains'),
            'Additional Whois Emails': context.get('domaintools').get('Identity').get('AdditionalWhoisEmails'),
            'Domain Registrant': context.get('domaintools').get('Registration').get('DomainRegistrant'),
            'Registrar Status': context.get('domaintools').get('Registration').get('RegistrarStatus'),
            'Domain Status': context.get('domaintools').get('Registration').get('DomainStatus'),
            'Create Date': context.get('domaintools').get('Registration').get('CreateDate'),
            'Expiration Date': context.get('domaintools').get('Registration').get('ExpirationDate'),
            'IP Addresses': context.get('domaintools').get('Hosting').get('IPAddresses'),
            'IP Country Code': context.get('domaintools').get('Hosting').get('IPCountryCode'),
            'Mail Servers': context.get('domaintools').get('Hosting').get('MailServers'),
            'SPF Record': context.get('domaintools').get('Hosting').get('SPFRecord'),
            'Name Servers': context.get('domaintools').get('Hosting').get('NameServers'),
            'SSL Certificate': context.get('domaintools').get('Hosting').get('SSLCertificate'),
            'Redirects To': context.get('domaintools').get('Hosting').get('RedirectsTo'),
            'Google Adsense Tracking Code': context.get('domaintools').get('Hosting').get('GoogleAdsenseTrackingCode'),
            'Google Analytic Tracking Code': context.get('domaintools').get('Hosting').get('GoogleAnalyticTrackingCode')
        }

        headers = [
            'Name',
            'Last Enriched',
            'Overall Risk Score',
            'Proximity Risk Score',
            'Threat Profile Risk Score',
            'Threat Profile Threats',
            'Threat Profile Evidence',
            'Website Response Code',
            'Alexa Rank',
            'Tags',
            'Registrant Name',
            'Registrant Org',
            'Registrant Contact',
            'SOA Email',
            'SSL Certificate Email',
            'Admin Contact',
            'Technical Contact',
            'Billing Contact',
            'Email Domains',
            'Additional Whois Emails',
            'Domain Registrant',
            'Registrar Status',
            'Domain Status',
            'Create Date',
            'Expiration Date',
            'IP Addresses',
            'IP Country Code',
            'Mail Servers',
            'SPF Record',
            'Name Servers',
            'SSL Certificate',
            'Redirects To',
            'Google Adsense Tracking Code',
            'Google Analytic Tracking Code'
        ]
        human_readable = tableToMarkdown('DomainTools Domain Profile for {}.'.format(domain_result.get('domain')),
                                         human_readable_data,
                                         headers=headers)
        results['human_readable'] = human_readable
        results['context'] = outputs
    return results


def domain_analytics(domain):
    """
    Analytics profile of a domain.
    Args:
        domain (str):

    Returns: All data relevant for Demisto command.

    """
    results = {'human_readable': 'No results found.', 'context': {}, 'raw': None}
    response = http_request('GET', '/v1/iris-investigate/', {'domain': domain})
    results['raw'] = response
    if response.get('results_count'):
        domain_result = response.get('results')[0]
        context = create_domain_context_outputs(domain_result)
        outputs = {'Domain(val.Name && val.Name == obj.Name)': context.get('domain'),
                   'DomainTools.Domains(val.Name && val.Name == obj.Name)': context.get('domaintools'),
                   'DBotScore': context.get('dbotscore')}
        convert_empty_to_null(outputs)

        human_readable_data = {
            'Overall Risk Score': context.get('domaintools').get('Analytics').get('OverallRiskScore'),
            'Proximity Risk Score': context.get('domaintools').get('Analytics').get('ProximityRiskScore'),
            'Threat Profile Risk Score': context.get('domaintools').get('Analytics').get('ThreatProfileRiskScore').get(
                'RiskScore'),
            'Domain Age (in days)': find_age(context.get('domaintools').get('Registration').get('CreateDate')),
            'Website Response': context.get('domaintools').get('Analytics').get('WebsiteResponseCode'),
            'Google Adsense': context.get('domaintools').get('Hosting').get('GoogleAdsenseTrackingCode'),
            'Google Analytics': context.get('domaintools').get('Hosting').get('GoogleAnalyticsTrackingCode'),
            'Alexa Rank': context.get('domaintools').get('Analytics').get('AlexaRank'),
            'Tags': context.get('domaintools').get('Analytics').get('Tags'),
        }

        convert_empty_to_null(human_readable_data)

        headers = ['Overall Risk Score',
                   'Proximity Risk Score',
                   'Domain Age (in days)',
                   'Website Response',
                   'Google Adsense',
                   'Google Analytics',
                   'Alexa Rank',
                   'Tags']
        human_readable = tableToMarkdown('DomainTools Domain Analytics for {}.'.format(domain_result.get('domain')),
                                         human_readable_data,
                                         headers=headers)
        results['human_readable'] = human_readable
        results['context'] = outputs
    return results


def threat_profile(domain):
    """
    Threat profiles a domain.
    Args:
        domain:

    Returns: All data relevant for Demisto command.

    """
    results = {'human_readable': 'No results found.', 'context': {}, 'raw': None}
    response = http_request('GET', '/v1/iris-investigate/', {'domain': domain})
    results['raw'] = response
    if response.get('results_count'):
        domain_result = response.get('results')[0]
        context = create_domain_context_outputs(domain_result)
        outputs = {'Domain(val.Name && val.Name == obj.Name)': context.get('domain'),
                   'DomainTools.Domains(val.Name && val.Name == obj.Name)': context.get('domaintools'),
                   'DBotScore': context.get('dbotscore')}
        convert_empty_to_null(outputs)
        proximity_risk_score = 0
        threat_profile_risk_score = 0
        threat_profile_malware_risk_score = 0
        threat_profile_phishing_risk_score = 0
        threat_profile_spam_risk_score = 0
        threat_profile_threats = ''
        threat_profile_evidence = ''

        overall_risk_score = domain_result.get('domain_risk').get('risk_score')
        risk_components = domain_result.get('domain_risk').get('components')
        if len(risk_components):
            proximity_data = get_threat_component(risk_components, 'proximity')
            blacklist_data = get_threat_component(risk_components, 'blacklist')
            if proximity_data:
                proximity_risk_score = proximity_data.get('risk_score')
            elif blacklist_data:
                proximity_risk_score = blacklist_data.get('risk_score')
            threat_profile_data = get_threat_component(risk_components, 'threat_profile')
            if threat_profile_data:
                threat_profile_risk_score = threat_profile_data.get('risk_score')
                threat_profile_threats = ', '.join(threat_profile_data.get('threats', []))
                threat_profile_evidence = ', '.join(threat_profile_data.get('evidence', []))
            threat_profile_malware_data = get_threat_component(risk_components, 'threat_profile_malware')
            if threat_profile_malware_data:
                threat_profile_malware_risk_score = threat_profile_malware_data.get('risk_score')
            threat_profile_phshing_data = get_threat_component(risk_components, 'threat_profile_phishing')
            if threat_profile_phshing_data:
                threat_profile_phishing_risk_score = threat_profile_phshing_data.get('risk_score')
            threat_profile_spam_data = get_threat_component(risk_components, 'threat_profile_spam')
            if threat_profile_spam_data:
                threat_profile_spam_risk_score = threat_profile_spam_data.get('risk_score')

        human_readable_data = {
            'Overall Risk Score': overall_risk_score,
            'Proximity Risk Score': proximity_risk_score,
            'Threat Profile Risk Score': threat_profile_risk_score,
            'Threat Profile Threats': threat_profile_threats,
            'Threat Profile Evidence': threat_profile_evidence,
            'Threat Profile Malware Risk Score': threat_profile_malware_risk_score,
            'Threat Profile Phishing Risk Score': threat_profile_phishing_risk_score,
            'Threat Profile Spam Risk Score': threat_profile_spam_risk_score
        }

        headers = ['Overall Risk Score',
                   'Proximity Risk Score',
                   'Threat Profile Risk Score'
                   'Threat Profile Threats',
                   'Threat Profile Evidence',
                   'Threat Profile Malware Risk Score',
                   'Threat Profile Phishing Risk Score',
                   'Threat Profile Spam Risk Score']
        human_readable = tableToMarkdown('DomainTools Threat Profile for {}.'.format(domain_result['domain']),
                                         human_readable_data,
                                         headers=headers)
        results['human_readable'] = human_readable
        results['context'] = outputs
    return results


def domain_pivot(search_data, search_type, search_value):
    """
    Pivots on a domain given a search type and search value.
    Args:
        search_data:
        search_type:
        search_value:

    Returns: All data relevant for Demisto command.

    """
    results = {'human_readable': 'No results found.', 'context': {}, 'raw': None}
    response = http_request('GET', '/v1/iris-investigate/', search_data)
    results['raw'] = response
    human_readable_data = []
    domain_context_list = []
    if response.get('results_count'):
        for domain_result in response.get('results'):
            human_readable_data.append(domain_result.get('domain'))
            domain_context = create_domain_context_outputs(domain_result)
            domain_context_list.append(domain_context.get('domaintools'))
        outputs = {'DomainTools.PivotedDomains(val.Name == obj.Name)': domain_context_list}
        convert_empty_to_null(outputs)
        headers = ['Domains']
        human_readable = tableToMarkdown('Domains for {}: {}.'.format(search_type, search_value),
                                         human_readable_data,
                                         headers=headers)
        results['human_readable'] = human_readable
        results['context'] = outputs
    return results


''' COMMANDS '''


def domain_profile_command():
    """
    Command to do a total profile of a domain.
    """
    domain = demisto.args().get('domain')
    results = domain_profile(domain)
    return_outputs(results.get('human_readable'), results.get('context'), results.get('raw'))


def domain_analytics_command():
    """
    Command to do a analytics profile of a domain.
    """
    domain = demisto.args().get('domain')
    results = domain_analytics(domain)
    return_outputs(results.get('human_readable'), results.get('context'), results.get('raw'))


def threat_profile_command():
    """
    Command to do a threat profile of a domain.
    """
    domain = demisto.args().get('domain')
    results = threat_profile(domain)
    return_outputs(results.get('human_readable'), results.get('context'), results.get('raw'))


def domain_pivot_command():
    """
    Command to do a domain pivot lookup.
    """
    data = {}
    search_type = ''
    search_value = ''
    if demisto.args().get('ip'):
        data = {'ip': demisto.args().get('ip')}
        search_type, search_value = 'IP', demisto.args().get('ip')
    elif demisto.args().get('email'):
        data = {'email': demisto.args().get('email')}
        search_type, search_value = 'E-Mail', demisto.args().get('email')
    elif demisto.args().get('nameserver_ip'):
        data = {'nameserver_ip': demisto.args().get('nameserver_ip')}
        search_type, search_value = 'Name Server IP', demisto.args().get('nameserver_ip')
    elif demisto.args().get('ssl_hash'):
        data = {'ssl_hash': demisto.args().get('ssl_hash')}
        search_type, search_value = 'SSL Hash', demisto.args().get('ssl_hash')
    elif demisto.args().get('nameserver_host'):
        data = {'nameserver_host': demisto.args().get('nameserver_host')}
        search_type, search_value = 'Name Server Host', demisto.args().get('nameserver_host')
    elif demisto.args().get('mailserver_host'):
        data = {'mailserver_host': demisto.args().get('mailserver_host')}
        search_type, search_value = 'Mail Server Host', demisto.args().get('mailserver_host')

    results = domain_pivot(data, search_type, search_value)
    return_outputs(results.get('human_readable'), results.get('context'), results.get('raw'))


def test_module():
    """
    Tests the API key for a user.
    """
    try:
        http_request('GET', '/v1/iris-investigate/', {'domain': 'demisto.com'})
        demisto.results('ok')
    except Exception as test_error:
        return_error('Unable to perform command : {}, Reason: {}'.format(demisto.command(), str(test_error)))


# def main():
"""
Main Demisto function.
"""
try:
    if demisto.command() == 'test-module':
        test_module()
    elif demisto.command() == 'domain':
        domain_profile_command()
    elif demisto.command() == 'domaintoolsiris-analytics':
        domain_analytics_command()
    elif demisto.command() == 'domaintoolsiris-threat-profile':
        threat_profile_command()
    elif demisto.command() == 'domaintoolsiris-pivot':
        domain_pivot_command()
except Exception as e:
    return_error('Unable to perform command : {}, Reason: {}'.format(demisto.command(), str(e)))

# if __name__ in ['__main__', 'builtin', 'builtins']:
#     main()
