import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import requests
import dateparser
from typing import Dict, Any
import warnings
warnings.simplefilter("ignore", UserWarning)


# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS '''

BASE_URL = demisto.params().get('base_url')
if not BASE_URL:
    BASE_URL = 'http://api.domaintools.com'  # we keep old http url for backwards comp
USERNAME = demisto.params().get('username')
API_KEY = demisto.params().get('apikey')
RISK_THRESHOLD = int(demisto.params().get('risk_threshold'))
YOUNG_DOMAIN_TIMEFRAME = int(demisto.params().get('young_domain_timeframe'))
VERIFY_CERT = not demisto.params().get('insecure', False)
PROXIES = handle_proxy()

''' HELPER FUNCTIONS '''


def http_request(method, path, other_params=None):
    """
    HTTP request helper function
    Args:
        method: HTTP Method
        path: part of the url
        other_params: Anything else that needs to be in the request

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
        params=params,
        verify=VERIFY_CERT,
        proxies=PROXIES
    )

    try:
        res_json = res.json()
    except json.JSONDecodeError:
        demisto.error(res.text)
        raise

    if not res.ok:
        error_message = res_json.get('error', {}).get('message')
        txt = 'error in URL {} status code: {} reason: {}'.format(url, res.status_code, error_message)
        demisto.error(txt)
        res.raise_for_status()

    return res_json.get('response')


def get_dbot_score(proximity_score, age, threat_profile_score):
    """
    Gets the DBot score
    Args:
        proximity_score: The proximity threat score deals with closeness to other malicious domains.
        age: The age of the domain.
        threat_profile_score: The threat profile score looking at things like phishing and spam.

    Returns: DBot Score

    """
    if proximity_score >= RISK_THRESHOLD or threat_profile_score >= RISK_THRESHOLD:
        return 3
    elif age < YOUNG_DOMAIN_TIMEFRAME and (proximity_score < RISK_THRESHOLD or threat_profile_score < RISK_THRESHOLD):
        return 2
    else:
        return 1


def find_age(create_date):
    """
    Finds how many days old a domain is given a start date.
    Args:
        create_date: Date in the form of %Y-%m-%d'

    Returns: Number of days

    """
    time_diff = datetime.now() - dateparser.parse(create_date)
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


def prune_context_data(data_obj):
    """
    Does a deep dive through a data object to prune any null or empty items. Checks for empty lists, dicts, and strs.
    Args:
        data_obj: Either a list or dict that needs to be pruned
    """
    items_to_prune = []
    if isinstance(data_obj, dict) and len(data_obj):
        for k, v in data_obj.items():
            if isinstance(data_obj[k], dict) or isinstance(data_obj[k], list):
                prune_context_data(data_obj[k])
            if not isinstance(v, int) and not v:
                items_to_prune.append(k)
            elif k == 'count' and v == 0:
                items_to_prune.append(k)
        for k in items_to_prune:
            del data_obj[k]
    elif isinstance(data_obj, list) and len(data_obj):
        for index, item in enumerate(data_obj):
            prune_context_data(item)
            if not isinstance(item, int) and not item:
                items_to_prune.append(index)
        data_obj[:] = [item for index, item in enumerate(data_obj) if index not in items_to_prune and len(item)]


def create_domain_context_outputs(domain_result):
    """
    Creates all the context data necessary given a domain result
    Args:
        domain_result: DomainTools domain data

    Returns: Dict with context data

    """
    domain = domain_result.get('domain')
    ip_addresses = domain_result.get('ip')
    create_date = domain_result.get('create_date', {}).get('value')
    expiration_date = domain_result.get('expiration_date', {}).get('value')
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
            threat_profile_threats = threat_profile_data.get('threats')
            threat_profile_evidence = threat_profile_data.get('evidence')

    website_response = domain_result.get('website_response')
    google_adsense = domain_result.get('adsense', {}).get('value')
    google_analytics = domain_result.get('google_analytics', {}).get('value')
    alexa_rank = domain_result.get('alexa')
    tags = domain_result.get('tags')

    registrant_name = domain_result.get('registrant_name', {}).get('value')
    registrant_org = domain_result.get('registrant_org', {}).get('value')
    contact_options = ['registrant_contact', 'admin_contact', 'technical_contact', 'billing_contact']
    contact_dict = {}
    for option in contact_options:
        contact_data = domain_result.get(option, {})
        contact_dict[option] = {
            'Country': contact_data.get('country'),
            'Email': contact_data.get('email'),
            'Name': contact_data.get('name'),
            'Phone': contact_data.get('phone'),
        }
    soa_email = [soa_email.get('value') for soa_email in domain_result.get('soa_email')]
    ssl_email = [ssl_email.get('value') for ssl_email in domain_result.get('ssl_email')]
    email_domains = [email_domain.get('value') for email_domain in domain_result.get('email_domain')]
    additional_whois_emails = domain_result.get('additional_whois_email')
    domain_registrant = domain_result.get('registrar')
    if isinstance(domain_registrant, dict):
        domain_registrant = domain_registrant.get('value')
    registrar_status = domain_result.get('registrar_status')
    ip_country_code = ip_addresses[0].get('country_code', {}).get('value') if len(ip_addresses) else ''
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
            'GoogleAdsenseTrackingCode': google_adsense,
            'GoogleAnalyticTrackingCode': google_analytics,
            'AlexaRank': alexa_rank,
            'Tags': tags
        },
        'Identity': {
            'RegistrantName': registrant_name,
            'RegistrantOrg': registrant_org,
            'RegistrantContact': contact_dict.get('registrant_contact'),
            'SOAEmail': soa_email,
            'SSLCertificateEmail': ssl_email,
            'AdminContact': contact_dict.get('admin_contact'),
            'TechnicalContact': contact_dict.get('technical_contact'),
            'BillingContact': contact_dict.get('billing_contact'),
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
            'IPAddresses': ip_addresses,
            'IPCountryCode': ip_country_code,
            'MailServers': mx_servers,
            'SPFRecord': spf_info,
            'NameServers': name_servers,
            'SSLCertificate': ssl_certificates,
            'RedirectsTo': redirects_to,
        }
    }

    domain_context = {
        'Name': domain,
        'DNS': [ip.get('address') for ip in ip_addresses],
        'CreationDate': create_date,
        'DomainStatus': domain_status,
        'ExpirationDate': expiration_date,
        'NameServers': [name_server.get('host', {}).get('value') for name_server in name_servers],
        'Registrant': {
            'Country': contact_dict.get('registrant_contact', {}).get('Country', {}).get('value'),
            'Email': [email.get('value') for email in contact_dict.get('registrant_contact', {}).get('Email', {})],
            'Name': contact_dict.get('registrant_contact', {}).get('Name', {}).get('value'),
            'Phone': contact_dict.get('registrant_contact', {}).get('Phone', {}).get('value')
        }
    }

    dbot_score = 0
    if create_date != '':
        domain_age = find_age(create_date)
        dbot_score = get_dbot_score(proximity_risk_score, domain_age, threat_profile_risk_score)
    dbot_context = {'Indicator': domain,
                    'Type': 'domain',
                    'Vendor': 'DomainTools Iris',
                    'Score': dbot_score}
    if dbot_score == 3:
        domain_context['Malicious'] = {
            'Vendor': 'DomainTools Iris',
            'Description': threat_profile_evidence if threat_profile_evidence is not None and len(
                threat_profile_evidence) else 'This domain has been profiled as a threat.'
        }
    outputs = {'domain': domain_context,
               'domaintools': domain_tools_context,
               'dbotscore': dbot_context}
    return outputs


def domain_profile(domain):
    """
    Profiles domain and gives back all relevant domain data
    Args:
        domain (str): Domain name to profile

    Returns: All data relevant for Demisto command.

    """
    response = http_request('GET', '/v1/iris-investigate/', {'domain': domain})
    return response


def domain_analytics(domain):
    """
    Analytics profile of a domain.
    Args:
        domain (str): Domain name to get analytics for

    Returns: All data relevant for Demisto command.

    """
    response = http_request('GET', '/v1/iris-investigate/', {'domain': domain})
    return response


def threat_profile(domain):
    """
    Threat profiles a domain.
    Args:
        domain (str): Domain name to threat profile

    Returns: All data relevant for Demisto command.

    """
    response = http_request('GET', '/v1/iris-investigate/', {'domain': domain})
    return response


def domain_pivot(search_data):
    """
    Pivots on a domain given a search type and search value.
    Args:
        search_data: Search parameters for request

    Returns: All data relevant for Demisto command.

    """
    response = http_request('GET', '/v1/iris-investigate/', search_data)
    return response


''' COMMANDS '''


def domain_profile_command():
    """
    Command to do a total profile of a domain.
    """
    domain = demisto.args().get('domain')
    response = domain_profile(domain)
    human_readable = 'No results found.'
    outputs = {}  # type: Dict[Any, Any]

    if response.get('results_count'):
        domain_result = response.get('results')[0]
        context = create_domain_context_outputs(domain_result)
        outputs = {'Domain(val.Name && val.Name == obj.Name)': context.get('domain'),
                   'DomainTools.Domains(val.Name && val.Name == obj.Name)': context.get('domaintools'),
                   'DBotScore': context.get('dbotscore')}
        prune_context_data(outputs)
        domaintools_analytics_data = context.get('domaintools', {}).get('Analytics', {})
        domaintools_hosting_data = context.get('domaintools', {}).get('Hosting', {})
        domaintools_identity_data = context.get('domaintools', {}).get('Identity', {})
        domaintools_registration_data = context.get('domaintools', {}).get('Registration', {})

        human_readable_data = {
            'Name': domain,
            'Last Enriched': datetime.now().strftime('%Y-%m-%d'),
            'Overall Risk Score': domaintools_analytics_data.get('OverallRiskScore', ''),
            'Proximity Risk Score': domaintools_analytics_data.get('ProximityRiskScore', ''),
            'Threat Profile Risk Score': domaintools_analytics_data.get('ThreatProfileRiskScore', {}).get('RiskScore',
                                                                                                          ''),
            'Threat Profile Threats': domaintools_analytics_data.get('ThreatProfileRiskScore', {}).get('Threats', ''),
            'Threat Profile Evidence': domaintools_analytics_data.get('ThreatProfileRiskScore', {}).get('Evidence', ''),
            'Google Adsense Tracking Code': domaintools_analytics_data.get('GoogleAdsenseTrackingCode', ''),
            'Google Analytic Tracking Code': domaintools_analytics_data.get('GoogleAnalyticTrackingCode', ''),
            'Website Response Code': domaintools_analytics_data.get('WebsiteResponseCode', ''),
            'Alexa Rank': domaintools_analytics_data.get('AlexaRank', ''),
            'Tags': domaintools_analytics_data.get('Tags', ''),
            'Registrant Name': domaintools_identity_data.get('RegistrantName', ''),
            'Registrant Org': domaintools_identity_data.get('RegistrantOrg', ''),
            'Registrant Contact': domaintools_identity_data.get('RegistrantContact', ''),
            'SOA Email': domaintools_identity_data.get('SOAEmail', ''),
            'SSL Certificate Email': domaintools_identity_data.get('SSLCertificateEmail', ''),
            'Admin Contact': domaintools_identity_data.get('AdminContact', ''),
            'Technical Contact': domaintools_identity_data.get('TechnicalContact', ''),
            'Billing Contact': domaintools_identity_data.get('BillingContact', ''),
            'Email Domains': domaintools_identity_data.get('EmailDomains', ''),
            'Additional Whois Emails': domaintools_identity_data.get('AdditionalWhoisEmails', ''),
            'Domain Registrant': domaintools_registration_data.get('DomainRegistrant', ''),
            'Registrar Status': domaintools_registration_data.get('RegistrarStatus', ''),
            'Domain Status': domaintools_registration_data.get('DomainStatus', ''),
            'Create Date': domaintools_registration_data.get('CreateDate', ''),
            'Expiration Date': domaintools_registration_data.get('ExpirationDate', ''),
            'IP Addresses': domaintools_hosting_data.get('IPAddresses', ''),
            'IP Country Code': domaintools_hosting_data.get('IPCountryCode', ''),
            'Mail Servers': domaintools_hosting_data.get('MailServers', ''),
            'SPF Record': domaintools_hosting_data.get('SPFRecord', ''),
            'Name Servers': domaintools_hosting_data.get('NameServers', ''),
            'SSL Certificate': domaintools_hosting_data.get('SSLCertificate', ''),
            'Redirects To': domaintools_hosting_data.get('RedirectsTo', '')
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
        demisto_title = 'DomainTools Domain Profile for {}.'.format(domain)
        iris_title = 'Investigate [{0}](https://research.domaintools.com/iris/search/?q={0}) in Iris.'.format(domain)
        human_readable = tableToMarkdown('{} {}'.format(demisto_title, iris_title),
                                         human_readable_data,
                                         headers=headers)
    return_outputs(human_readable, outputs, response)


def domain_analytics_command():
    """
    Command to do a analytics profile of a domain.
    """
    domain = demisto.args().get('domain')
    response = domain_analytics(domain)
    human_readable = 'No results found.'
    outputs = {}  # type: Dict[Any, Any]

    if response.get('results_count'):
        domain_result = response.get('results')[0]
        context = create_domain_context_outputs(domain_result)
        outputs = {'Domain(val.Name && val.Name == obj.Name)': context.get('domain'),
                   'DomainTools.Domains(val.Name && val.Name == obj.Name)': context.get('domaintools'),
                   'DBotScore': context.get('dbotscore')}
        prune_context_data(outputs)
        domaintools_analytics_data = context.get('domaintools', {}).get('Analytics', {})
        domain_age = 0
        create_date = context.get('domaintools').get('Registration').get('CreateDate', '')
        if create_date != '':
            domain_age = find_age(create_date)
        human_readable_data = {
            'Overall Risk Score': domaintools_analytics_data.get('OverallRiskScore', ''),
            'Proximity Risk Score': domaintools_analytics_data.get('ProximityRiskScore', ''),
            'Threat Profile Risk Score': domaintools_analytics_data.get('ThreatProfileRiskScore', {}).get('RiskScore',
                                                                                                          ''),
            'Domain Age (in days)': domain_age,
            'Website Response': domaintools_analytics_data.get('WebsiteResponseCode', ''),
            'Google Adsense': domaintools_analytics_data.get('GoogleAdsenseTrackingCode', ''),
            'Google Analytics': domaintools_analytics_data.get('GoogleAnalyticsTrackingCode', ''),
            'Alexa Rank': domaintools_analytics_data.get('AlexaRank', ''),
            'Tags': domaintools_analytics_data.get('Tags', ''),
        }

        headers = ['Overall Risk Score',
                   'Proximity Risk Score',
                   'Domain Age (in days)',
                   'Website Response',
                   'Google Adsense',
                   'Google Analytics',
                   'Alexa Rank',
                   'Tags']
        demisto_title = 'DomainTools Domain Analytics for {}.'.format(domain)
        iris_title = 'Investigate [{0}](https://research.domaintools.com/iris/search/?q={0}) in Iris.'.format(domain)
        human_readable = tableToMarkdown('{} {}'.format(demisto_title, iris_title),
                                         human_readable_data,
                                         headers=headers)
    return_outputs(human_readable, outputs, response)


def threat_profile_command():
    """
    Command to do a threat profile of a domain.
    """
    domain = demisto.args().get('domain')
    response = threat_profile(domain)
    human_readable = 'No results found.'
    outputs = {}  # type: Dict[Any, Any]

    if response.get('results_count'):
        domain_result = response.get('results')[0]
        context = create_domain_context_outputs(domain_result)
        outputs = {'Domain(val.Name && val.Name == obj.Name)': context.get('domain'),
                   'DomainTools.Domains(val.Name && val.Name == obj.Name)': context.get('domaintools'),
                   'DBotScore': context.get('dbotscore')}
        prune_context_data(outputs)
        proximity_risk_score = 0
        threat_profile_risk_score = 0
        threat_profile_malware_risk_score = 0
        threat_profile_phishing_risk_score = 0
        threat_profile_spam_risk_score = 0
        threat_profile_threats = ''
        threat_profile_evidence = ''

        overall_risk_score = domain_result.get('domain_risk', {}).get('risk_score', 0)
        risk_components = domain_result.get('domain_risk', {}).get('components', {})
        if risk_components:
            proximity_data = get_threat_component(risk_components, 'proximity')
            blacklist_data = get_threat_component(risk_components, 'blacklist')
            if proximity_data:
                proximity_risk_score = proximity_data.get('risk_score', 0)
            elif blacklist_data:
                proximity_risk_score = blacklist_data.get('risk_score', 0)
            threat_profile_data = get_threat_component(risk_components, 'threat_profile')
            if threat_profile_data:
                threat_profile_risk_score = threat_profile_data.get('risk_score', 0)
                threat_profile_threats = ', '.join(threat_profile_data.get('threats', []))
                threat_profile_evidence = ', '.join(threat_profile_data.get('evidence', []))
            threat_profile_malware_data = get_threat_component(risk_components, 'threat_profile_malware')
            if threat_profile_malware_data:
                threat_profile_malware_risk_score = threat_profile_malware_data.get('risk_score', 0)
            threat_profile_phshing_data = get_threat_component(risk_components, 'threat_profile_phishing')
            if threat_profile_phshing_data:
                threat_profile_phishing_risk_score = threat_profile_phshing_data.get('risk_score', 0)
            threat_profile_spam_data = get_threat_component(risk_components, 'threat_profile_spam')
            if threat_profile_spam_data:
                threat_profile_spam_risk_score = threat_profile_spam_data.get('risk_score', 0)

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
                   'Threat Profile Risk Score',
                   'Threat Profile Threats',
                   'Threat Profile Evidence',
                   'Threat Profile Malware Risk Score',
                   'Threat Profile Phishing Risk Score',
                   'Threat Profile Spam Risk Score']
        demisto_title = 'DomainTools Threat Profile for {}.'.format(domain)
        iris_title = 'Investigate [{0}](https://research.domaintools.com/iris/search/?q={0}) in Iris.'.format(domain)
        human_readable = tableToMarkdown('{} {}'.format(demisto_title, iris_title),
                                         human_readable_data,
                                         headers=headers)
    return_outputs(human_readable, outputs, response)


def domain_pivot_command():
    """
    Command to do a domain pivot lookup.
    """
    search_data = {}  # type: Dict[Any, Any]
    search_type = ''
    search_value = ''
    if demisto.args().get('ip'):
        search_data = {'ip': demisto.args().get('ip')}
        search_type, search_value = 'IP', demisto.args().get('ip')
    elif demisto.args().get('email'):
        search_data = {'email': demisto.args().get('email')}
        search_type, search_value = 'E-Mail', demisto.args().get('email')
    elif demisto.args().get('nameserver_ip'):
        search_data = {'nameserver_ip': demisto.args().get('nameserver_ip')}
        search_type, search_value = 'Name Server IP', demisto.args().get('nameserver_ip')
    elif demisto.args().get('ssl_hash'):
        search_data = {'ssl_hash': demisto.args().get('ssl_hash')}
        search_type, search_value = 'SSL Hash', demisto.args().get('ssl_hash')
    elif demisto.args().get('nameserver_host'):
        search_data = {'nameserver_host': demisto.args().get('nameserver_host')}
        search_type, search_value = 'Name Server Host', demisto.args().get('nameserver_host')
    elif demisto.args().get('mailserver_host'):
        search_data = {'mailserver_host': demisto.args().get('mailserver_host')}
        search_type, search_value = 'Mail Server Host', demisto.args().get('mailserver_host')

    response = domain_pivot(search_data)
    human_readable_data = []
    domain_context_list = []
    human_readable = 'No results found.'
    outputs = {}  # type: Dict[Any, Any]

    if response.get('results_count'):
        for domain_result in response.get('results'):
            human_readable_data.append(domain_result.get('domain'))
            domain_context = create_domain_context_outputs(domain_result)
            domain_context_list.append(domain_context.get('domaintools'))
        outputs = {'DomainTools.PivotedDomains(val.Name == obj.Name)': domain_context_list}
        prune_context_data(outputs)
        headers = ['Domains']
        human_readable = tableToMarkdown('Domains for {}: {}.'.format(search_type, search_value),
                                         human_readable_data,
                                         headers=headers)

    return_outputs(human_readable, outputs, response)


def test_module():
    """
    Tests the API key for a user.
    """
    try:
        http_request('GET', '/v1/iris-investigate/', {'domain': 'demisto.com'})
        demisto.results('ok')
    except Exception:
        raise


def main():
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


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
