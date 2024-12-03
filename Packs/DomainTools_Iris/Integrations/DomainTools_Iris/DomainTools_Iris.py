import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import urllib3
import statistics
from datetime import datetime
from typing import Any
from domaintools import API
from domaintools import utils
import urllib.parse
import copy

# disable insecure warnings
urllib3.disable_warnings()

''' GLOBALS '''
USERNAME = demisto.params().get('credentials', {}).get('identifier') or demisto.params().get('username')
API_KEY = demisto.params().get('credentials', {}).get('password') or demisto.params().get('apikey')
RISK_THRESHOLD = arg_to_number(demisto.params().get('risk_threshold')) or 70
YOUNG_DOMAIN_TIMEFRAME = arg_to_number(demisto.params().get('young_domain_timeframe')) or 7
VERIFY_CERT = not demisto.params().get('insecure', False)
PROXIES = handle_proxy()
GUIDED_PIVOT_THRESHOLD = arg_to_number(demisto.params().get('pivot_threshold')) or 500
IRIS_LINK = 'https://iris.domaintools.com/investigate/search/'

DOMAINTOOLS_MONITOR_DOMAINS_INCIDENT_NAME_BY_IRIS_SEARCH_HASH = "DomainTools Iris Monitor Domain Search Hash"
DOMAINTOOLS_MONITOR_DOMAINS_INCIDENT_NAME_BY_IRIS_TAGS = "DomainTools Iris Monitor Domain Tags"

INCIDENT_TYPES = {
    DOMAINTOOLS_MONITOR_DOMAINS_INCIDENT_NAME_BY_IRIS_SEARCH_HASH: "DomainTools Iris Monitor Domains - Iris Search Hash",
    DOMAINTOOLS_MONITOR_DOMAINS_INCIDENT_NAME_BY_IRIS_TAGS: "DomainTools Iris Monitor Domains - Iris Tags",
}

DOMAINTOOLS_IRIS_INDICATOR_TYPE = "DomainTools Iris"
MONITOR_DOMAIN_IRIS_SEARCH_HASH_TIMESTAMP = "monitor_domain_iris_search_hash_last_run"
MONITOR_DOMAIN_IRIS_TAG_TIMESTAMP = "monitor_domain_iris_tags_last_run"
BATCH_SIZE = 200

PROFILE_HEADERS = [
    'Name',
    'Last Enriched',
    'Overall Risk Score',
    'Proximity Risk Score',
    'Threat Profile Risk Score',
    'Threat Profile Threats',
    'Threat Profile Evidence',
    'Website Response Code',
    'Tags',
    'Registrant Name',
    'Registrant Org',
    'Registrant Contact',
    'Registrar',
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
    'Redirect Domain',
    'Google Adsense Tracking Code',
    'Google Analytic Tracking Code',
    'Website Title',
    'First Seen',
    'Server Type',
    'Popularity'
]

''' HELPER FUNCTIONS '''


def http_request(method, params=None):
    """
    HTTP request helper function
    Args:
        method: HTTP Method
        path: part of the url
        other_params: Anything else that needs to be in the request

    Returns: request result

    """
    proxy_url = PROXIES.get('https') if PROXIES.get('https') != '' else PROXIES.get('http')
    if not (USERNAME and API_KEY):
        raise DemistoException("The 'API Username' and 'API Key' parameters are required.")
    api = API(
        USERNAME,
        API_KEY,
        app_partner='cortex_xsoar',
        app_name='iris-plugin',
        app_version='2.0',
        proxy_url=proxy_url,
        verify_ssl=VERIFY_CERT,
        always_sign_api_key=True
    )

    try:
        if method == 'iris-investigate':
            response = api.iris_investigate(params.get('domains')).response()
        elif method == 'iris-enrich':
            response = api.iris_enrich(params.get('domains')).response()
        elif method == 'whois-history':
            response = api.whois_history(params.get('domain'), **params).response()
        elif method == 'hosting-history':
            response = api.hosting_history(params.get('domain')).response()
        elif method == 'reverse-whois':
            response = api.reverse_whois(**params).response()
        elif method == 'parsed-whois':
            response = api.parsed_whois(params.get('domain')).response()
        else:
            response = api.iris_investigate(**params).response()
    except Exception as e:
        demisto.error(str(e))
        raise

    return response


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


def prune_context_data(data_obj):
    """
    Does a deep dive through a data object to prune any null or empty items. Checks for empty lists, dicts, and strs.
    Args:
        data_obj: Either a list or dict that needs to be pruned
    """
    items_to_prune = []
    if isinstance(data_obj, dict) and len(data_obj):
        for k, v in data_obj.items():
            if isinstance(data_obj[k], dict | list):
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


def format_contact_grid(title, contact_dict):
    name = contact_dict.get('Name', {}).get('value')
    org = contact_dict.get('Org', {}).get('value')
    email = ','.join([email['value'] for email in contact_dict.get('Email', []) if 'value' in email])
    phone = contact_dict.get('Phone', {}).get('value')
    fax = contact_dict.get('Fax', {}).get('value')
    address = f"Street: {contact_dict.get('Street', {}).get('value')}, " \
              f"City: {contact_dict.get('City', {}).get('value')}, " \
              f"State: {contact_dict.get('State', {}).get('value')}, " \
              f"Postal: {contact_dict.get('Postal', {}).get('value')}, Country: {contact_dict.get('Country', {}).get('value')}"

    formatted_contact = [
        {'key': f'{title} Name', 'value': name} if name else None,
        {'key': f'{title} Organization', 'value': org} if org else None,
        {'key': f'{title} Email', 'value': email} if email else None,
        {'key': f'{title} Phone', 'value': phone} if phone else None,
        {'key': f'{title} Fax', 'value': fax} if fax else None,
        {'key': f'{title} Address', 'value': address},
    ]

    return [item for item in formatted_contact if item]


def format_dns_grid(type, dns_dict):
    return [{
        "type": type,
        "ip": ','.join([ip['value'] for ip in item.get('ip', []) if ip.get('value')]),
        "host": item.get('host', {}).get('value')
    } for item in dns_dict]


def format_risk_grid(domain_risk):
    result = [Common.ThreatTypes(threat_category='risk_score', threat_category_confidence=domain_risk.get('risk_score'))]

    for component in domain_risk.get('components', []):
        result.append(
            Common.ThreatTypes(threat_category=component.get('name'),
                               threat_category_confidence=component.get('risk_score'))
        )

    return result


def format_tags(tags):
    return ' '.join([tag['label'] for tag in tags])


def convert_and_format_date(
    string_date: str, string_date_format: str = "%Y-%m-%dT%H:%M:%SZ", new_format: str = "%Y-%m-%d"
) -> str:
    """Converts a date string to a datetime object then returns a string formatted date

    Args:
        string_date (str): The string date to be converted.
        string_date_format (str, optional): Defaults to "%Y-%m-%dT%H:%M:%SZ".
        new_format (str, optional): The desired return string format. Defaults to "%Y-%m-%d".

    Returns:
        str: The formatted string date
    """
    return datetime.strptime(string_date, string_date_format).strftime(new_format)


def create_results(domain_result):
    """
    Creates all the context data necessary given a domain result
    Args:
        domain_result: DomainTools domain data

    Returns: dict {
        domain: <Common.Domain> - Domain indicator object with Iris results that map to Domain context
        domaintools: <dict> - DomainTools context with all Iris results
    }

    """
    domain = f"{domain_result.get('domain')}"
    ip_addresses = domain_result.get('ip')
    create_date = domain_result.get('create_date', {}).get('value')
    expiration_date = domain_result.get('expiration_date', {}).get('value')
    name_servers = domain_result.get('name_server')
    domain_status = domain_result.get('active')

    domain_risk_score_details = get_domain_risk_score_details(domain_result.get("domain_risk") or {})

    website_response = domain_result.get('website_response')
    google_adsense = domain_result.get('adsense')
    google_analytics = domain_result.get('google_analytics')
    ga4 = domain_result.get('ga4')
    gtm_codes = domain_result.get('gtm_codes')
    fb_codes = domain_result.get('fb_codes')
    hotjar_codes = domain_result.get('hotjar_codes')
    baidu_codes = domain_result.get('baidu_codes')
    yandex_codes = domain_result.get('yandex_codes')
    matomo_codes = domain_result.get('matomo_codes')
    statcounter_project_codes = domain_result.get('statcounter_project_codes')
    statcounter_security_codes = domain_result.get('statcounter_security_codes')
    popularity_rank = domain_result.get('popularity_rank')
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
            'Street': contact_data.get('street'),
            'City': contact_data.get('city'),
            'State': contact_data.get('state'),
            'Postal': contact_data.get('postal'),
            'Org': contact_data.get('org')
        }
    soa_email = list(domain_result.get('soa_email'))
    ssl_email = list(domain_result.get('ssl_email'))
    email_domains = [email_domain.get('value') for email_domain in domain_result.get('email_domain')]
    additional_whois_emails = domain_result.get('additional_whois_email')
    domain_registrar = domain_result.get('registrar')
    registrar_status = domain_result.get('registrar_status')
    ip_country_code = ip_addresses[0].get('country_code', {}).get('value') if len(ip_addresses) else ""
    mx_servers = domain_result.get('mx')
    spf_info = domain_result.get('spf_info')
    ssl_certificates = domain_result.get('ssl_info')
    redirects_to = domain_result.get('redirect')
    redirect_domain = domain_result.get('redirect_domain')
    website_title = domain_result.get('website_title', {}).get('value') if domain_result.get('website_title') else ""
    server_type = domain_result.get('server_type', {}).get('value') if domain_result.get('server_type') else ""
    first_seen = domain_result.get('first_seen', {}).get('value') if domain_result.get('first_seen') else ""

    domain_tools_context = {
        'Name': domain,
        'LastEnriched': datetime.now().strftime('%Y-%m-%d'),
        'Analytics': {
            'OverallRiskScore': domain_risk_score_details["overall_risk_score"],
            'ProximityRiskScore': domain_risk_score_details["proximity_risk_score"],
            'MalwareRiskScore': domain_risk_score_details["threat_profile_malware_risk_score"],
            'PhishingRiskScore': domain_risk_score_details["threat_profile_phishing_risk_score"],
            'SpamRiskScore': domain_risk_score_details["threat_profile_spam_risk_score"],
            'ThreatProfileRiskScore': {'RiskScore': domain_risk_score_details["threat_profile_risk_score"],
                                       'Threats': domain_risk_score_details["threat_profile_threats"],
                                       'Evidence': domain_risk_score_details["threat_profile_evidence"]},
            'WebsiteResponseCode': website_response,
            'GoogleAdsenseTrackingCode': google_adsense,
            'GoogleAnalyticTrackingCode': google_analytics,
            'GA4TrackingCode': ga4,
            'GTMTrackingCode': gtm_codes,
            'FBTrackingCode': fb_codes,
            'HotJarTrackingCode': hotjar_codes,
            'BaiduTrackingCode': baidu_codes,
            'YandexTrackingCode': yandex_codes,
            'MatomoTrackingCode': matomo_codes,
            'StatcounterProjectTrackingCode': statcounter_project_codes,
            'StatcounterSecurityTrackingCode': statcounter_security_codes,
            'Tags': tags
        },
        'Identity': {
            'RegistrantName': registrant_name,
            'RegistrantOrg': registrant_org,
            'RegistrantContact': contact_dict.get('registrant_contact'),
            'Registrar': domain_registrar,
            'SOAEmail': soa_email,
            'SSLCertificateEmail': ssl_email,
            'AdminContact': contact_dict.get('admin_contact'),
            'TechnicalContact': contact_dict.get('technical_contact'),
            'BillingContact': contact_dict.get('billing_contact'),
            'EmailDomains': email_domains,
            'AdditionalWhoisEmails': additional_whois_emails
        },
        'Registration': {
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
            'RedirectDomain': redirect_domain
        },
        'WebsiteTitle': website_title,
        'FirstSeen': first_seen,
        'ServerType': server_type,
    }

    dns = [{"type": 'DNS', "ip": ip.get('address', {}).get('value')} for ip in ip_addresses] + \
        format_dns_grid('MX', mx_servers) + format_dns_grid('NS', name_servers)
    registrar = domain_result.get('registrar')
    registrant_country = domain_result.get('registrant_contact', {}).get('country', {}).get('value')
    admin_name = domain_result.get('admin_contact', {}).get('name', {}).get('value')
    admin_email = list(domain_result.get('admin_contact', {}).get('email', []))
    admin_phone = domain_result.get('admin_contact', {}).get('phone', {}).get('value')
    admin_country = domain_result.get('admin_contact', {}).get('country', {}).get('value')
    threat_types = format_risk_grid(domain_result.get('domain_risk', {}))
    tech_name = domain_result.get('technical_contact', {}).get('name', {}).get('value')
    tech_email = list(domain_result.get('technical_contact', {}).get('email', []))
    tech_org = domain_result.get('technical_contact', {}).get('org', {}).get('value')
    tech_country = domain_result.get('technical_contact', {}).get('country', {}).get('value')
    rank = [Common.Rank(source="DomainTools Popularity Rank", rank=popularity_rank if popularity_rank else 'None')]

    dbot_score_value = 0
    if first_seen:
        first_seen = convert_and_format_date(first_seen)
        domain_age = utils.get_domain_age(first_seen)
        dbot_score_value = get_dbot_score(
            domain_risk_score_details.get("proximity_risk_score") or 0,
            domain_age,
            domain_risk_score_details.get("threat_profile_risk_score") or 0
        )

    malicious_description = None
    if dbot_score_value == 3:
        threat_profile_evidence = domain_risk_score_details["threat_profile_evidence"]
        malicious_description = threat_profile_evidence if threat_profile_evidence is not None and len(
            threat_profile_evidence) else 'This domain has been profiled as a threat.'

    dbot_score = Common.DBotScore(
        indicator=domain,
        indicator_type=DBotScoreType.DOMAIN,
        integration_name='DomainTools Iris',
        score=dbot_score_value,
        reliability=demisto.params().get('integrationReliability'),
        malicious_description=malicious_description
    )

    domain_indicator = Common.Domain(domain, dbot_score=dbot_score, dns=dns,
                                     organization=registrant_org, creation_date=create_date,
                                     expiration_date=expiration_date,
                                     domain_status=domain_status,
                                     registrar_name=registrar,
                                     registrant_name=registrant_name,
                                     registrant_country=registrant_country,
                                     admin_name=admin_name, admin_email=admin_email, admin_phone=admin_phone,
                                     admin_country=admin_country, tags=tags,
                                     threat_types=threat_types,
                                     tech_country=tech_country, tech_name=tech_name, tech_email=tech_email,
                                     tech_organization=tech_org,
                                     rank=rank)

    outputs = {'domain': domain_indicator, 'domaintools': domain_tools_context}
    return outputs


def domain_investigate(domain):
    """
    Profiles domain and gives back all relevant domain data
    Args:
        domain (str): Domain name to profile

    Returns: All data relevant for Demisto command.

    """
    return http_request('iris-investigate', {'domains': domain})


def domain_enrich(domain):
    """
    Profiles domain and gives back all relevant domain data
    Args:
        domain (str): Domain name to profile

    Returns: All data relevant for Demisto command.

    """
    return http_request('iris-enrich', {'domains': domain})


def domain_pivot(search_params):
    """
    Analytics profile of a domain.
    Args:
        domain (str): Domain name to get analytics for

    Returns: All data relevant for Demisto command.

    """
    return http_request('iris-pivot', search_params)


def whois_history(**kwargs):
    return http_request('whois-history', kwargs)


def hosting_history(domain):
    return http_request('hosting-history', {'domain': domain})


def reverse_whois(**kwargs):
    return http_request('reverse-whois', kwargs)


def parsed_whois(domain):
    return http_request('parsed-whois', {'domain': domain})


def add_key_to_json(cur, to_add):
    if not cur:
        return to_add
    if not isinstance(cur, list):
        return [cur, to_add]
    cur.append(to_add)
    return cur


def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def format_enrich_output(result):
    domain = result.get('domain')
    indicators = create_results(result)

    domaintools_analytics_data = indicators.get('domaintools', {}).get('Analytics', {})
    domaintools_hosting_data = indicators.get('domaintools', {}).get('Hosting', {})
    domaintools_identity_data = indicators.get('domaintools', {}).get('Identity', {})
    domaintools_registration_data = indicators.get('domaintools', {}).get('Registration', {})

    human_readable_data = {
        'Name': f"{domain}",
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
        'Tags': domaintools_analytics_data.get('Tags', ''),
        'Registrant Name': domaintools_identity_data.get('RegistrantName', ''),
        'Registrant Org': domaintools_identity_data.get('RegistrantOrg', ''),
        'Registrant Contact': domaintools_identity_data.get('RegistrantContact', ''),
        'Registrar': domaintools_identity_data.get('Registrar', ''),
        'SOA Email': domaintools_identity_data.get('SOAEmail', ''),
        'SSL Certificate Email': domaintools_identity_data.get('SSLCertificateEmail', ''),
        'Admin Contact': domaintools_identity_data.get('AdminContact', ''),
        'Technical Contact': domaintools_identity_data.get('TechnicalContact', ''),
        'Billing Contact': domaintools_identity_data.get('BillingContact', ''),
        'Email Domains': domaintools_identity_data.get('EmailDomains', ''),
        'Additional Whois Emails': domaintools_identity_data.get('AdditionalWhoisEmails', ''),
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
        'Redirects To': domaintools_hosting_data.get('RedirectsTo', ''),
        'Redirect Domain': domaintools_hosting_data.get('RedirectDomain', ''),
        'Website Title': indicators.get('domaintools', {}).get('WebsiteTitle'),
        'First Seen': indicators.get('domaintools', {}).get('FirstSeen'),
        'Server Type': indicators.get('domaintools', {}).get('ServerType'),
        'Popularity': indicators.get('domain', {}).rank,
    }

    demisto_title = f'DomainTools Iris Enrich for {domain}.'
    iris_title = 'Investigate [{0}](https://research.domaintools.com/iris/search/?q={0}) in Iris.'.format(domain)
    human_readable = tableToMarkdown(
        f'{demisto_title} {iris_title}', human_readable_data, headers=PROFILE_HEADERS
    )

    return (human_readable, indicators)


def format_ips(ips):
    for ip in ips:
        address = ip['address']
        address['count'] = format_guided_pivot_link("ip.ip", address)

        asns = ip.get('asn', [])
        for asn in asns:
            asn['count'] = format_guided_pivot_link("ip.asn", asn)

        country_code = ip['country_code']
        country_code['count'] = format_guided_pivot_link("ip.cc", country_code)

        isp = ip['isp']
        isp['count'] = format_guided_pivot_link("ip.isp", isp)

    return ips


def format_nameserver(nameservers):
    for ns in nameservers:
        host = ns['host']
        host['count'] = format_guided_pivot_link("ns.ns", host)

        ips = ns['ip']
        for ip in ips:
            ip['count'] = format_guided_pivot_link("ns.nip", ip)

        domain = ns['domain']
        domain['count'] = format_guided_pivot_link("ns.nsd", domain)

    return nameservers


def format_mailserver(mailservers):
    for mx in mailservers:
        host = mx['host']
        host['count'] = format_guided_pivot_link("mx.mx", host)

        ips = mx['ip']
        for ip in ips:
            ip['count'] = format_guided_pivot_link("mx.mip", ip)

        domain = mx['domain']
        domain['count'] = format_guided_pivot_link("mx.mxd", domain)

    return mailservers


def format_ssl_info(certs):
    for cert in certs:
        alt_names = cert['alt_names']
        for an in alt_names:
            an['count'] = format_guided_pivot_link("ssl.alt_names", an)

        ssl_hash = cert['hash']
        ssl_hash['count'] = format_guided_pivot_link("ssl.sh", ssl_hash)

        subject = cert['subject']
        subject['count'] = format_guided_pivot_link("ssl.s", subject)

        org = cert['organization']
        org['count'] = format_guided_pivot_link("ssl.so", org)

        cn = cert['common_name']
        cn['count'] = format_guided_pivot_link("ssl.common_name", cn)

        icn = cert['issuer_common_name']
        icn['count'] = format_guided_pivot_link("ssl.issuer_common_name", icn)

        na = cert['not_after']
        na['count'] = format_guided_pivot_link("ssl.not_after", na)

        nb = cert['not_before']
        nb['count'] = format_guided_pivot_link("ssl.not_before", nb)

        duration = cert['duration']
        duration['count'] = format_guided_pivot_link("ssl.duration", duration)

    return certs


def format_contact(contact, domain, email_type):
    country = contact['country']
    country['count'] = format_guided_pivot_link('cons.cc', country)
    name = contact['name']
    name['count'] = format_guided_pivot_link('cons.nm', name)
    phone = contact['phone']
    phone['count'] = format_guided_pivot_link('cons.ph', phone)
    street = contact['street']
    street['count'] = format_guided_pivot_link('cons.str', street)

    org = contact['org']
    org['count'] = format_guided_pivot_link(None, org, domain)
    city = contact['city']
    city['count'] = format_guided_pivot_link(None, city, domain)
    state = contact['state']
    state['count'] = format_guided_pivot_link(None, state, domain)
    postal = contact['postal']
    postal['count'] = format_guided_pivot_link(None, postal, domain)
    fax = contact['fax']
    fax['count'] = format_guided_pivot_link(None, fax, domain)

    emails = contact['email']
    for email in emails:
        email['count'] = format_guided_pivot_link(email_type, email)

    return contact


def format_single_value(link_type, value, domain=None):
    if isinstance(value, str):
        return value

    value['count'] = format_guided_pivot_link(link_type, value, domain)

    return json.dumps(value, ensure_ascii=False)


def format_list_value(link_type, list, domain=None):
    for item in list:
        item['count'] = format_guided_pivot_link(link_type, item, domain)

    return list


def format_guided_pivot_link(link_type, item, domain=None):
    query = item.get('value', '')
    count = item.get('count', 0)

    if domain:
        link_type = 'domain'
        query = domain

    if 1 < int(count) < GUIDED_PIVOT_THRESHOLD:
        return f'[{count}]({IRIS_LINK}?q={link_type}:"{urllib.parse.quote(str(query), safe="")}")'

    return count


def format_investigate_output(result):
    domain = result.get('domain')
    result_copy = copy.deepcopy(result)
    indicators = create_results(result_copy)

    domaintools_analytics_data = indicators.get('domaintools', {}).get('Analytics', {})
    domaintools_hosting_data = indicators.get('domaintools', {}).get('Hosting', {})
    domaintools_registration_data = indicators.get('domaintools', {}).get('Registration', {})

    human_readable_data = {
        'Name': f"[{domain}](https://domaintools.com)",
        'Last Enriched': datetime.now().strftime('%Y-%m-%d'),
        'Overall Risk Score': domaintools_analytics_data.get('OverallRiskScore', ''),
        'Proximity Risk Score': domaintools_analytics_data.get('ProximityRiskScore', ''),
        'Threat Profile Risk Score': domaintools_analytics_data.get('ThreatProfileRiskScore', {}).get('RiskScore',
                                                                                                      ''),
        'Threat Profile Threats': domaintools_analytics_data.get('ThreatProfileRiskScore', {}).get('Threats', ''),
        'Threat Profile Evidence': domaintools_analytics_data.get('ThreatProfileRiskScore', {}).get('Evidence', ''),
        'Google Adsense Tracking Code': format_single_value('ad', result.get('adsense', {})),
        'Google Analytic Tracking Code': format_single_value('ga', result.get('google_analytics', {})),
        'Website Response Code': domaintools_analytics_data.get('WebsiteResponseCode', ''),
        'Tags': domaintools_analytics_data.get('Tags', 'not here'),
        'Registrant Name': format_single_value('r_n', result.get('registrant_name', {})),
        'Registrant Org': format_single_value('r_o', result.get('registrant_org', {})),
        'Registrant Contact': format_contact(result.get('registrant_contact', {}), domain, 'empr'),
        'Registrar': format_single_value('reg', result.get('registrar', {})),
        'SOA Email': format_list_value('ema', result.get('soa_email', [])),
        'SSL Certificate Email': format_list_value('ssl.em', result.get('ssl_email', [])),
        'Admin Contact': format_contact(result.get('admin_contact', {}), domain, 'empa'),
        'Technical Contact': format_contact(result.get('technical_contact', {}), domain, 'empt'),
        'Billing Contact': format_contact(result.get('billing_contact', {}), domain, 'empb'),
        'Email Domains': format_list_value('emd', result.get('email_domain', [])),
        'Additional Whois Emails': format_list_value('em', result.get('additional_whois_email', [])),
        'Registrar Status': domaintools_registration_data.get('RegistrarStatus', ''),
        'Domain Status': domaintools_registration_data.get('DomainStatus', ''),
        'Create Date': format_single_value('cre', result.get('create_date', {})),
        'Expiration Date': format_single_value('exp', result.get('expiration_date', {})),
        'IP Addresses': format_ips(result.get('ip', {})),
        'IP Country Code': domaintools_hosting_data.get('IPCountryCode', ''),
        'Mail Servers': format_mailserver(result.get('mx', {})),
        'SPF Record': format_single_value(None, result.get('spf_info', {}), domain),
        'Name Servers': format_nameserver(result.get('name_server', {})),
        'SSL Certificate': format_ssl_info(result.get('ssl_info', {})),
        'Redirects To': format_single_value(None, result.get('redirect', {}), domain),
        'Redirect Domain': format_single_value('rdd', result.get('redirect_domain', {})),
        'Website Title': format_single_value(None, result.get('website_title', {}), domain),
        'First Seen': format_single_value(None, result.get('first_seen', {}), domain),
        'Server Type': format_single_value('server_type', result.get('server_type', {})),
        'Popularity': result.get('popularity_rank'),
    }

    demisto_title = f'DomainTools Iris Investigate for {domain}.'
    iris_title = f'Investigate [{domain}](https://research.domaintools.com/iris/search/?q={domain}) in Iris.'
    human_readable = tableToMarkdown(
        f'{demisto_title} {iris_title}', human_readable_data, headers=PROFILE_HEADERS
    )

    return (human_readable, indicators)


def get_domain_risk_score_details(domain_risk: dict[str, Any]) -> dict[str, Any]:
    """Get the domain risk score details on a given domain risk

    Args:
        domain_risk (dict[str, Any]): The domain risk attribute of a domain

    Returns:
        dict[str, Any]: The detailed risk scores.
    """
    risk_scores = {
        "overall_risk_score": 0,
        "proximity_risk_score": "",
        "threat_profile_risk_score": "",
        "threat_profile_malware_risk_score": "",
        "threat_profile_phishing_risk_score": "",
        "threat_profile_spam_risk_score": "",
        "threat_profile_threats": "",
        "threat_profile_evidence": ""
    }

    risk_scores["overall_risk_score"] = domain_risk.get("risk_score")
    risk_components = domain_risk.get("components") or []
    if risk_components:
        proximity_data = utils.get_threat_component(risk_components, 'proximity')
        blacklist_data = utils.get_threat_component(risk_components, 'blacklist')
        if proximity_data:
            risk_scores["proximity_risk_score"] = proximity_data.get('risk_score') or ""
        elif blacklist_data:
            risk_scores["proximity_risk_score"] = blacklist_data.get('risk_score') or ""

        threat_profile_data = utils.get_threat_component(risk_components, 'threat_profile')
        if threat_profile_data:
            risk_scores["threat_profile_risk_score"] = threat_profile_data.get('risk_score') or ""
            risk_scores["threat_profile_threats"] = ', '.join(threat_profile_data.get('threats', []))
            risk_scores["threat_profile_evidence"] = ', '.join(threat_profile_data.get('evidence', []))
        threat_profile_malware_data = utils.get_threat_component(risk_components, 'threat_profile_malware')
        if threat_profile_malware_data:
            risk_scores["threat_profile_malware_risk_score"] = threat_profile_malware_data.get('risk_score') or ""
        threat_profile_phshing_data = utils.get_threat_component(risk_components, 'threat_profile_phishing')
        if threat_profile_phshing_data:
            risk_scores["threat_profile_phishing_risk_score"] = threat_profile_phshing_data.get('risk_score') or ""
        threat_profile_spam_data = utils.get_threat_component(risk_components, 'threat_profile_spam')
        if threat_profile_spam_data:
            risk_scores["threat_profile_spam_risk_score"] = threat_profile_spam_data.get('risk_score', 0)

    return risk_scores


def format_attribute(attribute: list[dict], key: str = '') -> str:
    """Format list of attribute to str

    Args:
        attribute (list[dict]): The attribute to format
        key (str): The key to lookup, supports nested dict (e.g "host.value")

    Returns:
        str: The string formatted attribute
    """
    formatted_str = []
    for attr in attribute:
        if isinstance(attr, dict):
            keys = key.split(".")
            value = attr[keys[0]][keys[1]] if len(keys) > 1 else attr[keys[0]]
            formatted_str.append(value)
        else:  # for list only values
            formatted_str.append(attr)

    return ",".join(formatted_str) if formatted_str else ""


def create_indicator_from_dt_domain(domain: dict[str, Any], source: str) -> dict[str, Any]:
    """Create an Indicator object from the Domaintools Iris domain.

    Args:
        domain (dict[str, Any]): The domain to be created as indicator.
        source (str): The domain source.

    Returns:
        dict[str, Any]: The DomainTools Iris Indicator Attributes
    """
    ip_addresses = domain.get("ip") or []
    ip_country_code = ip_addresses[0].get('country_code', {}).get('value') if len(ip_addresses) else ''
    domain_age = 0

    first_seen = domain.get('first_seen', {}).get('value') or ""
    if first_seen:
        domain_age = utils.get_domain_age(convert_and_format_date(first_seen))

    domain_risk_score_details = get_domain_risk_score_details(domain.get("domain_risk") or {})
    try:
        dbot_score = get_dbot_score(
            domain_risk_score_details["proximity_risk_score"],
            domain_age,
            domain_risk_score_details["threat_profile_risk_score"]
        )
    except Exception as e:
        demisto.info(f"Error finding reputation: {str(e)}")
        dbot_score = 1

    riskscore_component_mapping = {
        "proximity": domain_risk_score_details["proximity_risk_score"],
        "malware": domain_risk_score_details["threat_profile_malware_risk_score"],
        "phishing": domain_risk_score_details["threat_profile_phishing_risk_score"],
        "spam": domain_risk_score_details["threat_profile_spam_risk_score"],
        "evidence": domain_risk_score_details["threat_profile_evidence"]
    }

    raw_json_indicator = {
        "type": DOMAINTOOLS_IRIS_INDICATOR_TYPE,
        "value": domain.get("domain")
    }

    return {
        "type": raw_json_indicator["type"],
        "value": raw_json_indicator["value"],
        "occured": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "rawJSON": raw_json_indicator,
        "score": dbot_score,
        "fields": {
            "source": source,
            "sourcebrands": "DomainTools Iris",
            "domaintoolsirisdomainage": domain_age,
            "domainstatus": domain.get('active'),
            "firstseen": first_seen,
            "domaintoolsirisriskscore": domain.get("domain_risk", {}).get("risk_score"),
            "domaintoolsirisfirstseen": first_seen,
            "domaintoolsiristags": format_attribute(domain.get("tags", []), key="label"),
            "domaintoolsirisadditionalwhoisemails": format_attribute(domain.get("additional_whois_email", []), key="value"),
            "domaintoolsirisemaildomains": format_attribute(domain.get("email_domain", []), key="value"),
            "nameservers": format_attribute(domain.get("name_server", []), key="host.value"),
            "domaintoolsirisipaddresses": format_attribute(domain.get("ip", []), key="address.value"),
            "domaintoolsirismailservers": format_attribute(domain.get("mx", []), key="domain.value"),
            "domaintoolsirisipcountrycode": ip_country_code,
            "domaintoolsirisregistrantorg": domain.get("registrant_org", {}).get("value") or "",
            "registrantname": domain.get("registrant_name", {}).get("value") or "",
            "domaintoolsirissoaemail": format_attribute(domain.get("soa_email", []), key="value"),
            "expirationdate": domain.get("expiration_date", {}).get("value"),
            "domaintoolsirisriskscorecomponents": riskscore_component_mapping
        }
    }


def fetch_domains_from_dt_api(search_type: str, search_value: str) -> list[dict[str, Any]]:
    """Fetch Domains from Domaintools API

    Args:
        search_type (str): The pivot search type
        search_value (str): The search value

    Returns:
        list[dict[str, Any]]: DomainTools Iris response
    """
    search_data = {search_type: search_value}
    dt_query = domain_pivot(search_data)
    dt_results = dt_query['results']
    while dt_query['has_more_results']:
        search_data['position'] = dt_query['position']
        response = domain_pivot(search_data)
        dt_results.extend(response['results'])

    return dt_results


def fetch_and_process_domains(iris_search_hash: dict[str, Any], iris_tags: dict[str, Any]) -> None:
    """
    Fetch and Process Domaintools Domain by given search hash or iris tags.
    Creates incidents/indicators in XSOAR.

    Args:
        iris_search_hash (dict[str, str]): The iris_search_hash key value attribute (keys: search_hash, import_only)
        iris_tags (dict[str, str]): The iris_tags key value attribute (keys: tags, import_only)
    """

    def process_domains(
        domains_list: list[dict[str, Any]] = [],
        import_only: bool = True,
        incident_name: str = "",
        source: str = ""
    ) -> str:
        """ Process domains by the given iris search hash. Creates incidents/indicator in XSOAR.

            domains_list (list): A list of DomainTools Iris domain objects.
            import_only (bool): If True, import only indicators. Otherwise it will create an incident. Defaults to True.
            incident_name (str): The incident name
            source (str): The source name e.g (Domaintools Iris Search Hash)
        """
        last_run = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        indicators = [
            create_indicator_from_dt_domain(domain, source=source)
            for domain in domains_list
        ]

        for batched in batch(indicators, batch_size=BATCH_SIZE):
            demisto.createIndicators(batched)
        demisto.info(f"Added {len(indicators)} indicators to demisto (source: {source})")

        if not import_only and len(indicators) >= 1:
            incident_long_name = f"{incident_name} Since {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}"
            demisto.info(f"Creating incident object for {incident_long_name}")
            incidents.append({
                "name": incident_long_name,
                "details": json.dumps(domains_list),
                "occured": last_run,
                "rawJSON": json.dumps({"incidents": domains_list, "type": source}),
                "type": INCIDENT_TYPES[incident_name],
            })

        return last_run

    incidents: list[Any] = []
    dt_iris_search_hash_result: list[Any] = []
    dt_iris_tags_result: list[Any] = []

    # DT Iris Tags Results
    if iris_tags["tags"]:
        dt_iris_tags_result = fetch_domains_from_dt_api(
            search_type="tagged_with_any", search_value=iris_tags["tags"])

    # DT Iris Search Hash Results
    if iris_search_hash["search_hash"]:
        dt_iris_search_hash_result = fetch_domains_from_dt_api(
            search_type="search_hash", search_value=iris_search_hash["search_hash"])

    domains_to_process = [
        (
            dt_iris_tags_result,
            iris_tags["import_only"],
            DOMAINTOOLS_MONITOR_DOMAINS_INCIDENT_NAME_BY_IRIS_TAGS,
            "DomainTools Iris Tag",
            MONITOR_DOMAIN_IRIS_TAG_TIMESTAMP
        ),
        (
            dt_iris_search_hash_result,
            iris_search_hash["import_only"],
            DOMAINTOOLS_MONITOR_DOMAINS_INCIDENT_NAME_BY_IRIS_SEARCH_HASH,
            "DomainTools Iris Search Hash",
            MONITOR_DOMAIN_IRIS_SEARCH_HASH_TIMESTAMP
        )
    ]

    last_runs = {MONITOR_DOMAIN_IRIS_TAG_TIMESTAMP: "", MONITOR_DOMAIN_IRIS_SEARCH_HASH_TIMESTAMP: ""}

    for domains_list, import_only, incident_name, source, timestamp_key in domains_to_process:
        last_runs[timestamp_key] = process_domains(
            domains_list=domains_list,
            import_only=import_only,
            incident_name=incident_name,
            source=source
        )

    demisto.setIntegrationContext(last_runs)
    demisto.info(f"Adding {len(incidents)} incidents to demisto")
    demisto.incidents(incidents)


''' COMMANDS '''


def domain_command():
    """
    Command to do a total profile of a domain using iris_investigate API endpoint.
    e.g. !domain domain=domaintools.com
    """
    domain = demisto.args()['domain']
    domain_list = domain.split(",")
    domain_chunks = chunks(domain_list, 100)
    include_context = argToBoolean(demisto.args().get('include_context', True))
    command_results_list: list[CommandResults] = []

    for chunk in domain_chunks:
        response = domain_investigate(','.join(chunk))
        missing_domains = response.get("missing_domains")
        for result in response.get('results', []):
            human_readable_output, indicators = format_investigate_output(result)

            if len(missing_domains) > 0:
                human_readable_output += f"Missing Domains: {','.join(missing_domains)}"

            domain_indicator = indicators.get('domain') if include_context else None
            domaintools_context = indicators.get('domaintools') if include_context else None

            command_results_list.append(
                CommandResults(
                    outputs_prefix='DomainTools',
                    outputs_key_field='Name',
                    indicator=domain_indicator,
                    outputs=domaintools_context,
                    readable_output=human_readable_output,
                    raw_response=result,
                    ignore_auto_extract=True,
                )
            )

    if not command_results_list:
        return_warning("No results.", exit=True)

    return_results(command_results_list)


def domain_enrich_command():
    """
    Command to do a total profile of a domain using iris-enrich API endpoint.
    e.g. !domaintoolsiris-enrich domain=domaintools.com
    """
    domain = demisto.args()['domain']
    domain_list = domain.split(",")
    domain_chunks = chunks(domain_list, 100)
    include_context = argToBoolean(demisto.args().get('include_context', True))
    command_results_list: list[CommandResults] = []

    for chunk in domain_chunks:
        response = domain_enrich(','.join(chunk))
        missing_domains = response.get("missing_domains")
        for result in response.get('results', []):
            human_readable_output, indicators = format_enrich_output(result)

            if len(missing_domains) > 0:
                human_readable_output += f"Missing Domains: {','.join(missing_domains)}"

            domain_indicator = indicators.get('domain') if include_context else None
            domaintools_context = indicators.get('domaintools') if include_context else None

            command_results_list.append(
                CommandResults(
                    outputs_prefix='DomainTools',
                    outputs_key_field='Name',
                    outputs=domaintools_context,
                    indicator=domain_indicator,
                    readable_output=human_readable_output,
                    raw_response=result,
                    ignore_auto_extract=True,
                )
            )

    if not command_results_list:
        return_warning("No results.", exit=True)

    return_results(command_results_list)


def domain_analytics_command():
    """
    Command to get risk and other analytics for a domain using iris-investigate API endpoint.
    e.g. !domaintoolsiris-analytics domain=domaintools.com
    """
    domain = demisto.args()['domain']
    response = domain_investigate(domain)

    if not response.get('results_count'):
        return_warning("No analytics for this domain.", exit=True)

    domain_result = response.get('results')[0]
    indicators = create_results(domain_result)
    domain_indicator = indicators.get('domain')
    domaintools_context = indicators.get('domaintools')

    domaintools_analytics_data = domaintools_context.get('Analytics', {})
    domain_age = 0
    if first_seen := domaintools_context.get('FirstSeen', ''):
        first_seen = convert_and_format_date(first_seen)
        domain_age = utils.get_domain_age(first_seen)
    human_readable_data = {
        'Overall Risk Score': domaintools_analytics_data.get('OverallRiskScore', ''),
        'Proximity Risk Score': domaintools_analytics_data.get('ProximityRiskScore', ''),
        'Threat Profile Risk Score': domaintools_analytics_data.get('ThreatProfileRiskScore', {}).get('RiskScore',
                                                                                                      ''),
        'Domain Age (in days)': domain_age,
        'Website Response': domaintools_analytics_data.get('WebsiteResponseCode', ''),
        'Google Adsense': domaintools_analytics_data.get('GoogleAdsenseTrackingCode', ''),
        'Google Analytics': domaintools_analytics_data.get('GoogleAnalyticsTrackingCode', ''),
        'Tags': domaintools_analytics_data.get('Tags', ''),
    }

    headers = ['Overall Risk Score',
               'Proximity Risk Score',
               'Domain Age (in days)',
               'Website Response',
               'Google Adsense',
               'Google Analytics',
               'Tags']
    demisto_title = f'DomainTools Domain Analytics for {domain}.'
    iris_title = f'Investigate [{domain}](https://research.domaintools.com/iris/search/?q={domain}) in Iris.'
    human_readable = tableToMarkdown(
        f'{demisto_title} {iris_title}',
        human_readable_data,
        headers=headers,
    )

    return_results(
        CommandResults(
            outputs_prefix='DomainTools',
            outputs_key_field='Name',
            outputs=domaintools_context,
            indicator=domain_indicator,
            readable_output=human_readable,
            raw_response=domain_result,
            ignore_auto_extract=True,
        )
    )


def threat_profile_command():
    """
    Command to get threat profile for a domain using iris-investigate API endpoint.
    e.g. !domaintoolsiris-threat-profile domain=domaintools.com
    """
    domain = demisto.args()['domain']
    response = domain_investigate(domain)

    if not response.get('results_count'):
        return_warning("No threat profile for this domain.", exit=True)

    domain_result = response.get('results')[0]
    indicators = create_results(domain_result)
    domain_indicator = indicators.get('domain')
    domaintools_context = indicators.get('domaintools')

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
        proximity_data = utils.get_threat_component(risk_components, 'proximity')
        blacklist_data = utils.get_threat_component(risk_components, 'blacklist')
        if proximity_data:
            proximity_risk_score = proximity_data.get('risk_score', 0)
        elif blacklist_data:
            proximity_risk_score = blacklist_data.get('risk_score', 0)
        threat_profile_data = utils.get_threat_component(risk_components, 'threat_profile')
        if threat_profile_data:
            threat_profile_risk_score = threat_profile_data.get('risk_score', 0)
            threat_profile_threats = ', '.join(threat_profile_data.get('threats', []))
            threat_profile_evidence = ', '.join(threat_profile_data.get('evidence', []))
        threat_profile_malware_data = utils.get_threat_component(risk_components, 'threat_profile_malware')
        if threat_profile_malware_data:
            threat_profile_malware_risk_score = threat_profile_malware_data.get('risk_score', 0)
        threat_profile_phshing_data = utils.get_threat_component(risk_components, 'threat_profile_phishing')
        if threat_profile_phshing_data:
            threat_profile_phishing_risk_score = threat_profile_phshing_data.get('risk_score', 0)
        threat_profile_spam_data = utils.get_threat_component(risk_components, 'threat_profile_spam')
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
    demisto_title = f'DomainTools Threat Profile for {domain}.'
    iris_title = f'Investigate [{domain}](https://research.domaintools.com/iris/search/?q={domain}) in Iris.'
    human_readable = tableToMarkdown(f'{demisto_title} {iris_title}',
                                     human_readable_data,
                                     headers=headers)

    return_results(
        CommandResults(
            outputs_prefix='DomainTools',
            outputs_key_field='Name',
            outputs=domaintools_context,
            indicator=domain_indicator,
            readable_output=human_readable,
            raw_response=domain_result,
            ignore_auto_extract=True,
        )
    )


def domain_pivot_command():
    """
    Command to get list of domains that share connected infrastructure iris-investigate API endpoint.
    e.g. !domaintoolsiris-pivot ip=1.1.1.1
    """
    search_data = {}  # type: dict[Any, Any]
    search_type = ''
    search_value = ''
    available_pivots = {
        'ip': 'IP',
        'email': 'E-Mail',
        'nameserver_ip': 'Name Server IP',
        'ssl_hash': 'SSL Hash',
        'nameserver_host': 'Name Server Host',
        'mailserver_host': 'Mail Server Host',
        'email_domain': 'Email Domain',
        'nameserver_domain': 'Name Server Domain',
        'registrar': 'Registrar',
        'registrant': 'Registrant',
        'registrant_org': 'Registrant Org',
        'tagged_with_any': 'Tagged with Any',
        'tagged_with_all': 'Tagged with All',
        'mailserver_domain': 'Mail Server Domain',
        'mailserver_ip': 'Mail Server IP',
        'redirect_domain': 'Redirect Domain',
        'ssl_org': 'SSL Org',
        'ssl_subject': 'SSL Subject',
        'ssl_email': 'SSL Email',
        'google_analytics': 'Google Analytics',
        'adsense': 'Adsense',
        'search_hash': 'Iris Search Hash'
    }

    for pivot_type in available_pivots:
        if demisto.args().get(pivot_type):
            search_data = {pivot_type: demisto.args().get(pivot_type)}
            search_type, search_value = available_pivots[pivot_type], demisto.args().get(pivot_type)
            break

    if not search_type or not search_value:
        raise Exception(f"Invalid pivot type or value. pivot type: {search_type} search value: {search_value}")

    response = domain_pivot(search_data)
    results = response['results']
    while response['has_more_results']:
        search_data['position'] = response['position']
        response = domain_pivot(search_data)
        results.extend(response['results'])

    output = []
    domain_context_list = []
    risk_list = []
    age_list = []
    count = 0
    include_context = argToBoolean(demisto.args().get('include_context', True))

    if not response.get('results_count'):
        return_warning("No pivots for this search.", exit=True)

    for domain_result in results:
        risk_score = domain_result.get('domain_risk', {}).get('risk_score')
        first_seen = domain_result.get('first_seen', {}).get('value') if domain_result.get('first_seen') else ""
        output.append({'domain': domain_result.get('domain'), 'risk_score': risk_score})

        if risk_score is not None:
            risk_list.append(risk_score)
        if first_seen:
            first_seen = convert_and_format_date(first_seen)
            domain_age = utils.get_domain_age(first_seen)
            age_list.append(domain_age)
        if include_context:
            domain_context = create_results(domain_result)
            domain_context_list.append(domain_context.get('domaintools'))

        count += 1

    average_risk = round(statistics.mean(risk_list), 2) if risk_list else "Unknown"
    average_age = round(statistics.mean(age_list), 2) if age_list else "Unknown"

    pivot_result = {
        "Value": search_value,
        "AverageRisk": average_risk,
        "AverageAge": average_age,
        "PivotedDomains": domain_context_list
    }

    headers = ['domain', 'risk_score']

    sorted_output = sorted(output, key=lambda x: x['risk_score'] if x['risk_score'] is not None else -1, reverse=True)
    human_readable = tableToMarkdown(f'Domains for {search_type}: {search_value} '
                                     f'({count} results, {average_risk} average risk, {average_age} average age)',
                                     sorted_output,
                                     headers=headers)

    results = CommandResults(
        outputs_prefix='DomainTools.Pivots',
        outputs_key_field='Value',
        outputs=pivot_result,
        readable_output=human_readable,
        ignore_auto_extract=True
    )
    return_results(results)


def to_camel_case(value):
    result = f' {value.strip()}'
    result = re.sub(r' ([a-z,A-Z])', lambda g: g.group(1).upper(), result)
    return result


def whois_history_command():
    """
    Command to get whois history for a domain using the whois-history API endpoint.
    e.g. !whoisHistory domain=domaintools.com
    """
    domain = demisto.args()['domain']
    sort = demisto.args().get('sort')
    limit = demisto.args().get('limit')
    mode = demisto.args().get('mode')
    offset = demisto.args().get('offset')
    response = whois_history(domain=domain, sort=sort, limit=limit, mode=mode, offset=offset)
    history = response.get('history', [])

    all_context = []
    human_readable = ''

    for entry in history:
        record = entry.get('whois', {}).get('record')
        split_record = record.split('\n')
        entry_context = {}
        table = {}
        headers = []

        for pair in split_record:
            split_entry = re.split(r':\s(.+)', pair)
            if len(split_entry) > 1:
                label = split_entry[0].rstrip('.')
                value = split_entry[1]

                headers.append(label)
                table[label] = value
                entry_context[to_camel_case(label)] = value

        human_readable += tableToMarkdown(f"{domain}: {entry.get('date')}", table, headers=headers)
        all_context.append(entry_context)

    history_result = {
        "Value": domain,
        "WhoisHistory": all_context
    }

    if mode == 'count':
        human_readable = f'record count: {response.get("record_count")}'
    if mode == 'check_existence':
        human_readable = f'has history entries: {response.get("has_history_entries")}'

    results = CommandResults(
        outputs_prefix='DomainTools.History',
        outputs_key_field='Value',
        outputs=history_result,
        readable_output=human_readable,
        ignore_auto_extract=True
    )
    return_results(results)


def create_history_table(data, headers):
    table = []
    for row in data:
        entry = {header: row.get(header) for header in headers}
        table.append(entry)

    return table


def hosting_history_command():
    """
    Command to get hosting history for a domain using the hosting-history API endpoint.
    e.g. !hostingHistory domain=domaintools.com
    """
    domain = demisto.args()['domain']
    response = hosting_history(domain)

    ip_history = response.get('ip_history', [])
    ip_headers = ['domain', 'actiondate', 'action', 'action_in_words', 'post_ip', 'pre_ip']
    ip_table = create_history_table(ip_history, ip_headers)
    human_readable_ip = tableToMarkdown(
        "IP Address History", ip_table, headers=ip_headers
    )

    ns_history = response.get('nameserver_history', [])
    ns_headers = ['domain', 'actiondate', 'action', 'action_in_words', 'post_mns', 'pre_mns']
    ns_table = create_history_table(ns_history, ns_headers)
    human_readable_ns = tableToMarkdown(
        "Name Server History", ns_table, headers=ns_headers
    )

    registrar_history = response.get('registrar_history', [])
    registrar_headers = [
        'domain',
        'date_created',
        'date_expires',
        'date_lastchecked',
        'date_updated',
        'registrar',
        'registrartag']
    registrar_table = create_history_table(registrar_history, registrar_headers)
    human_readable_registrar = tableToMarkdown(
        "Registrar History", registrar_table, headers=registrar_headers
    )

    human_readable_all = human_readable_registrar + human_readable_ns + human_readable_ip
    history_result = {'Value': domain, 'IPHistory': ip_table, 'NameserverHistory': ns_table, 'RegistrarHistory': registrar_table}

    results = CommandResults(
        outputs_prefix='DomainTools.History',
        outputs_key_field='Value',
        outputs=history_result,
        readable_output=human_readable_all,
        ignore_auto_extract=True
    )
    return_results(results)


def reverse_whois_command():
    """
    Command to get list of domains that share same registrant info using the reverse-whois API endpoint.
    e.g. !reverseWhois terms=domaintools
    """
    terms = demisto.args()['terms']
    exclude = demisto.args().get('exclude')
    scope = (
        'current'
        if demisto.args().get('onlyHistoricScope') == 'false'
        else 'historic'
    )
    results = reverse_whois(query=terms, mode='purchase', exclude=exclude, scope=scope)
    domains = results.get('domains', [])

    context = []
    human_readable = f'Found {len(domains)} domains:\n'

    for domain in domains:
        human_readable += f'* {domain}\n'
        context.append({'Name': domain})

    all_context = {'Value': terms, 'Results': context}
    results = CommandResults(
        outputs_prefix='DomainTools.ReverseWhois',
        outputs_key_field='Value',
        outputs=all_context,
        readable_output=human_readable,
        ignore_auto_extract=True
    )
    return_results(results)


def change_keys(conv, obj):
    output = {}
    for key, value in obj.items():
        if isinstance(value, dict):
            output[conv(key)] = change_keys(conv, value)
        else:
            output[conv(key)] = value
    return output


def parsed_whois_command():
    domain = demisto.args()['query']
    response = parsed_whois(domain)

    whois_record = response.get('whois', {}).get('record', '')
    split_record = whois_record.split('\n')
    table = {}
    headers = []
    for entry in split_record:
        split_entry = re.split(r':\s(.+)', entry)
        if len(split_entry) > 1:
            headers.append(split_entry[0])
            table[split_entry[0]] = split_entry[1]

    human_readable = tableToMarkdown(f'DomainTools whois result for {domain}', table, headers=headers)

    parsed = response.get('parsed_whois', {})
    domain_indicator = Common.Domain(domain, None,
                                     registrar_name=parsed.get('registrar', {}).get('name'),
                                     registrar_abuse_email=parsed.get('registrar', {}).get('abuse_contact_email'),
                                     registrar_abuse_phone=parsed.get('registrar', {}).get('abuse_contact_phone'),

                                     registrant_name=parsed.get('contacts', {}).get('registrant', {}).get('name'),
                                     registrant_email=parsed.get('contacts', {}).get('registrant', {}).get('email'),
                                     registrant_phone=parsed.get('contacts', {}).get('registrant', {}).get('phone'),
                                     registrant_country=parsed.get('contacts', {}).get('registrant', {}).get('country'),

                                     admin_name=parsed.get('contacts', {}).get('admin', {}).get('name'),
                                     admin_email=parsed.get('contacts', {}).get('admin', {}).get('email'),
                                     admin_phone=parsed.get('contacts', {}).get('admin', {}).get('phone'),
                                     admin_country=parsed.get('contacts', {}).get('admin', {}).get('country'),

                                     tech_country=parsed.get('contacts', {}).get('tech', {}).get('country'),
                                     tech_name=parsed.get('contacts', {}).get('tech', {}).get('name'),
                                     tech_organization=parsed.get('contacts', {}).get('tech', {}).get('org'),
                                     tech_email=parsed.get('contacts', {}).get('tech', {}).get('email'),
                                     billing=parsed.get('contacts', {}).get('billing', {}).get('name'),
                                     name_servers=parsed.get('name_servers'),
                                     whois_records=[
                                         Common.WhoisRecord(
                                             whois_record_value=whois_record,
                                             whois_record_date=parsed.get('updated_date'))]
                                     )

    results = CommandResults(
        indicator=domain_indicator,
        readable_output=human_readable,
        raw_response=parsed,
        ignore_auto_extract=True
    )

    return_results(results)


def test_module():
    """
    Tests the API key for a user.
    """

    http_request('iris-investigate', {'domains': 'demisto.com'})
    demisto.results('ok')


def fetch_domains():
    # iris search hash
    monitor_domain_by_search_hash = demisto.params().get("monitor_iris_search_hash") or "Import Indicators Only"
    iris_search_hash = demisto.params().get("domaintools_iris_search_hash") or False
    # iris tags
    monitor_domain_by_iris_tags = demisto.params().get("monitor_iris_tags") or "Import Indicators Only"
    iris_tags = demisto.params().get("domaintools_iris_tags") or False

    iris_search_hash_params = {
        "import_only": monitor_domain_by_search_hash == "Import Indicators Only",
        "search_hash": iris_search_hash
    }
    iris_tags_params = {
        "import_only": monitor_domain_by_iris_tags == "Import Indicators Only",
        "tags": iris_tags
    }

    fetch_and_process_domains(
        iris_search_hash=iris_search_hash_params,
        iris_tags=iris_tags_params
    )


def main():
    """
    Main Demisto function.
    """
    try:
        if demisto.command() == 'test-module':
            test_module()
        elif demisto.command() == 'domain':
            domain_command()
        elif demisto.command() == 'domaintoolsiris-investigate':
            domain_command()
        elif demisto.command() == 'domaintoolsiris-analytics':
            domain_analytics_command()
        elif demisto.command() == 'domaintoolsiris-threat-profile':
            threat_profile_command()
        elif demisto.command() == 'domaintoolsiris-pivot':
            domain_pivot_command()
        elif demisto.command() == 'domaintoolsiris-enrich':
            domain_enrich_command()
        elif demisto.command() == 'domaintools-whois-history':
            whois_history_command()
        elif demisto.command() == 'domaintools-hosting-history':
            hosting_history_command()
        elif demisto.command() == 'domaintools-reverse-whois':
            reverse_whois_command()
        elif demisto.command() == 'domaintools-whois':
            parsed_whois_command()
        elif demisto.command() == 'fetch-incidents':
            fetch_domains()
    except Exception as e:
        return_error(
            f'Unable to perform command : {demisto.command()}, Reason: {str(e)}'
        )


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
