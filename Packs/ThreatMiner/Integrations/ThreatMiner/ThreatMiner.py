import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3


''' IMPORTS '''

# disable insecure warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_HEADERS = {
    "Content-Type": "application/json"
}

''' HELPER FUNCTIONS '''


def http_request(method, url, verify_certificates, headers):
    try:
        res = requests.request(method,
                               url,
                               verify=verify_certificates,
                               headers=headers)

        if res.status_code == 200:
            return res.json()
        # 204 HTTP status code is returned when api rate limit has been exceeded
        elif res.status_code == 204:
            return_error("You've reached your API call quota.")
        elif res.status_code == 404:
            return {}

        res.raise_for_status()

    except Exception as e:
        demisto.results({
            'Type': entryTypes['error'],
            'ContentsFormat': formats['text'],
            'Contents': f'error has occured: {e}',
        })


def get_domain_report_from_threat_miner(domain_name, threat_miner_url, verify_certificates):
    return {
        'raw_whois': get_domain_whois_rawdata(domain_name, threat_miner_url, verify_certificates),
        'raw_passive_dns': get_domain_passive_dns_rawdata(domain_name, threat_miner_url, verify_certificates),
        'raw_sub_domains': get_domain_subdomains_rawdata(domain_name, threat_miner_url, verify_certificates),
        'raw_domain_uris': get_domain_URI_rawdata(domain_name, threat_miner_url, verify_certificates),
        'raw_domain_md5': get_domain_MD5_rawdata(domain_name, threat_miner_url, verify_certificates)
    }


def get_domain_whois_rawdata(domain_name, threat_miner_url, verify_certificates):
    threat_miner_domain_url_postfix = f'domain.php?q={domain_name}&rt={1}'
    response = http_request('GET', threat_miner_url + threat_miner_domain_url_postfix, verify_certificates,
                            DEFAULT_HEADERS)
    domain_whois = response.get('results', [])
    if len(domain_whois) == 0:
        return {}

    return domain_whois[0]


def get_domain_passive_dns_rawdata(domain_name, threat_miner_url, verify_certificates):
    threat_miner_domain_url_postfix = f'domain.php?q={domain_name}&rt={2}'
    response = http_request('GET', threat_miner_url + threat_miner_domain_url_postfix, verify_certificates,
                            DEFAULT_HEADERS)
    threatminer_results_as_array = response.get('results', [])
    if len(threatminer_results_as_array) == 0:
        return []

    return threatminer_results_as_array


def get_domain_passive_dns(passive_dns, max_returned_array_size):
    if max_returned_array_size == -1:
        return passive_dns['raw_passive_dns']
    return passive_dns['raw_passive_dns'][:max_returned_array_size]


def get_domain_subdomains_rawdata(domain_name, threat_miner_url, verify_certificates):
    threat_miner_domain_url_postfix = f'domain.php?q={domain_name}&rt={5}'
    response = http_request('GET', threat_miner_url + threat_miner_domain_url_postfix, verify_certificates,
                            DEFAULT_HEADERS)
    sub_domains_array = response.get('results', [])
    return sub_domains_array


def get_domain_URI_rawdata(domain_name, threat_miner_url, verify_certificates):
    threat_miner_domain_url_postfix = f'domain.php?q={domain_name}&rt={3}'
    response = http_request('GET', threat_miner_url + threat_miner_domain_url_postfix, verify_certificates,
                            DEFAULT_HEADERS)
    uris_full_result = response.get('results', [])
    return uris_full_result


def get_domain_URI(uris_raw_data, max_returned_array_size):
    uri_counter = 0
    uris = []
    for uri_info in uris_raw_data['raw_domain_uris']:
        if max_returned_array_size == -1 or uri_counter < max_returned_array_size:
            uris.append({
                'Address': uri_info['uri'],
                'LastSeen': uri_info['last_seen']
            })
            uri_counter += 1
        else:
            break

    return uris


def get_domain_MD5_rawdata(domain_name, threat_miner_url, verify_certificates):
    threat_miner_domain_url_postfix = f'domain.php?q={domain_name}&rt={4}'
    response = http_request('GET', threat_miner_url + threat_miner_domain_url_postfix, verify_certificates,
                            DEFAULT_HEADERS)
    md5s = response.get('results', [])
    return md5s


def create_domain_command_markdown(domain, context):
    md = f'## Threat_miner Domain report for: {domain}\n'
    threat_miner_found_results = False

    if len(context.get('Whois', '')) != 0:
        md += tableToMarkdown(f"Whois for {domain} domain", context['Whois'],
                              ['Domain', 'Server', 'CreateDate', 'UpdateDate', 'Expiration', 'NameServers'])
        threat_miner_found_results = True
    if len(context.get('PassiveDNS', '')) != 0:
        md += tableToMarkdown(f"PassiveDNS for {domain} domain",
                              context['PassiveDNS'], ['IP', 'FirstSeen', 'LastSeen'])
        threat_miner_found_results = True
    if len(context.get('Subdomains', '')) != 0:
        md += tableToMarkdown(f"{domain} Subdomains", context['Subdomains'],
                              ['Subdomains'])
        threat_miner_found_results = True
    if len(context.get('URI', '')) != 0:
        md += tableToMarkdown(f"{domain} URIs", context['URI'],
                              ['Address', 'LastSeen'])
        threat_miner_found_results = True
    if len(context.get('MD5', '')) != 0:
        md += tableToMarkdown(f"{domain} Related Samples(hash only)",
                              context['MD5'], ['hashes'])
        threat_miner_found_results = True

    if not threat_miner_found_results:
        md += 'No results found'

    return md


def domain_command(**kwargs):
    domains_names = demisto.args().get('domain')
    domains_names_list = argToList(domains_names)

    domains_results = []

    for domain_name in domains_names_list:
        threat_miner_raw_results = get_domain_report_from_threat_miner(domain_name, kwargs.get('threat_miner_url'),
                                                                       kwargs.get('verify_certificates'))

        passive_dns = {}
        subdomains = {}
        md5s = {}
        max_returned_array_size = kwargs.get('max_array_size')
        if max_returned_array_size == -1:
            passive_dnses = threat_miner_raw_results['raw_passive_dns']
            subdomains = threat_miner_raw_results['raw_sub_domains']
            md5s = threat_miner_raw_results['raw_domain_md5']
        else:
            passive_dnses = threat_miner_raw_results['raw_passive_dns'][:max_returned_array_size]
            subdomains = threat_miner_raw_results['raw_sub_domains'][:max_returned_array_size]
            md5s = threat_miner_raw_results['raw_domain_md5'][:max_returned_array_size]

        context_passive_dnses = []
        for passive_dns in passive_dnses:
            context_passive_dnses.append({
                'IP': passive_dns['ip'],
                'FirstSeen': passive_dns['first_seen'],
                'LastSeen': passive_dns['last_seen']

            })

        threat_miner_context = {
            'Name': domain_name,
            'Whois': {
                'Server': threat_miner_raw_results['raw_whois']['whois']['whois_server'],
                'CreateDate': threat_miner_raw_results['raw_whois']['whois']['creation_date'],
                'UpdateDate': threat_miner_raw_results['raw_whois']['whois']['updated_date'],
                'Expiration': threat_miner_raw_results['raw_whois']['whois']['expiration_date'],
                'NameServers': threat_miner_raw_results['raw_whois']['whois']['nameservers']
            },
            'PassiveDNS': context_passive_dnses,
            'Subdomains': subdomains,
            'URI': get_domain_URI(threat_miner_raw_results, max_returned_array_size),
            'MD5': md5s
        }

        passive_dnses_ips = []
        for passive_dns in passive_dnses:
            passive_dnses_ips.append(passive_dns['ip'])

        domain_context = {
            "Name": threat_miner_context['Name'],
            "DNS": passive_dnses_ips,
            'Whois': {
                'UpdateDate': threat_miner_context['Whois']['UpdateDate'],
                'CreateDate': threat_miner_context['Whois']['CreateDate'],
                'Expiration': threat_miner_context['Whois']['Expiration'],
                'Registrant': {
                    'Name': threat_miner_raw_results['raw_whois']['whois']['tech_info']['Organization'],
                    'Email': threat_miner_raw_results['raw_whois']['whois']['emails']['registrant']
                }
            }
        }

        context = {
            'ThreatMiner.Domain(val.Name && val.Name == obj.Name)': threat_miner_context,
            'Domain(val.Name && val.Name == obj.Name)': domain_context
        }

        markdown = create_domain_command_markdown(domain_name, threat_miner_context)

        result = {
            'Type': entryTypes['note'],
            'Contents': threat_miner_raw_results,
            'HumanReadable': markdown,
            'EntryContext': context,
            'ContentsFormat': formats['json']
        }
        domains_results.append(result)

    demisto.results(domains_results)


def get_ip_whois_rawdata(ip_address, threat_miner_url, verify_certificates):
    threat_miner_ip_url_postfix = f'host.php?q={ip_address}&rt={1}'
    response = http_request('GET', threat_miner_url + threat_miner_ip_url_postfix,
                            verify_certificates, DEFAULT_HEADERS)
    whois_rawdata = response.get('results', [])
    if len(whois_rawdata) > 0:
        return whois_rawdata[0]
    return {}


def get_ip_whois(whois_rawdata, ip_address):
    ip_whois_results = {}
    ip_whois_results['Address'] = ip_address
    ip_whois_results['Reverse'] = whois_rawdata['raw_whois']['reverse_name']
    ip_whois_results['Bgp'] = whois_rawdata['raw_whois']['bgp_prefix']
    ip_whois_results['Country'] = whois_rawdata['raw_whois']['cc']
    ip_whois_results['ASN'] = whois_rawdata['raw_whois']['asn']
    ip_whois_results['Org'] = whois_rawdata['raw_whois']['org_name']

    return ip_whois_results


def get_ip_passiveDNS_rawdata(ip_address, threat_miner_url, verify_certificates):
    threat_miner_ip_url_postfix = f'host.php?q={ip_address}&rt={2}'
    response = http_request('GET', threat_miner_url + threat_miner_ip_url_postfix, verify_certificates, DEFAULT_HEADERS)
    passiveDNSArray = response.get('results', [])

    return passiveDNSArray


def get_ip_URI_rawdata(ip_address, threat_miner_url, verify_certificates):
    threat_miner_ip_url_postfix = f'host.php?q={ip_address}&rt={3}'
    response = http_request('GET', threat_miner_url + threat_miner_ip_url_postfix, verify_certificates, DEFAULT_HEADERS)
    uris_rawdata = response.get('results', [])
    return uris_rawdata


def get_ip_URI(threatminer_results_as_array, max_returned_array_size):
    uri_counter = 0
    URIs = []

    for _ in threatminer_results_as_array['raw_ip_uris']:
        if max_returned_array_size == -1 or uri_counter < max_returned_array_size:
            URIs.append({
                'Address': threatminer_results_as_array['raw_ip_uris'][uri_counter]['uri'],
                'LastSeen': threatminer_results_as_array['raw_ip_uris'][uri_counter]['last_seen']
            })
            uri_counter += 1
        else:
            break

    return URIs


def get_ip_MD5_rawdata(ip_address, threat_miner_url, verify_certificates):
    threat_miner_domain_url_postfix = f'host.php?q={ip_address}&rt={4}'
    response = http_request('GET', threat_miner_url + threat_miner_domain_url_postfix, verify_certificates,
                            DEFAULT_HEADERS)

    md5s = response.get('results', [])

    if len(md5s) == 0:
        return []
    return md5s


def get_ip_SSL_rawdata(ip_address, threat_miner_url, verify_certificates):
    threat_miner_domain_url_postfix = f'host.php?q={ip_address}&rt={5}'
    response = http_request('GET', threat_miner_url + threat_miner_domain_url_postfix, verify_certificates,
                            DEFAULT_HEADERS)

    ssls_raw_data = response.get('results', [])
    return ssls_raw_data


def create_ip_command_markdown(ip_address, context):
    md = f'## Threat_miner IP report for: {ip_address}\n'
    threat_miner_found_results = False

    if len(context['Whois']) != 0:
        md += tableToMarkdown(f"Whois for {ip_address}", context['Whois'],
                              ['Address', 'Country', 'Org', 'Bgp', 'Reverse', 'ASN'])
        threat_miner_found_results = True
    if len(context['PassiveDNS']) != 0:
        md += tableToMarkdown(f"PassiveDNS for {ip_address}", context['PassiveDNS'],
                              ['Domain', 'FirstSeen', 'LastSeen'])
        threat_miner_found_results = True
    if len(context['URI']) != 0:
        md += tableToMarkdown(f"{ip_address} URIs", context['URI'],
                              ['Address', 'LastSeen'])
        threat_miner_found_results = True
    if len(context['MD5']) != 0:
        md += tableToMarkdown(f"{ip_address} MD5s", context['MD5'], ['MD5'])
        threat_miner_found_results = True
    if len(context['SSL']) != 0:
        md += tableToMarkdown(f"{ip_address} SSLs", context['SSL'], ['SSL'])
        threat_miner_found_results = True

    if not threat_miner_found_results:
        md += 'No results found'

    return md


def get_ip_report_from_threat_miner(ip_address, threat_miner_url, verify_certificates):
    return {
        'raw_whois': get_ip_whois_rawdata(ip_address, threat_miner_url, verify_certificates),
        'raw_passive_dns': get_ip_passiveDNS_rawdata(ip_address, threat_miner_url, verify_certificates),
        'raw_ip_md5': get_ip_MD5_rawdata(ip_address, threat_miner_url, verify_certificates),
        'raw_ip_uris': get_ip_URI_rawdata(ip_address, threat_miner_url, verify_certificates),
        'raw_ip_ssl': get_ip_SSL_rawdata(ip_address, threat_miner_url, verify_certificates)
    }


def get_passive_dns(threat_miner_raw_results):
    passive_dnses = []
    for passive_dns in threat_miner_raw_results['raw_passive_dns']:
        passive_dnses.append({
            "Domain": passive_dns['domain'],
            "FirstSeen": passive_dns['first_seen'],
            "LastSeen": passive_dns['last_seen']
        })
    return passive_dnses


def validate_ips(ips):
    invalid_ips = []

    for ip in ips:
        if not is_ip_valid(ip):
            invalid_ips.append(ip)

    if invalid_ips:
        return_error(f'An invalid IP(s) was specified: {invalid_ips}')


def ip_command(**kwargs):
    ips_address = demisto.args().get('ip')
    ips_address_list = argToList(ips_address)

    validate_ips(ips_address_list)

    ips_address_results = []

    for ip_address in ips_address_list:
        threat_miner_raw_results = get_ip_report_from_threat_miner(ip_address, kwargs.get('threat_miner_url'),
                                                                   kwargs.get('verify_certificates'))
        passiveDnses = get_passive_dns(threat_miner_raw_results)
        md5s = {}
        ssls = {}

        max_returned_array_size = kwargs.get('max_array_size')
        if max_returned_array_size == -1:
            passiveDns = passiveDnses
            md5s = threat_miner_raw_results['raw_ip_md5']
            ssls = threat_miner_raw_results['raw_ip_ssl']
        else:
            ssls = threat_miner_raw_results['raw_ip_ssl'][:max_returned_array_size]
            passiveDns = passiveDnses[:max_returned_array_size]
            md5s = threat_miner_raw_results['raw_ip_md5'][:max_returned_array_size]

        threat_miner_context = {
            'Address': ip_address,
            'Whois': {
                'Address': ip_address,
                'Reverse': threat_miner_raw_results['raw_whois'].get('reverse_name'),
                'Bgp': threat_miner_raw_results['raw_whois'].get('bgp_prefix'),
                'Country': threat_miner_raw_results['raw_whois'].get('cc'),
                'ASN': threat_miner_raw_results['raw_whois'].get('asn'),
                'Org': threat_miner_raw_results['raw_whois'].get('org_name')
            },
            'PassiveDNS': passiveDns,
            'MD5': md5s,
            'URI': get_ip_URI(threat_miner_raw_results, max_returned_array_size),
            'SSL': ssls
        }

        markdown = create_ip_command_markdown(ip_address, threat_miner_context)
        ipcontext = {
            "IP.Address": threat_miner_context['Address'],
            "IP.Geo.Country": threat_miner_context['Whois']['Country'],
            "IP.ASN": threat_miner_context['Whois']['ASN'],
        }
        context = {
            'ThreatMiner.IP(val.Address && val.Address == obj.Address)': threat_miner_context,
            'IP(val.Address && val.Address == obj.Address)': ipcontext
        }

        result = {
            'Type': entryTypes['note'],
            'Contents': threat_miner_raw_results,
            'HumanReadable': markdown,
            'EntryContext': context,
            'ContentsFormat': formats['json']
        }
        ips_address_results.append(result)

    demisto.results(ips_address_results)


def get_file_whois_rawdata(hashed_file, threat_miner_url, verify_certificates):
    threat_miner_ip_url_postfix = f'sample.php?q={hashed_file}&rt={1}'
    response = http_request('GET', threat_miner_url + threat_miner_ip_url_postfix, verify_certificates, DEFAULT_HEADERS)
    threatminer_results_as_array = response.get('results', [])

    if len(threatminer_results_as_array) == 0:
        return {}

    return threatminer_results_as_array[0]


def get_file_http_rawdata(hashed_file, threat_miner_url, verify_certificates):
    threat_miner_domain_url_postfix = f'sample.php?q={hashed_file}&rt={2}'
    response = http_request('GET', threat_miner_url + threat_miner_domain_url_postfix, verify_certificates,
                            DEFAULT_HEADERS)
    file_http_raw_data = response.get('results', [])
    return file_http_raw_data


def get_file_http(file_http_raw_data, max_returned_array_size):
    if len(file_http_raw_data['raw_file_https']) == 0:
        return []

    file_http = file_http_raw_data['raw_file_https'][0]
    http_traffics = file_http['http_traffic']

    http_traffic_counter = 0
    http_traffics_info = []

    for _ in http_traffics:
        if max_returned_array_size == -1 or http_traffic_counter < max_returned_array_size:
            http_traffics_info.append({
                'Domain': http_traffics[http_traffic_counter]['domain'],
                'URL': http_traffics[http_traffic_counter]['url'],
                'Useragent': http_traffics[http_traffic_counter]['user_agent']
            })
            http_traffic_counter += 1
        else:
            break
    return http_traffics_info


def get_file_domains_and_ip_rawdata(hashed_file, threat_miner_url, verify_certificates):
    threat_miner_domain_url_postfix = f'sample.php?q={hashed_file}&rt={3}'
    response = http_request('GET', threat_miner_url + threat_miner_domain_url_postfix, verify_certificates,
                            DEFAULT_HEADERS)
    domain_and_ip_raw_data = response.get('results', [])
    return domain_and_ip_raw_data


def get_file_domains_and_ip(domain_and_ip_raw_data, max_returned_array_size):
    if len(domain_and_ip_raw_data['raw_file_domains']) == 0:
        return {}

    counter = 0
    domains_and_ips = []
    for domain_and_ip in domain_and_ip_raw_data['raw_file_domains'][0]['domains']:
        if max_returned_array_size == -1 or counter < max_returned_array_size:
            domains_and_ips.append({
                'Domain': domain_and_ip['domain'],
                'IP': domain_and_ip['ip']
            })
        else:
            break
    return domains_and_ips


def get_file_mutants_rawdata(hashed_file, threat_miner_url, verify_certificates):
    threat_miner_domain_url_postfix = f'sample.php?q={hashed_file}&rt={4}'
    response = http_request('GET', threat_miner_url + threat_miner_domain_url_postfix, verify_certificates,
                            DEFAULT_HEADERS)
    mutants_rawdata = response.get('results', [])
    return mutants_rawdata


def get_file_mutants(mutants_rawdata, max_returned_array_size):
    if len(mutants_rawdata['raw_file_mutants']) == 0:
        return {}

    file_mutants = mutants_rawdata['raw_file_mutants'][0]
    if max_returned_array_size == -1:
        return file_mutants['mutants']
    return file_mutants['mutants'][:max_returned_array_size]


def get_file_registry_keys_rawdata(hashed_file, threat_miner_url, verify_certificates):
    threat_miner_domain_url_postfix = f'sample.php?q={hashed_file}&rt={5}'
    response = http_request('GET', threat_miner_url + threat_miner_domain_url_postfix, verify_certificates,
                            DEFAULT_HEADERS)

    threatminer_results_as_array = response.get('results', [])
    if len(threatminer_results_as_array) == 0:
        return {}
    return threatminer_results_as_array[0]


def get_file_registry_keys(file_registry_keys, max_returned_array_size):
    if len(file_registry_keys['raw_file_registry']) == 0:
        return {}

    if max_returned_array_size == -1:
        return file_registry_keys['raw_file_registry']['registry_keys']
    return file_registry_keys['raw_file_registry']['registry_keys'][:max_returned_array_size]


def get_file_AV_detection_rawdata(hashed_file, threat_miner_url, verify_certificates):
    threat_miner_domain_url_postfix = f'sample.php?q={hashed_file}&rt={6}'
    response = http_request('GET', threat_miner_url + threat_miner_domain_url_postfix, verify_certificates,
                            DEFAULT_HEADERS)

    raw_file_av_dectection = response.get('results', {})
    return raw_file_av_dectection


def get_file_AV_detection(raw_file_av_dectection):
    if len(raw_file_av_dectection['raw_file_av']) == 0:
        return {}

    av_detections = []
    for av_detection in raw_file_av_dectection['raw_file_av'][0]['av_detections']:
        av_detections.append({
            'Name': av_detection['av'],
            'Detection': av_detection['detection']
        })
    return av_detections


def get_file_report_from_threat_miner(hashed_file, threat_miner_url, verify_certificates):
    return {
        'raw_whois': get_file_whois_rawdata(hashed_file, threat_miner_url, verify_certificates),
        'raw_file_https': get_file_http_rawdata(hashed_file, threat_miner_url, verify_certificates),
        'raw_file_domains': get_file_domains_and_ip_rawdata(hashed_file, threat_miner_url, verify_certificates),
        'raw_file_mutants': get_file_mutants_rawdata(hashed_file, threat_miner_url, verify_certificates),
        'raw_file_registry': get_file_registry_keys_rawdata(hashed_file, threat_miner_url, verify_certificates),
        'raw_file_av': get_file_AV_detection_rawdata(hashed_file, threat_miner_url, verify_certificates)
    }


def get_dbot_scores_context(threat_miner_raw_results, file_context, hashed_file, reliability):
    amount_of_detections = len(threat_miner_raw_results.get('AV', ''))
    dbot_scores = get_dbot_score_report(amount_of_detections, hashed_file, file_context, reliability)
    return dbot_scores


def file_command(**kwargs):
    hashed_files = demisto.args().get('file')
    hashed_files_list = argToList(hashed_files)

    hashed_files_results = []

    for hashed_file in hashed_files_list:
        threat_miner_raw_results = get_file_report_from_threat_miner(hashed_file, kwargs.get('threat_miner_url'),
                                                                     kwargs.get('verify_certificates'))

        max_returned_array_size = kwargs.get('max_array_size')
        threat_miner_context = {
            'MD5': threat_miner_raw_results['raw_whois'].get('md5', ''),
            'Architecture': threat_miner_raw_results['raw_whois'].get('architecture', ''),
            'SHA1': threat_miner_raw_results['raw_whois'].get('sha1', ''),
            'SHA256': threat_miner_raw_results['raw_whois'].get('sha256', ''),
            'Type': threat_miner_raw_results['raw_whois'].get('file_type', ''),
            'Name': threat_miner_raw_results['raw_whois'].get('file_name', ''),
            'Size': threat_miner_raw_results['raw_whois'].get('file_size', ''),
            'Analyzed': threat_miner_raw_results['raw_whois'].get('date_analysed', ''),
            'HTTP': get_file_http(threat_miner_raw_results, max_returned_array_size),
            'Domains': get_file_domains_and_ip(threat_miner_raw_results, max_returned_array_size),
            'Mutants': get_file_mutants(threat_miner_raw_results, max_returned_array_size),
            'Registry': get_file_registry_keys(threat_miner_raw_results, max_returned_array_size),
            'AV': get_file_AV_detection(threat_miner_raw_results)
        }
        markdown = create_file_command_markdown(hashed_file, threat_miner_context)

        file_context = {
            'MD5': threat_miner_raw_results['raw_whois'].get('md5', ''),
            'Architecture': threat_miner_raw_results['raw_whois'].get('architecture', ''),
            'SHA1': threat_miner_raw_results['raw_whois'].get('sha1', ''),
            'SHA256': threat_miner_raw_results['raw_whois'].get('sha256', ''),
            'Type': threat_miner_raw_results['raw_whois'].get('file_type', ''),
            'Name': threat_miner_raw_results['raw_whois'].get('file_name', ''),
            'Size': threat_miner_raw_results['raw_whois'].get('file_size', ''),
            'Analyzed': threat_miner_raw_results['raw_whois'].get('date_analysed', '')
        }
        dbot_scores = get_dbot_scores_context(threat_miner_context, file_context, hashed_file, kwargs.get('reliability'))

        context = {
            'ThreatMiner.File(val.MD5 && val.MD5 == obj.MD5)': threat_miner_context,
            'File(val.MD5 && val.MD5 == obj.MD5)': file_context,
            'DBotScore': dbot_scores
        }

        result = {'Type': entryTypes['note'],
                  'Contents': threat_miner_raw_results,
                  'HumanReadable': markdown,
                  'EntryContext': context,
                  'ContentsFormat': formats['json']}
        hashed_files_results.append(result)

    demisto.results(hashed_files_results)


def get_dbot_score_report(amount_of_detections, hashed_file, file_context, reliability):
    dbot = {}
    dbot_score = get_dbot_score(amount_of_detections)
    dbot['Score'] = dbot_score
    dbot['Indicator'] = hashed_file
    dbot['Type'] = 'File'
    dbot['Vendor'] = 'ThreatMiner'
    dbot['Reliability'] = reliability

    if dbot_score == 3:
        file_context['Malicious'] = {}
        file_context['Malicious']['Vendor'] = 'ThreatMiner'
        file_context['Malicious']['Detections'] = amount_of_detections
    return dbot


def get_dbot_score(amount_of_detections):
    malicious_threshold = int(demisto.args().get('threshold'))
    if amount_of_detections == 0:
        return 0
    if amount_of_detections > 0 and amount_of_detections < malicious_threshold:
        return 2
    if amount_of_detections >= malicious_threshold:
        return 3


def create_file_command_markdown(hashed_file, File_context):
    md = f'## Threat_miner file report for hashed file: {hashed_file}\n'
    threat_miner_found_results = False

    md += '\n'
    md += f'**File MD5:** {hashed_file}'
    md += '\n'
    md += '**File Architecture:** {}'.format(File_context.get('Architecture', 'Unkown'))
    md += '\n'
    md += '**File SHA1:** {}'.format(File_context.get('Sha1', 'Unknown'))
    md += '\n'
    md += '**File SHA256:** {}'.format(File_context.get('Sha256', 'Unkown'))
    md += '\n'
    md += '**File Type:** {}'.format(File_context.get('Type', 'Unkown'))
    md += '\n'
    md += '**File Name:** {}'.format(File_context.get('Name', 'Unkown'))
    md += '\n'
    md += '**File Size:** {}'.format(File_context.get('Size', 'Unkown'))
    md += '\n'
    md += '**File Analyzed:** {}'.format(File_context.get('Analyzed', 'Unkown'))

    if len(File_context.get('HTTP', '')) != 0:
        md += tableToMarkdown(f"HTTP for hashed file {hashed_file}",
                              File_context['HTTP'], ['Domain', 'URL', 'Useragent'])
        threat_miner_found_results = True
    if len(File_context.get('Domains', '')) != 0:
        md += tableToMarkdown(f"Hashed file: {hashed_file} Domains",
                              File_context['Domains'], ['Domain', 'IP'])
        threat_miner_found_results = True
    if len(File_context.get('Mutants', '')) != 0:
        md += tableToMarkdown(f"Hashed file: {hashed_file} Mutants",
                              File_context['Mutants'], ['Mutants'])
        threat_miner_found_results = True
    if len(File_context.get('Registry', '')) != 0:
        md += tableToMarkdown(f"Hashed file: {hashed_file} Registry keys",
                              File_context['Registry'], ['Registry'])
        threat_miner_found_results = True
    if len(File_context.get('AV', '')) != 0:
        md += tableToMarkdown(f"Hashed file: {hashed_file} Anti Virus detections",
                              File_context['AV'], ['Name', 'Detection'])
        threat_miner_found_results = True

    if not threat_miner_found_results:
        md += 'No results found'

    return md


def delete_proxy_if_asked():
    if not demisto.params()['proxy']:
        del os.environ['HTTP_PROXY']
        del os.environ['HTTPS_PROXY']
        del os.environ['http_proxy']
        del os.environ['https_proxy']

    ''' EXECUTION CODE '''


def main():
    try:

        demisto_params = demisto.params()

        params = {
            'threat_miner_url': demisto_params.get('threatminer_url'),
            'verify_certificates': False if demisto_params.get('insecure') else True,
        }

        reliability = demisto_params.get('integrationReliability')
        reliability = reliability if reliability else DBotScoreReliability.C

        if DBotScoreReliability.is_valid_type(reliability):
            params['reliability'] = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability)
        else:
            Exception("Please provide a valid value for the Source Reliability parameter.")

        delete_proxy_if_asked()
        demisto_command = demisto.command()
        if demisto_command == 'test-module':
            report = get_ip_whois_rawdata('8.8.8.8', params['threat_miner_url'], params['verify_certificates'])

            if 'asn' in report:
                demisto.results('ok')
            else:
                demisto.results('test failed')

        if demisto_params.get('limit_results').lower() == 'all':
            params['max_array_size'] = -1
        else:
            params['max_array_size'] = int(demisto_params.get('limit_results', 30))

        if demisto_command == 'domain':
            domain_command(**params)

        if demisto_command == 'ip':
            ip_command(**params)

        if demisto_command == 'file':
            file_command(**params)

    except Exception as e:
        return_error(f'An error has occurred: {e}')


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
