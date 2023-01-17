import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


''' IMPORTS '''
import copy
import urllib3
from base64 import b64decode

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
API_ENDPOINT = 'https://endpoint.apivoid.com'
GOOD = 10
SUSPICIOUS = 30
BAD = 60
MALICIOUS = 'suspicious'


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """
    def __init__(self, base_url, apikey, verify, proxy):
        self.apikey = apikey
        super().__init__(base_url, verify=verify, proxy=proxy)

    def test(self):

        # Use iprep & STATS as test parameter
        suffix = '/iprep/v1/pay-as-you-go/'
        api_params = {'key': self.apikey, 'stats': ''}
        response = self._http_request(method='GET', url_suffix=suffix, params=api_params)
        return response

    def check_ip(self, ip):

        suffix = '/iprep/v1/pay-as-you-go/'
        api_params = {'key': self.apikey, 'ip': ip}
        response = self._http_request(method='GET', url_suffix=suffix, params=api_params)
        return response

    def check_domain(self, domain):

        suffix = '/domainbl/v1/pay-as-you-go/'
        api_params = {'key': self.apikey, 'host': domain}
        response = self._http_request(method='GET', url_suffix=suffix, params=api_params)
        return response

    def check_url(self, url):

        suffix = '/urlrep/v1/pay-as-you-go/'
        api_params = {'key': self.apikey, 'url': url}
        response = self._http_request(method='GET', url_suffix=suffix, params=api_params)
        return response

    def check_dns(self, host, dns_type):

        suffix = '/dnslookup/v1/pay-as-you-go/'
        api_params = {'key': self.apikey, 'host': host, 'action': f'dns-{dns_type.lower()}'}
        response = self._http_request(method='GET', url_suffix=suffix, params=api_params)
        return response

    def check_ssl(self, host):

        suffix = '/sslinfo/v1/pay-as-you-go/'
        api_params = {'key': self.apikey, 'host': host}
        response = self._http_request(method='GET', url_suffix=suffix, params=api_params)
        return response

    def check_email_address(self, email):

        suffix = '/emailverify/v1/pay-as-you-go/'
        api_params = {'key': self.apikey, 'email': email}
        response = self._http_request(method='GET', url_suffix=suffix, params=api_params)
        return response

    def check_threatlog(self, host):

        suffix = '/threatlog/v1/pay-as-you-go/'
        api_params = {'key': self.apikey, 'host': host}
        response = self._http_request(method='GET', url_suffix=suffix, params=api_params)
        return response

    def check_parked_domain(self, domain):

        suffix = '/parkeddomain/v1/pay-as-you-go/'
        api_params = {'key': self.apikey, 'host': domain}
        response = self._http_request(method='GET', url_suffix=suffix, params=api_params)
        return response

    def check_domain_age(self, domain):

        suffix = '/domainage/v1/pay-as-you-go/'
        api_params = {'key': self.apikey, 'host': domain}
        response = self._http_request(method='GET', url_suffix=suffix, params=api_params)
        return response

    def screenshot(self, url):

        suffix = '/screenshot/v1/pay-as-you-go/'
        api_params = {'key': self.apikey, 'url': url}
        response = self._http_request(method='GET', url_suffix=suffix, params=api_params)
        return response

    def url_to_pdf(self, url):

        suffix = '/urltopdf/v1/pay-as-you-go/'
        api_params = {'key': self.apikey, 'url': url}
        response = self._http_request(method='GET', url_suffix=suffix, params=api_params)
        return response

    def url_to_html(self, url):

        suffix = '/urltohtml/v1/pay-as-you-go/'
        api_params = {'key': self.apikey, 'url': url}
        response = self._http_request(method='GET', url_suffix=suffix, params=api_params)
        return response

    def site_trust(self, host):

        suffix = '/sitetrust/v1/pay-as-you-go/'
        api_params = {'key': self.apikey, 'host': host}
        response = self._http_request(method='GET', url_suffix=suffix, params=api_params)
        return response


def indicator_context(client, indicator, indicator_context_path, indicator_value_field, engines, detections):
    # DBot Information
    dbot_score = 0
    if engines != 0:
        detection_rate = (detections / engines) * 100

        if detection_rate < GOOD:
            dbot_score = 1
        if detection_rate > SUSPICIOUS:
            dbot_score = 2
        if detection_rate > BAD:
            dbot_score = 3

    if (MALICIOUS == "suspicious" and dbot_score >= 2) or (MALICIOUS == "bad" and dbot_score == 3):
        indicator['Malicious'] = {
            'Vendor': 'APIVoid',
            'Description': f"Detection rate of {indicator['PositiveDetections']}/{indicator['DetectionEngines']}"
        }

    return {
        indicator_context_path: indicator,
        'DBotScore': {
            'Score': dbot_score,
            'Vendor': 'APIVoid',
            'Indicator': indicator[indicator_value_field],
            'Type': 'ip',
            'Reliability': demisto.params().get('integrationReliability')
        }
    }


def test_module(client):

    result = client.test()

    if result.get('success'):
        return 'ok'
    else:
        return 'Test Failed: ' + str(result)


def ip_command(client, args, reputation_only):

    ip = args.get('ip')
    raw_response = client.check_ip(ip)

    if 'error' in raw_response:
        return_error("Command Failed: " + str(raw_response['error']))

    report = raw_response.get('data', {}).get('report', None)
    if report:
        engines = report.get('blacklists', {}).get('engines_count', 0)
        detections = report.get('blacklists', {}).get('detections', 0)

        # IP Information
        information = report.get('information', {})
        lat = information.get('latitude', None)
        lng = information.get('longitude', None)
        ip = {
            'Address': report['ip'],
            'Hostname': information.get('reverse_dns', None),
            'Geo': {
                'Location': f'{lat}:{lng}' if lat and lng else None,
                'Country': information.get('country_name', None),
                'Description': information.get('isp', None),
            },
            'DetectionEngines': engines,
            'PositiveDetections': detections,
        }
        ec = indicator_context(client, ip, outputPaths['ip'], 'Address', engines, detections)

        if not reputation_only:
            ec['APIVoid.IP(val.ip && val.ip == obj.ip)'] = report

        md = tableToMarkdown(f'APIVoid information for {ip["Address"]}:', ip)

    else:
        ec = {}
        md = f'## No information for {ip}'

    return_outputs(md, ec, raw_response)


def domain_command(client, args, reputation_only):

    domain = args.get('domain')
    raw_response = client.check_domain(domain)

    if 'error' in raw_response:
        return_error("Command Failed: " + str(raw_response['error']))

    report = raw_response.get('data', {}).get('report', None)
    if report:
        engines = report.get('blacklists', {}).get('engines_count', 0)
        detections = report.get('blacklists', {}).get('detections', 0)

        # Domain Information
        domain = {
            'Name': report['host'],
            'DNS': report['host'],
            'DetectionEngines': engines,
            'PositiveDetections': detections,
        }

        ec = indicator_context(client, domain, outputPaths['domain'], 'Name', engines, detections)
        md = tableToMarkdown(f'APIVoid information for {domain["Name"]}:', domain)

        if not reputation_only:
            ec['APIVoid.Domain(val.domain && val.domain == obj.domain)'] = report

    else:
        ec = {}
        md = f'## No information for {domain}'

    return_outputs(md, ec, raw_response)


def url_command(client, args, reputation_only):

    url = args.get('url')
    raw_response = client.check_url(url)

    if 'error' in raw_response:
        return_error("Command Failed: " + str(raw_response['error']))

    report = raw_response.get('data', {}).get('report', None)
    if report:
        report['url'] = url

        engines = len(report.get('domain_blacklist', {}).get('engines', []))
        detections = report.get('domain_blacklist', {}).get('detections', 0)

        # URL Information
        url = {
            'Data': report['url'],
            'DetectionEngines': engines,
            'PositiveDetections': detections,
        }

        ec = indicator_context(client, url, outputPaths['url'], 'Data', engines, detections)
        md = tableToMarkdown(f'APIVoid information for {url["Data"]}:', url)

        if not reputation_only:
            ec['APIVoid.URL(val.url && val.url == obj.url)'] = report

    else:
        ec = {}
        md = f'## No information for {url}'

    return_outputs(md, ec, raw_response)


def dns_lookup_command(client, args):

    host = args.get('host')
    dns_type = args.get('type')
    raw_response = client.check_dns(host, dns_type)

    if 'error' in raw_response:
        return_error("Command Failed: " + str(raw_response['error']))

    records = raw_response.get('data', {}).get('records', None)
    entries = list()
    if records:
        md_data = copy.deepcopy(records)
        md_data['Host'] = host
        md_data['Type'] = dns_type

        records['host'] = host
        records['type'] = dns_type

        ec = {
            'APIVoid.DNS(val.host && val.type && val.host == obj.host && val.type == obj.type)': records,
        }
        md = tableToMarkdown(f'APIVoid DNS-{dns_type} information for {host}:', md_data)
        entries.append({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': ec,
            'HumanReadable': md,
            'ReadableContentsFormat': formats['markdown'],
            'EntryContext': ec
        })

        for item in records.get('items', []):
            item_type = item.get('type', dns_type)
            md = tableToMarkdown(f'Information of {item_type} record from {host}:', item)
            entries.append({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': item,
                'HumanReadable': md,
                'ReadableContentsFormat': formats['markdown']
            })

        demisto.results(entries)
    else:
        demisto.results(f'## No information for {host}')


def ssl_lookup_command(client, args):

    host = args.get('host')
    raw_response = client.check_ssl(host)

    if 'error' in raw_response:
        raise Exception(f"Command Failed: {raw_response['error']}")

    certificate = raw_response.get('data', {}).get('certificate', None)
    if certificate:
        md_data = copy.deepcopy(certificate)
        if 'details' in md_data:
            del md_data['details']

        certificate['host'] = host
        ec = {
            'APIVoid.SSL(val.host && val.host == obj.host)': certificate,
        }
        md = tableToMarkdown(f'APIVoid SSL Information for {host}:', md_data)

    else:
        ec = {}
        md = f'## No information for {host}'

    return_outputs(md, ec, raw_response)


def email_address_command(client, args):

    email = args.get('email')
    raw_response = client.check_email_address(email)

    if 'error' in raw_response:
        return_error("Command Failed: " + str(raw_response['error']))

    data = raw_response.get('data', {})
    if data:
        ec = {
            'APIVoid.Email(val.email && val.email == obj.email)': data
        }
        md = tableToMarkdown(f'APIVoid Email Information for {email}:', data)

    else:
        ec = {}
        md = f'## No information for {email}'

    return_outputs(md, ec, raw_response)


def threatlog_command(client, args):

    host = args.get('host')
    raw_response = client.check_threatlog(host)

    if 'error' in raw_response:
        return_error("Command Failed: " + str(raw_response['error']))

    data = raw_response.get('data', {}).get('threatlog', None)
    if data:
        ec = {
            'APIVoid.ThreatLog(val.host && val.host == obj.host)': data,
            'Domain': {
                'Name': host,
            }
        }
        md = tableToMarkdown(f'APIVoid ThreatLog Information for {host}:', data)

    else:
        ec = {}
        md = f'## No information for {host}'

    return_outputs(md, ec, raw_response)


def check_parked_domain_command(client, args):

    domain = args.get('domain')
    raw_response = client.check_parked_domain(domain)

    if 'error' in raw_response:
        return_error("Command Failed: " + str(raw_response['error']))

    data = raw_response.get('data', {})
    if data:
        ec = {
            'APIVoid.ParkedDomain(val.host && val.host == obj.host)': data,
            'Domain': {
                'Name': domain
            }
        }
        md = tableToMarkdown(f'APIVoid Parked Domain Information for {domain}:', data)

    else:
        ec = {}
        md = f'## No information for {domain}'

    return_outputs(md, ec, raw_response)


def domain_age_command(client, args):

    domain = args.get('domain')
    raw_response = client.check_domain_age(domain)

    if 'error' in raw_response:
        return_error("Command Failed: " + str(raw_response['error']))

    data = raw_response.get('data', {})
    if data:
        ec = {
            'APIVoid.DomainAge(val.host && val.host == obj.host)': data,
            'Domain': {
                'Name': domain,
                'CreationDate': data.get('domain_creation_date', None),
            }
        }
        md = tableToMarkdown(f'APIVoid Domain Age Information for {domain}:', data)

    else:
        ec = {}
        md = f'## No information for {domain}'

    return_outputs(md, ec, raw_response)


def screenshot_command(client, args):

    url = args.get('url')
    raw_response = client.screenshot(url)

    if 'error' in raw_response:
        return_error("Command Failed: " + str(raw_response['error']))

    data = raw_response.get('data', {})
    if data:

        # Create new file here
        file_name = url.replace("https", "").replace("http", "").replace("://", "").replace(".", "_")
        file_name += "_capture.png"
        demisto.results(fileResult(file_name, b64decode(data.get('base64_file', None))))


def url_to_pdf_command(client, args):

    url = args.get('url')
    raw_response = client.url_to_pdf(url)

    if 'error' in raw_response:
        return_error("Command Failed: " + str(raw_response['error']))

    data = raw_response.get('data', {})
    if data:

        # Create new file here
        file_name = url.replace("https", "").replace("http", "").replace("://", "").replace(".", "_")
        file_name += "_capture.pdf"
        demisto.results(fileResult(file_name, b64decode(data.get('base64_file', None))))


def url_to_html_command(client, args):

    url = args.get('url')
    raw_response = client.url_to_html(url)

    if 'error' in raw_response:
        return_error("Command Failed: " + str(raw_response['error']))

    data = raw_response.get('data', {})
    if data:

        # Create new file here
        file_name = url.replace("https", "").replace("http", "").replace("://", "").replace(".", "_")
        file_name += "_capture.html"
        demisto.results(fileResult(file_name, b64decode(data.get('base64_file', None))))


def site_trust_command(client, args):

    host = args.get('host')
    raw_response = client.site_trust(host)

    if 'error' in raw_response:
        return_error("Command Failed: " + str(raw_response['error']))

    data = raw_response.get('data', {}).get('report', None)
    if data:
        data['host'] = host
        ec = {
            'APIVoid.SiteTrust(val.host && val.host == obj.host)': data,
        }
        md = tableToMarkdown(f'APIVoid Site Trustworthiness for {host}:', data)

        # Populate Domain information if available
        if data.get('domain_age', {}).get('found', False):
            ec['Domain'] = {
                'Name': host,
                'CreationDate': data.get('domain_age', {}).get('domain_creation_date', None),
            }
        if "ns" in data.get('dns_records', {}):
            name_servers = ",".join([
                x.get('target', None) for x in data.get('dns_records', {}).get('ns', {}).get('records', [])
            ])
            ec['Domain']['NameServers'] = name_servers

    else:
        ec = {}
        md = f'## No information for {host}'

    return_outputs(md, ec, raw_response)


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    global GOOD, SUSPICIOUS, BAD, MALICIOUS
    params = demisto.params()
    # get the service API url (This is static for this service)
    base_url = API_ENDPOINT

    apikey = params.get('credentials', {}).get('password') or params.get('apikey', None)

    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    GOOD = int(params.get('good', 10))
    SUSPICIOUS = int(params.get('suspicious', 30))
    BAD = int(params.get('bad', 60))
    MALICIOUS = params.get('malicious', 'suspicious')
    command = demisto.command()

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url,
            apikey,
            verify_certificate,
            proxy,
        )

        args = demisto.args()

        commands = {
            'apivoid-dns-lookup': dns_lookup_command,
            'apivoid-ssl-info': ssl_lookup_command,
            'apivoid-email-verify': email_address_command,
            'apivoid-threatlog': threatlog_command,
            'apivoid-parked-domain': check_parked_domain_command,
            'apivoid-domain-age': domain_age_command,
            'apivoid-url-to-image': screenshot_command,
            'apivoid-url-to-pdf': url_to_pdf_command,
            'apivoid-url-to-html': url_to_html_command,
            'apivoid-site-trustworthiness': site_trust_command,
        }

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

        elif command == 'ip':
            ip_command(client, args, True)

        elif command == 'apivoid-ip':
            ip_command(client, args, False)

        elif command == 'domain':
            domain_command(client, args, True)

        elif command == 'apivoid-domain':
            domain_command(client, args, False)

        elif command == 'url':
            url_command(client, args, True)

        elif command == 'apivoid-url':
            url_command(client, args, False)

        else:
            commands[command](client, args)

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
