''' IMPORTS '''

import requests
from base64 import b64decode

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
API_ENDPOINT = 'https://endpoint.apivoid.com'


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """
    def __init__(self, apikey, base_url, verify, auth, proxy):
        self.apikey = apikey
        super().__init__(base_url, verify=verify, auth=auth, proxy=proxy)

    def set_boundaries(self, good, suspicious, bad, malicious):
        self.good = good
        self.suspicious = suspicious
        self.bad = bad
        self.malicious = malicious

    def test(self):

        # Use iprep & STATS as test parameter
        suffix = '/iprep/v1/pay-as-you-go/'
        api_params = {'key': self.apikey, 'stats': ''}
        response = super()._http_request(method='GET', url_suffix=suffix, params=api_params)
        return (response)

    def check_ip(self, ip):

        suffix = '/iprep/v1/pay-as-you-go/'
        api_params = {'key': self.apikey, 'ip': ip}
        response = super()._http_request(method='GET', url_suffix=suffix, params=api_params)
        return (response)

    def check_domain(self, domain):

        suffix = '/domainbl/v1/pay-as-you-go/'
        api_params = {'key': self.apikey, 'host': domain}
        response = super()._http_request(method='GET', url_suffix=suffix, params=api_params)
        return (response)

    def check_url(self, url):

        suffix = '/urlrep/v1/pay-as-you-go/'
        api_params = {'key': self.apikey, 'url': url}
        response = super()._http_request(method='GET', url_suffix=suffix, params=api_params)
        return (response)

    def check_dns(self, host, dnsType):

        suffix = '/dnslookup/v1/pay-as-you-go/'
        api_params = {'key': self.apikey, 'host': host, 'action': f'dns-{dnsType.lower()}'}
        response = super()._http_request(method='GET', url_suffix=suffix, params=api_params)
        return (response)

    def check_ssl(self, host):

        suffix = '/sslinfo/v1/pay-as-you-go/'
        api_params = {'key': self.apikey, 'host': host}
        response = super()._http_request(method='GET', url_suffix=suffix, params=api_params)
        return (response)

    def check_email_address(self, email):

        suffix = '/emailverify/v1/pay-as-you-go/'
        api_params = {'key': self.apikey, 'email': email}
        response = super()._http_request(method='GET', url_suffix=suffix, params=api_params)
        return (response)

    def check_threatlog(self, host):

        suffix = '/threatlog/v1/pay-as-you-go/'
        api_params = {'key': self.apikey, 'host': host}
        response = super()._http_request(method='GET', url_suffix=suffix, params=api_params)
        return (response)

    def check_parked_domain(self, domain):

        suffix = '/parkeddomain/v1/pay-as-you-go/'
        api_params = {'key': self.apikey, 'host': domain}
        response = super()._http_request(method='GET', url_suffix=suffix, params=api_params)
        return (response)

    def check_domain_age(self, domain):

        suffix = '/domainage/v1/pay-as-you-go/'
        api_params = {'key': self.apikey, 'host': domain}
        response = super()._http_request(method='GET', url_suffix=suffix, params=api_params)
        return (response)

    def screenshot(self, url):

        suffix = '/screenshot/v1/pay-as-you-go/'
        api_params = {'key': self.apikey, 'url': url}
        response = super()._http_request(method='GET', url_suffix=suffix, params=api_params)
        return (response)

    def url_to_pdf(self, url):

        suffix = '/urltopdf/v1/pay-as-you-go/'
        api_params = {'key': self.apikey, 'url': url}
        response = super()._http_request(method='GET', url_suffix=suffix, params=api_params)
        return (response)

    def url_to_html(self, url):

        suffix = '/urltohtml/v1/pay-as-you-go/'
        api_params = {'key': self.apikey, 'url': url}
        response = super()._http_request(method='GET', url_suffix=suffix, params=api_params)
        return (response)

    def site_trust(self, host):

        suffix = '/sitetrust/v1/pay-as-you-go/'
        api_params = {'key': self.apikey, 'host': host}
        response = super()._http_request(method='GET', url_suffix=suffix, params=api_params)
        return (response)


def test_module(client):

    result = client.test()

    if (result['success']):
        return 'ok'
    else:
        return ('Test Failed: ' + str(result))


def ip_command(client, args, reputation_only):

    ip = args.get('ip')
    raw_response = client.check_ip(ip)

    if 'error' in raw_response:
        return_error("Command Failed: " + str(raw_response['error']))

    report = raw_response.get('data', {}).get('report', None)
    if report:
        apivoid = dict()
        for k, v in report.items():
            apivoid[k] = v
        engines = apivoid.get('blacklists', {}).get('engines_count', 0)
        detections = apivoid.get('blacklists', {}).get('detections', 0)

        # IP Information
        information = apivoid.get('information', {})
        ip = dict()
        ip['Address'] = apivoid['ip']
        ip['Hostname'] = information.get('reverse_dns', None)
        geo = dict()
        lat = information.get('latitude', None)
        lng = information.get('longitude', None)
        geo['Location'] = f'{lat}:{lng}' if lat and lng else None
        geo['Country'] = information.get('country_name', None)
        geo['Description'] = information.get('isp', None)
        ip['Geo'] = geo
        ip['DetectionEngines'] = engines
        ip['PositiveDetections'] = detections

        # DBot Information
        if detections and engines:
            detectionRate = (detections / engines) * 100
        else:
            detectionRate = 0
        dbotScore = 0
        if detectionRate < client.good:
            dbotScore = 1
        if engines == 0:
            dbotScore = 0
        if detectionRate > client.suspicious:
            dbotScore = 2
        if detectionRate > client.bad:
            dbotScore = 3
        if (client.malicious == "suspicious" and dbotScore >= 2) or (client.malicious == "bad" and dbotScore == 3):
            ip['Malicious'] = dict()
            ip['Malicious']['Vendor'] = 'apivoid'
            ip['Malicious']['Description'] = f"Detection rate of {ip['PositiveDetections']}/{ip['DetectionEngines']}"

        ec = {
            'IP(val.ip && val.ip == obj.ip)': ip,
            'DBotScore': {
                'Score': dbotScore,
                'Vendor': 'URL Void',
                'Indicator': ip['Address'],
                'Type': 'ip'
            }
        }

        md = tableToMarkdown(f'apivoid information for {ip["Address"]}:', ip)

        if not reputation_only:
            ec['apivoid.IP(val.ip && val.ip == obj.ip)'] = apivoid

    else:
        ec = {}
        md = f'## No information for {ip}'

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': ec,
        'HumanReadable': md,
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': ec
    })


def domain_command(client, args, reputation_only):

    domain = args.get('domain')
    raw_response = client.check_domain(domain)

    if 'error' in raw_response:
        return_error("Command Failed: " + str(raw_response['error']))

    report = raw_response.get('data', {}).get('report', None)
    if report:
        apivoid = dict()
        for k, v in report.items():
            apivoid[k] = v

        engines = apivoid.get('blacklists', {}).get('engines_count', 0)
        detections = apivoid.get('blacklists', {}).get('detections', 0)

        # Domain Information
        domain = dict()
        domain['Name'] = apivoid['host']
        domain['DNS'] = apivoid['host']
        domain['DetectionEngines'] = engines
        domain['PositiveDetections'] = detections

        # DBot Information
        if detections and engines:
            detectionRate = (detections / engines) * 100
        else:
            detectionRate = 0
        dbotScore = 0
        if detectionRate < client.good:
            dbotScore = 1
        if engines == 0:
            dbotScore = 0
        if detectionRate > client.suspicious:
            dbotScore = 2
        if detectionRate > client.bad:
            dbotScore = 3
        if (client.malicious == "suspicious" and dbotScore >= 2) or (client.malicious == "bad" and dbotScore == 3):
            domain['Malicious'] = dict()
            domain['Malicious']['Vendor'] = 'apivoid'
            domain['Malicious']['Description'] = f"Detection rate of {domain['PositiveDetections']}/{domain['DetectionEngines']}"

        ec = {
            'Domain(val.Name && val.Name == obj.Name)': domain,
            'DBotScore': {
                'Score': dbotScore,
                'Vendor': 'URL Void',
                'Indicator': domain['Name'],
                'Type': 'domain'
            }
        }
        md = tableToMarkdown(f'apivoid information for {domain["Name"]}:', domain)

        if not reputation_only:
            ec['apivoid.Domain(val.domain && val.domain == obj.domain)'] = apivoid

    else:
        ec = {}
        md = f'## No information for {domain}'

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': ec,
        'HumanReadable': md,
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': ec
    })


def url_command(client, args, reputation_only):

    url = args.get('url')
    raw_response = client.check_url(url)

    if 'error' in raw_response:
        return_error("Command Failed: " + str(raw_response['error']))

    report = raw_response.get('data', {}).get('report', None)
    if report:
        apivoid = dict()
        for k, v in report.items():
            apivoid[k] = v
        apivoid['url'] = url

        engines = len(apivoid.get('domain_blacklist', {}).get('engines', 0))
        detections = apivoid.get('domain_blacklist', {}).get('detections', 0)

        # URL Information
        url = dict()
        url['Data'] = apivoid['url']
        url['DetectionEngines'] = engines
        url['PositiveDetections'] = detections

        # DBot Information
        if detections and engines:
            detectionRate = (detections / engines) * 100
        else:
            detectionRate = 0
        dbotScore = 0
        if detectionRate < client.good:
            dbotScore = 1
        if engines == 0:
            dbotScore = 0
        if detectionRate > client.suspicious:
            dbotScore = 2
        if detectionRate > client.bad:
            dbotScore = 3
        if (client.malicious == "suspicious" and dbotScore >= 2) or (client.malicious == "bad" and dbotScore == 3):
            url['Malicious'] = dict()
            url['Malicious']['Vendor'] = 'apivoid'
            url['Malicious']['Description'] = f"Detection rate of {url['PositiveDetections']}/{url['DetectionEngines']}"

        ec = {
            'URL(val.ip && val.ip == obj.ip)': url,
            'DBotScore': {
                'Score': dbotScore,
                'Vendor': 'URL Void',
                'Indicator': url['Data'],
                'Type': 'url'
            }
        }
        md = tableToMarkdown(f'apivoid information for {url["Data"]}:', url)

        if not reputation_only:
            ec['apivoid.URL(val.url && val.url == obj.url)'] = apivoid

    else:
        ec = {}
        md = f'## No information for {url}'

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': ec,
        'HumanReadable': md,
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': ec
    })


def dns_lookup_command(client, args):

    host = args.get('host')
    dns_type = args.get('type')
    raw_response = client.check_dns(host, dns_type)

    if 'error' in raw_response:
        return_error("Command Failed: " + str(raw_response['error']))

    records = raw_response.get('data', {}).get('records', None)
    entries = list()
    if records:
        apivoid = dict()
        for k, v in records.items():
            apivoid[k] = v
        apivoid['host'] = host
        apivoid['type'] = dns_type

        mdData = dict()
        mdData['Host'] = host
        mdData['Type'] = dns_type
        for k, v in records.items():
            if k not in ['items']:
                mdData[k] = v

        ec = {
            'apivoid.DNS(val.host && val.type && val.host == obj.host && val.type == obj.type)': apivoid
        }
        md = tableToMarkdown(f'apivoid DNS-{dns_type} information for {host}:', mdData)
        entries.append({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': ec,
            'HumanReadable': md,
            'ReadableContentsFormat': formats['markdown'],
            'EntryContext': ec
        })

        for item in apivoid.get('items', []):
            thisType = item.get('type', dns_type)
            md = tableToMarkdown(f'Information of {thisType} record from {host}:', item)
            entries.append({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': item,
                'HumanReadable': md,
                'ReadableContentsFormat': formats['markdown']
            })

    else:
        ec = {}
        md = f'## No information for {host}'

    demisto.results(entries)


def ssl_lookup_command(client, args):

    host = args.get('host')
    raw_response = client.check_ssl(host)

    if 'error' in raw_response:
        return_error("Command Failed: " + str(raw_response['error']))

    certificate = raw_response.get('data', {}).get('certificate', None)
    if certificate:
        apivoid = dict()
        for k, v in certificate.items():
            apivoid[k] = v
        apivoid['host'] = host

        mdData = dict()
        for k, v in certificate.items():
            if k not in ['details']:
                mdData[k] = v

        ec = {
            'apivoid.SSL(val.host && val.host == obj.host)': apivoid
        }
        md = tableToMarkdown(f'apivoid SSL Information for {host}:', mdData)

    else:
        ec = {}
        md = f'## No information for {host}'

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': ec,
        'HumanReadable': md,
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': ec
    })


def email_address_command(client, args):

    email = args.get('email')
    raw_response = client.check_email_address(email)

    if 'error' in raw_response:
        return_error("Command Failed: " + str(raw_response['error']))

    data = raw_response.get('data', {})
    if data:
        apivoid = dict()
        for k, v in data.items():
            apivoid[k] = v
        ec = {
            'apivoid.Email(val.email && val.email == obj.email)': apivoid
        }
        md = tableToMarkdown(f'apivoid Email Information for {email}:', apivoid)

    else:
        ec = {}
        md = f'## No information for {domain}'

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': ec,
        'HumanReadable': md,
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': ec
    })


def threatlog_command(client, args):

    host = args.get('host')
    raw_response = client.check_threatlog(host)

    if 'error' in raw_response:
        return_error("Command Failed: " + str(raw_response['error']))

    data = raw_response.get('data', {}).get('threatlog', None)
    if data:
        apivoid = dict()

        for k, v in data.items():
            apivoid[k] = v
        ec = {
            'apivoid.ThreatLog(val.host && val.host == obj.host)': apivoid,
            'Domain': {
                'Name': host,
            }
        }
        md = tableToMarkdown(f'apivoid ThreatLog Information for {host}:', apivoid)

    else:
        ec = {}
        md = f'## No information for {host}'

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': ec,
        'HumanReadable': md,
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': ec
    })


def check_parked_domain_command(client, args):

    domain = args.get('domain')
    raw_response = client.check_parked_domain(domain)

    if 'error' in raw_response:
        return_error("Command Failed: " + str(raw_response['error']))

    data = raw_response.get('data', {})
    if data:
        apivoid = dict()

        for k, v in data.items():
            apivoid[k] = v
        ec = {
            'apivoid.ParkedDomain(val.host && val.host == obj.host)': apivoid,
            'Domain': {
                'Name': domain
            }
        }
        md = tableToMarkdown(f'apivoid Parked Domain Information for {domain}:', apivoid)

    else:
        ec = {}
        md = f'## No information for {domain}'

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': ec,
        'HumanReadable': md,
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': ec
    })


def domain_age_command(client, args):

    domain = args.get('domain')
    raw_response = client.check_domain_age(domain)

    if 'error' in raw_response:
        return_error("Command Failed: " + str(raw_response['error']))

    data = raw_response.get('data', {})
    if data:
        apivoid = dict()

        for k, v in data.items():
            apivoid[k] = v
        ec = {
            'apivoid.DomainAge(val.host && val.host == obj.host)': apivoid,
            'Domain': {
                'Name': domain,
                'CreationDate': apivoid.get('domain_creation_date', None),
            }
        }
        md = tableToMarkdown(f'apivoid Domain Age Information for {domain}:', apivoid)

    else:
        ec = {}
        md = f'## No information for {domain}'

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': ec,
        'HumanReadable': md,
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': ec
    })


def screenshot_command(client, args):

    url = args.get('url')
    raw_response = client.screenshot(url)

    if 'error' in raw_response:
        return_error("Command Failed: " + str(raw_response['error']))

    data = raw_response.get('data', {})
    if data:

        # Create new file here
        fileName = url.replace("https", "").replace("http", "").replace("://", "").replace(".", "_")
        fileName += "_capture.png"
        demisto.results(fileResult(fileName, b64decode(data.get('base64_file', None))))


def url_to_pdf_command(client, args):

    url = args.get('url')
    raw_response = client.url_to_pdf(url)

    if 'error' in raw_response:
        return_error("Command Failed: " + str(raw_response['error']))

    data = raw_response.get('data', {})
    if data:

        # Create new file here
        fileName = url.replace("https", "").replace("http", "").replace("://", "").replace(".", "_")
        fileName += "_capture.pdf"
        demisto.results(fileResult(fileName, b64decode(data.get('base64_file', None))))


def url_to_html_command(client, args):

    url = args.get('url')
    raw_response = client.url_to_html(url)

    if 'error' in raw_response:
        return_error("Command Failed: " + str(raw_response['error']))

    data = raw_response.get('data', {})
    if data:

        # Create new file here
        fileName = url.replace("https", "").replace("http", "").replace("://", "").replace(".", "_")
        fileName += "_capture.html"
        demisto.results(fileResult(fileName, b64decode(data.get('base64_file', None))))


def site_trust_command(client, args):

    host = args.get('host')
    raw_response = client.site_trust(host)

    if 'error' in raw_response:
        return_error("Command Failed: " + str(raw_response['error']))

    data = raw_response.get('data', {}).get('report', None)
    if data:

        apivoid = dict()
        for k, v in data.items():
            apivoid[k] = v
        apivoid['host'] = host
        ec = {
            'apivoid.SiteTrust(val.host && val.host == obj.host)': apivoid,
        }
        md = tableToMarkdown(f'apivoid Site Trustworthiness for {host}:', apivoid)

        # Populate Domain information if available
        if apivoid.get('domain_age', {}).get('found', False):
            ec['Domain'] = {
                'Name': host,
                'CreationDate': apivoid.get('domain_age', {}).get('domain_creation_date', None),
            }
        if "ns" in apivoid.get('dns_records', {}):
            nameServers = ",".join([
                x.get('target', None) for x in apivoid.get('dns_records', {}).get('ns', {}).get('records', [])
            ])
            ec['Domain']['NameServers'] = nameServers

    else:
        ec = {}
        md = f'## No information for {host}'

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': ec,
        'HumanReadable': md,
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': ec
    })


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """

    params = demisto.params()
    # get the service API url (This is static for this service)
    base_url = API_ENDPOINT

    apikey = params.get('apikey', None)

    verify_certificate = not params.get('insecure', False)

    proxy = params.get('proxy', False)
    good = int(params.get('good', 10))
    suspicious = int(params.get('suspicious', 30))
    bad = int(params.get('bad', 60))
    malicious = params.get('malicious', 'suspicious')
    command = demisto.command()

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            apikey,
            base_url,
            verify_certificate,
            None,
            proxy)

        client.set_boundaries(good, suspicious, bad, malicious)
        args = demisto.args()
        command = demisto.command()

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
