import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import requests
import os

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

if not demisto.params().get('useProxy', False):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

''' GLOBAL VARS '''
SERVER_URL_V1 = 'https://www.cymon.io:443/api/nexus/v1'
SERVER_DASHBOARD_URL_V1 = 'https://www.cymon.io:443/api/dashboard/v1'
SERVER_URL_V2 = 'https://api.cymon.io/v2/ioc/search'

VERIFY_CERTIFICATES = False if demisto.params().get('unsecure') else True

DEFAULT_HEADERS = {
    "Content-Type": "application/json"
}

''' HELPER FUNCTIONS '''


def cymon_says():
    return_error('Cymon service discontinued. Please disable or delete the integration instance.')


def http_request(method, url, headers):
    try:
        res = requests.request(method,
                               url,
                               verify=VERIFY_CERTIFICATES,
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
        raise (e)


''' DOMAIN COMMAND '''


# def get_domain_full_report(domain):
#     report_results = []
#
#     from_param = 0
#     size_param = 10
#     total = None
#
#     url = '{}/{}/{}?from={}&size={}'.format(SERVER_URL_V2, 'domain', domain, from_param, size_param)
#
#     while total is None or total > from_param:
#         response = http_request('GET', url, DEFAULT_HEADERS)
#
#         hits = response.get('hits', [])
#         for hit in hits:
#             timestamp = datetime.strptime(
#                 hit.get('timestamp', datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")),
#                 '%Y-%m-%dT%H:%M:%S.%fZ')
#
#             report_results.append({
#                 'Title': hit.get('title', "").title(),
#                 'Feed': hit.get('feed'),
#                 'Timestamp': timestamp.strftime("%Y-%m-%d %H:%M:%S"),
#                 # Formatting the timestamp to human readable date and time
#                 'Tags': hit.get('tags'),
#                 'Hostname': hit.get('ioc', {}).get('hostname'),
#                 'IP': hit.get('ioc', {}).get('ip'),
#                 'Domain': hit.get('ioc', {}).get('domain'),
#                 'Reported By': hit.get('reported_by'),
#                 'Location': hit.get('location', {}).get('country')
#             })
#
#         from_param = from_param + size_param
#         total = int(response.get('total', 0))
#
#         url = '{}/{}/{}?from={}&size={}'.format(SERVER_URL_V2, 'domain', domain, from_param, size_param)
#
#     return report_results


# def get_domain_report(domain_full_report):
#     reports = {}  # type:dict
#
#     for report in domain_full_report:
#         title = report.get('Title')
#         timestamp = datetime.strptime(
#             report.get('Timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S")), '%Y-%m-%d %H:%M:%S')
#
#         if (title in reports and reports.get(title).get('Timestamp') < timestamp) or title not in reports:  # type: ignore
#             reports.update({title: {
#                 'Feed': report.get('Feed'),
#                 'Timestamp': timestamp,
#                 'Tags': report.get('Tags'),
#                 'Hostname': report.get('Hostname'),
#                 'IP': report.get('IP'),
#                 'Domain': report.get('Domain'),
#                 'Reported By': report.get('Reported By'),
#                 'Location': report.get('Location')
#             }})
#
#     report_results = []
#
#     for report in reports:
#         report_results.append({
#             'Title': report,
#             'Feed': reports.get(report).get('Feed'),  # type: ignore
#             'Timestamp': reports.get(report).get('Timestamp').strftime("%Y-%m-%d %H:%M:%S"),  # type: ignore
#             # Formatting the timestamp to human readable date and time
#             'Tags': reports.get(report).get('Tags'),  # type: ignore
#             'Hostname': reports.get(report).get('Hostname'),  # type: ignore
#             'IP': reports.get(report).get('IP'),  # type: ignore
#             'Domain': reports.get(report).get('Domain'),  # type: ignore
#             'Reported By': reports.get(report).get('Reported By'),  # type: ignore
#             'Location': reports.get(report).get('Location')  # type: ignore
#         })
#
#     return {
#         'reports': report_results,
#         'total': len(domain_full_report)
#     }


# def create_domain_command_markdown(domain, total_hits, reports, domain_full_report, is_full_response):
#     md = '## Cymon Domain report for: {}\n'.format(domain)
#
#     md += '\n'
#
#     md += '**Total Hits:** {}'.format(total_hits)
#
#     md += '\n'
#
#     md += tableToMarkdown("The following reports are the latest malicious hits resolved to the given domain:", reports,
#                           ['Title', 'Hostname', 'IP', 'Timestamp', 'Feed', 'Tags', 'Location', 'Reported By', 'Domain'])
#
#     if is_full_response:
#         md += tableToMarkdown("Full report list:", domain_full_report,
#                               ['Title', 'Hostname', 'IP', 'Timestamp', 'Feed', 'Tags', 'Location', 'Reported By',
#                                'Domain'])
#
#     return md


# def create_context_domain_command(domain, reports):
#     cymon_domain_context_activities = []
#     description = 'Reported suspicious activities: '
#
#     for report in reports:
#         cymon_domain_context_activities.append({
#             'Title': report.get('Title'),
#             'Tags': report.get('Tags'),
#             'Time': report.get('Timestamp'),
#             'Hostname': report.get('Hostname'),
#             'IP': report.get('IP')
#         })
#
#         description += '{}, '.format(report.get('Title'))
#
#     description = description[:-2]
#
#     context = {
#         outputPaths['domain']: {
#             'Name': domain,
#             'Malicious': {
#                 'Vendor': 'Cymon',
#                 'Description': description
#             }
#         },
#         'Cymon': {
#             'Domain': {
#                 'Activities': cymon_domain_context_activities
#             }
#         }
#     }
#
#     return context


# def get_domain_report_command():
#     args = demisto.args()
#
#     domain = args.get('domain')
#     is_full_response = args.get('fullResponse') == 'true'
#
#     domain_full_report = get_domain_full_report(domain)
#     domain_summarized_report = get_domain_report(domain_full_report)
#
#     if len(domain_full_report) == 0:
#         return "Domain " + domain + " is not in Cymons's dataset"
#
#     markdown = create_domain_command_markdown(domain, domain_summarized_report.get('total'),
#                                               domain_summarized_report.get('reports'), domain_full_report,
#                                               is_full_response)
#     context = create_context_domain_command(domain, domain_summarized_report.get('reports'))
#
#     return {
#         'Type': entryTypes['note'],
#         'Contents': domain_full_report,
#         'ContentsFormat': formats['json'],
#         'HumanReadable': markdown,
#         'EntryContext': context
#     }


''' IP COMMAND '''


# def get_ip_events_sources(ip):
#     url = '{}/{}/{}'.format(SERVER_URL_V1, 'ip', ip)
#     response = http_request('GET', url, DEFAULT_HEADERS)
#
#     return response.get('sources', None)


# def get_ip_events(ip):
#     url = '{}/{}/{}/{}?limit={}'.format(SERVER_URL_V1, 'ip', ip, 'events', 100)
#     events = {}  # type:dict
#
#     next_link = url
#
#     while next_link is not None:
#         response = http_request('GET', next_link, DEFAULT_HEADERS)
#
#         for event in response.get('results', []):
#             tag = event.get('tag')
#             date = datetime.strptime(
#                 event.get('updated', datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")), '%Y-%m-%dT%H:%M:%SZ')
#
#             if (tag in events and events[tag] < date) or tag not in events:
#                 events.update({tag: date})
#
#         next_link = response.get('next')
#
#     for event in events:
#         events[event] = events[event].strftime(
#             "%Y-%m-%d %H:%M:%S")  # Formatting the timestamp to human readable date and time
#
#     return events


# def get_ip_location(ip):
#     url = '{}/{}/{}'.format(SERVER_DASHBOARD_URL_V1, 'geolocation', ip)
#
#     response = http_request('GET', url, DEFAULT_HEADERS)
#
#     lon = response.get('longitude', None)
#     lat = response.get('latitude', None)
#
#     if not lon or not lat:
#         return {}
#     else:
#         return {
#             'lon': lon,
#             'lat': lat
#         }


# def get_ip_domains(ip, max_len):
#     url = '{}/{}/{}/{}?limit={}'.format(SERVER_URL_V1, 'ip', ip, 'domains', max_len)
#     domains = []
#
#     response = http_request('GET', url, DEFAULT_HEADERS)
#
#     for domain in response.get('results', []):
#         date = datetime.strptime(
#             domain.get('updated', datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")), '%Y-%m-%dT%H:%M:%SZ')
#
#         domains.append({'Hostname': domain.get('name'),
#                         'Last Resolved': date.strftime("%Y-%m-%d %H:%M:%S")})
#
#     return domains


# def get_ip_urls(ip, max_len):
#     url = '{}/{}/{}/{}?limit={}'.format(SERVER_URL_V1, 'ip', ip, 'urls', max_len)
#     urls = {}  # type:dict
#
#     response = http_request('GET', url, DEFAULT_HEADERS)
#
#     for response_url in response.get('results', []):
#         url = response_url.get('location')
#         if url.endswith("/"):
#             url = url[:-1]
#
#         date = datetime.strptime(
#             response_url.get('updated', datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")),
#             '%Y-%m-%dT%H:%M:%SZ')
#
#         if (url in urls and urls[url] < date) or url not in urls:
#             urls.update({url: date})
#
#     urls_result = []
#     for url in urls:
#         urls_result.append({'Url': url, "Last Resolved": urls[url].strftime(
#             "%Y-%m-%d %H:%M:%S")})  # Formatting the timestamp to human readable date and time
#
#     return urls_result


# def get_ip_asn(ip):
#     url = '{}/{}/{}'.format(SERVER_DASHBOARD_URL_V1, 'ipwhois', ip)
#
#     response = http_request('GET', url, DEFAULT_HEADERS)
#
#     asn = response.get('asn')
#     asn_country_code = response.get('asn_country_code')
#
#     if not asn or not asn_country_code:
#         return {}
#     else:
#         return {
#             'asn': asn,
#             'country': asn_country_code
#         }


# def create_ip_command_markdown(ip, sources, events, domains, urls, asn):
#     md = '## Cymon IP report for: {}\n'.format(ip)
#
#     if asn:
#         md += 'ASN: **{}** ({})\n'.format(asn.get('asn'), asn.get('country'))
#
#     md += '\n'
#
#     if events:
#         md += '### Reports\n'
#         for event in events:
#             md += '**{}** (Last reported on: {})\n'.format(event.title(), events[event])
#
#     if sources:
#         md += '#### Sources\n'
#         for source in sources:
#             md += '{}\n'.format(source)
#
#     if domains and len(domains) > 0:
#         md += tableToMarkdown("The following domains were resolved to the given IP address:", domains)
#
#     if urls and len(urls) > 0:
#         md += tableToMarkdown("The following urls were resolved to the given IP address:", urls)
#
#     return md


# def create_ip_command_context(ip, asn, events, domains):
#     if events:
#         description = 'Reported suspicious activities: '
#
#         for event in events:
#             description += '{}, '.format(event)
#
#         description = description[:-2]
#     else:
#         description = 'No suspicious activities were reported'
#
#     asn_in_context = {}  # type:dict
#
#     if asn:
#         asn_in_context = {
#             'ASN': asn.get('asn'),
#             'Geo': {
#                 'Country': asn.get('country')
#             }
#         }
#
#     context = {'Cymon': {
#         'IP': {
#             'Domains': domains
#         }
#     }, outputPaths['ip']: {
#         'Address': ip,
#         'Malicious': {
#             'Vendor': 'Cymon',
#             'Description': description
#         }
#     }}
#
#     context[outputPaths['ip']].update(asn_in_context)
#
#     return context


# def get_ip_report_command():
#     args = demisto.args()
#
#     full_response = args.get('fullResponse') == 'true'
#
#     ip = args.get('ip')
#     if not is_ip_valid(ip):
#         return_error('An inalid IP was specified')
#
#     sources = get_ip_events_sources(ip)
#
#     if not sources:
#         return "IP " + ip + " is not in Cymons's dataset"
#
#     if full_response:
#         max_len = 1000
#     else:
#         max_len = 50
#
#     events = get_ip_events(ip)
#     location = get_ip_location(ip)
#     domains = get_ip_domains(ip, max_len)
#     urls = get_ip_urls(ip, max_len)
#     asn = get_ip_asn(ip)
#
#     markdown = create_ip_command_markdown(ip, sources, events, domains, urls, asn)
#     context = create_ip_command_context(ip, asn, events, domains)
#
#     return [
#         {
#             'Type': entryTypes['map'],
#             'Contents': {
#                 'lat': float(location.get('lat')),
#                 'lng': float(location.get('lon'))
#             },
#             'ContentsFormat': formats['json']
#         },
#         {
#             'Type': entryTypes['note'],
#             'Contents': {
#                 'events': events,
#                 'sources': sources,
#                 'location': location,
#                 'domains': domains,
#                 'urls': urls,
#                 'asn': asn
#             },
#             'HumanReadable': markdown,
#             'EntryContext': context,
#             'ContentsFormat': formats['json']
#         }]


''' EXECUTION CODE '''
try:
    command = demisto.command()

    if command == 'test-module':
        demisto.results('Cymon has been Deprecated and is no longer in service. Please delete the instance.')
    elif command == 'ip':
        cymon_says()
    elif command == 'domain':
        cymon_says()

except Exception as e:
    raise
