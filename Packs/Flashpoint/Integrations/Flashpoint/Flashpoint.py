from CommonServerPython import *

""" IMPORTS """
import ipaddress
import requests
import urllib.parse
from typing import Dict, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

""" CONSTANTS """
FLASHPOINT_PATHS = {
    'IP': 'Flashpoint.IP.Event(val.Fpid && val.Fpid == obj.Fpid)',
    'Url': 'Flashpoint.URL.Event(val.Fpid && val.Fpid == obj.Fpid)',
    'Domain': 'Flashpoint.Domain.Event(val.Fpid && val.Fpid == obj.Fpid)',
    'Email': 'Flashpoint.Email.Event(val.Fpid && val.Fpid == obj.Fpid)',
    'File': 'Flashpoint.File.Event(val.Fpid && val.Fpid == obj.Fpid)',
    'Filename': 'Flashpoint.Filename.Event(val.Fpid && val.Fpid == obj.Fpid)',
    'Event': 'Flashpoint.Event(val.EventId == obj.EventId)',
    'Report': 'Flashpoint.Report(val.ReportId == obj.ReportId)',
    'Forum': 'Flashpoint.Forum(val.ForumId == obj.ForumId)',
    'Room': 'Flashpoint.Forum.Room(val.RoomId == obj.RoomId)',
    'User': 'Flashpoint.Forum.User(val.UserId == obj.UserId)',
    'Post': 'Flashpoint.Forum.Post(val.PostId == obj.PostId)',
    'Site': 'Flashpoint.Forum.Site(val.SiteId == obj.SiteId)'
}


class Client:
    """
    Client to use in integration with powerful http_request.
    :type api_key: ``str``
    :param api_key: Use to authenticate request in header

    :type url: ``str``
    :param url: Base server address with suffix, for example: https://example.com.

    :type verify: ``Boolean``
    :param verify: Use to indicate secure/insecure http request

    :type proxies: ``dict``
    :param proxies: proxies dict for http request

    :return response of request
    :rtype ``dict``
    """

    def __init__(self, api_key, url, verify, proxies):
        self.url = url
        self.api_key = api_key
        self.verify = verify
        self.proxies = proxies

    def http_request(self, method, url_suffix, params=None):
        """
        Get http response based on url and given parameters.

        :param method: Specify http methods
        :param url_suffix: url encoded url suffix
        :param params: None
        :return: http response on json
        """
        base_url = self.url + "/api/v4"
        full_url = base_url + url_suffix

        headers = {
            'Authorization': self.api_key
        }

        resp = requests.request(
            method,
            full_url,
            verify=self.verify,
            proxies=self.proxies,
            params=params,
            headers=headers)

        status_code = resp.status_code

        resp_json = resp.json()

        if status_code != 200:
            if status_code == 400:
                raise ValueError(
                    "Invalid argument value while trying to get information from Flashpoint: " + resp_json.get(
                        'detail', 'N/A'))
            elif status_code == 401:
                raise ValueError(
                    "Encountered error while trying to get information from Flashpoint: Invalid API Key is "
                    "configured")
            elif status_code == 404:
                raise ValueError("No record found for given argument(s): Not Found")
            elif status_code in (521, 403):
                raise ValueError("Test connectivity failed. Please provide valid input parameters.")
            else:
                resp.raise_for_status()

        return resp_json


''' HELPER FUNCTIONS '''


def get_apikey():
    """ Get API Key from the command argument"""
    api_key = demisto.params()["api_key"]

    return api_key


def get_url_suffix(query):
    """
    Create url-suffix using the query value with url encoding

    :param query: value of query param
    :return: url-encoded url-suffix
    """
    return r'/indicators/simple?query=' + urllib.parse.quote(query.encode('utf8'))


def parse_indicator_response(indicators):
    """
    Extract Flashpoint event details and href values from each of the indicator in an indicator list

    :param indicators: list of indicators
    :return: dict containing event details and href
    """
    events = []
    hrefs = []
    for indicator in indicators:
        hrefs.append(indicator.get('Attribute', {}).get('href', ''))

        event = indicator.get('Attribute', {}).get('Event', {})

        tags_list = [tag for tag in event['Tags']]
        tags_value = ', '.join(tags_list)

        observed_time = time.strftime('%b %d, %Y  %H:%M', time.gmtime(float(event['timestamp'])))

        events.append({
            'Date Observed (UTC)': observed_time,
            'Name': event.get('info', ''),
            'Tags': tags_value,
        })

    return {'events': events, 'href': hrefs}


def parse_event_response(client, event, fpid, href):
    """
    Prepare required event json object from event response

    :param href: reference link of event
    :param fpid: unique id of event. i.e EventId
    :param client: object of client class
    :param event: event indicator from response
    :return: required event json object
    """
    observed_time = time.strftime('%b %d, %Y  %H:%M', time.gmtime(float(event['timestamp'])))
    name = event.get('info', '')
    uuid = event.get('uuid', '')
    if uuid:
        fp_link = client.url + '/home/technical_data/iocs/items/' + uuid
        name_str = '[{}]({})'.format(name, fp_link)
    else:
        name_str = name

    tags_list = [tag['name'] for tag in event.get('Tag', [])]
    tags_value = ', '.join(tags_list)

    event_creator_email = event.get('event_creator_email', '')

    event = {
        'Observed time (UTC)': observed_time,
        'Name': name_str,
        'Tags': tags_value,
        'EventCreatorEmail': event_creator_email,
        'EventId': fpid,
        'Href': href
    }

    return event


def parse_forum_response(resp):
    """
    Prepare forum json object from forum response

    :param resp: forum response
    :return: required forum json object
    """
    name = resp.get('name', '')
    hostname = resp.get('hostname', '')

    tags_list = [tag['name'] for tag in resp['tags']]
    tags_value = ', '.join(tags_list)

    forum_details = {
        'Name': name,
        'Hostname': hostname,
        'Tags': tags_value
    }

    return forum_details


def get_post_context(resp):
    """
    Prepare context data for forum post

    :param resp: forum post api response
    :return: dict object
    """
    post_ec = {
        'PostId': resp['id'],
        'PublishedAt': resp.get('published_at', ''),
        'Url': resp.get('url', ''),
        'PlatformUrl': resp.get('platform_url', ''),
        'Forum': resp['embed']['forum'],
        'Room': resp['embed']['room'],
        'User': resp['embed']['author']
    }

    return post_ec


def reputation_operation_command(client, indicator, func):
    """
    Common method for reputation commands to accept argument as a comma-separated values and converted into list
    and call specific function for all values.

    :param client: object of client class
    :param indicator: comma-separated values or single value
    :param func: reputation command function. i.e file_lookup, domain_lookup etc.
    :return: output of all value according to specified function.
    """
    args = argToList(indicator, ',')
    for arg in args:
        return_outputs(*func(client, arg))


def replace_key(dictionary, new_key, old_key):
    """
    This method is used for replace key in dictionary.

    :param dictionary: dictionary object on which we wan to replace key.
    :param new_key: key which will replace in dictionary
    :param old_key: existing key in dictionary
    :return: dict object
    """
    dictionary[new_key] = dictionary.pop(old_key)
    return dictionary


''' FUNCTIONS '''


def ip_lookup_command(client, ip):
    """
    'ip' command to lookup a particular ip-address
    This command searches for the ip in Flashpoint's IOC Dataset. If found, mark it as Malicious.
    If not found, lookup in Torrents for matching peer ip. If found, mark it as Suspicious.
    If not found, lookup in Forums for matching ip. If found, mark it as Suspicious.


    :param client: object of client class
    :param ip: ip-address
    :return: command output
    """
    if not is_ip_valid(ip, True):
        raise ValueError("Invalid ip - " + ip)

    query = r'+type:("ip-src","ip-dst") +value.\*:"' + urllib.parse.quote(ip.encode('utf-8')) + '"'
    resp = client.http_request("GET", url_suffix=get_url_suffix(query))

    if isinstance(resp, list):
        indicators = resp
    else:
        indicators = []

    if len(indicators) > 0:

        hr = '### Flashpoint IP address reputation for ' + ip + '\n'
        hr += 'Reputation: Malicious\n\n'

        events_details = parse_indicator_response(indicators)

        hr += tableToMarkdown('Events in which this IOC observed', events_details['events'],
                              ['Date Observed (UTC)', 'Name', 'Tags'])

        # Constructing FP Deeplink
        fp_link = client.url + '/home/search/iocs?group=indicator&ioc_type=ip-dst%2Cip-src&ioc_value=' + ip
        hr += '\nAll events and details (fp-tools): [{}]({})\n'.format(fp_link, fp_link)

        dbot_context = {
            'Indicator': ip,
            'Type': 'ip',
            'Vendor': 'Flashpoint',
            'Score': 3
        }

        ip_context = {
            'Address': ip,
            'Malicious': {
                'Vendor': 'Flashpoint',
                'Description': 'Found in malicious indicators dataset'
            }
        }

        flashpoint_ip_context = []
        for indicator in resp:
            indicator = indicator.get("Attribute", {})
            event = {
                'Address': ip,
                'EventDetails': indicator.get('Event'),
                'Category': indicator.get('category', ''),
                'Fpid': indicator.get('fpid', ''),
                'Href': indicator.get('href', ''),
                'Timestamp': indicator.get('timestamp', ''),
                'Type': indicator.get('type', ''),
                'Uuid': indicator.get('uuid', ''),
                'Comment': indicator['value'].get('comment', '')
            }
            flashpoint_ip_context.append(event)

        ec = {
            'DBotScore': dbot_context,
            outputPaths['ip']: ip_context,
            FLASHPOINT_PATHS['IP']: flashpoint_ip_context
        }

        return hr, ec, resp

    else:
        # Search for IP in torrents
        torrent_search_url_suffix = '/all/search?query=+basetypes:(+torrent) +is_verified:true ' \
                                    '+ip_address:("' + urllib.parse.quote(ip.encode('utf-8')) + \
                                    '")&limit=10&_source_includes=ip_address'
        torrent_resp = client.http_request("GET", url_suffix=torrent_search_url_suffix)
        torrent_result = torrent_resp.get('hits').get('hits', [])

        if torrent_result:
            torrent_search_link = client.url + '/home/search/torrents?ip_address=' + ip

            hr = '### Flashpoint IP address reputation for ' + ip + '\n'
            hr += 'Reputation: Suspicious\n\n'
            hr += 'FP tools link to torrent search: [{}]({})\n'.format(torrent_search_link, torrent_search_link)

            ec = {
                FLASHPOINT_PATHS['IP']: {
                    "Address": ip
                },
                'DBotScore': {
                    'Indicator': ip,
                    'Type': 'ip',
                    'Vendor': 'Flashpoint',
                    'Score': 2
                }
            }
        else:
            # Search for IP in Forums
            forum_search_url_suffix = '/forums/visits?ip_address=' + urllib.parse.quote(ip.encode('utf-8'))
            forum_resp = client.http_request("GET", url_suffix=forum_search_url_suffix)
            forum_result = forum_resp.get('data', [])

            if forum_result:
                forum_search_link = client.url + '/home/search/visits?exclude_tor_nodes_and_known_proxies=true' \
                                                 '&ip_address=' + ip

                hr = '### Flashpoint IP address reputation for ' + ip + '\n'
                hr += 'Reputation: Suspicious\n\n'
                hr += 'FP tools link to Forum-visit search: [{}]({})\n'.format(forum_search_link, forum_search_link)

                ec = {
                    FLASHPOINT_PATHS['IP']: {
                        "Address": ip
                    },
                    'DBotScore': {
                        'Indicator': ip,
                        'Type': 'ip',
                        'Vendor': 'Flashpoint',
                        'Score': 2
                    }
                }
            else:
                hr = '### Flashpoint IP address reputation for ' + ip + '\n'
                hr += 'Reputation: Unknown\n\n'
                ec = {
                    'DBotScore': {
                        'Indicator': ip,
                        'Type': 'ip',
                        'Vendor': 'Flashpoint',
                        'Score': 0
                    }
                }

        return hr, ec, resp


def domain_lookup_command(client, domain):
    """
    'domain' command to lookup a particular domain

    :param client: object of client class
    :param domain: domain
    :return: command output
    """
    query = r'+type:("domain") +value.\*.keyword:"' + domain + '"'
    resp = client.http_request("GET", url_suffix=get_url_suffix(query))

    if isinstance(resp, list):
        indicators = resp
    else:
        indicators = []

    if len(indicators) > 0:

        hr = '### Flashpoint Domain reputation for ' + domain + '\n'
        hr += 'Reputation: Malicious\n\n'

        events_details = parse_indicator_response(indicators)

        hr += tableToMarkdown('Events in which this IOC observed', events_details['events'],
                              ['Date Observed (UTC)', 'Name', 'Tags'])

        fp_link = client.url + '/home/search/iocs?group=indicator&ioc_type=domain&ioc_value=' + domain
        hr += '\nAll events and details (fp-tools): [{}]({})\n'.format(fp_link, fp_link)

        dbot_context = {
            'Indicator': domain,
            'Type': 'domain',
            'Vendor': 'Flashpoint',
            'Score': 3
        }

        domain_context = {
            'Name': domain,
            'Malicious': {
                'Vendor': 'Flashpoint',
                'Description': 'Found in malicious indicators dataset'
            }

        }

        flashpoint_domain_context = []
        for indicator in resp:
            indicator = indicator.get("Attribute", {})
            event = {
                'Domain': domain,
                'Category': indicator.get('category', ''),
                'Fpid': indicator.get('fpid', ''),
                'Href': indicator.get('href', ''),
                'Timestamp': indicator.get('timestamp', ''),
                'Type': indicator.get('type'),
                'Uuid': indicator.get('uuid', ''),
                'EventDetails': indicator.get('Event', []),
                'Comment': indicator['value'].get('comment', '')
            }
            flashpoint_domain_context.append(event)

        ec = {
            'DBotScore': dbot_context,
            outputPaths['domain']: domain_context,
            FLASHPOINT_PATHS['Domain']: flashpoint_domain_context
        }

        return hr, ec, resp

    else:
        hr = '### Flashpoint Domain reputation for ' + domain + '\n'
        hr += 'Reputation: Unknown\n\n'
        ec = {
            'DBotScore': {
                'Indicator': domain,
                'Type': 'domain',
                'Vendor': 'Flashpoint',
                'Score': 0
            }
        }

        return hr, ec, resp


def filename_lookup_command(client, filename):
    """
    'filename' command to lookup a particular filename

    :param client: object of client class
    :param filename: filename
    :return: command output
    """
    query = r'+type:("filename") +value.\*.keyword:"' + filename.replace('\\', '\\\\') + '"'
    resp = client.http_request("GET", url_suffix=get_url_suffix(query))

    if isinstance(resp, list):
        indicators = resp
    else:
        indicators = []

    if len(indicators) > 0:

        hr = '### Flashpoint Filename reputation for ' + filename + '\n'
        hr += 'Reputation: Malicious\n\n'

        events_details = parse_indicator_response(indicators)

        hr += tableToMarkdown('Events in which this IOC observed', events_details['events'],
                              ['Date Observed (UTC)', 'Name', 'Tags'])

        fp_link = client.url + '/home/search/iocs?group=indicator&ioc_type=filename&ioc_value=' + urllib.parse.quote(
            filename.replace('\\', '\\\\').encode('utf8'))
        hr += '\nAll events and details (fp-tools): [{}]({})\n'.format(fp_link, fp_link)

        dbot_context = {
            'Indicator': filename,
            'Type': 'filename',
            'Vendor': 'Flashpoint',
            'Score': 3
        }

        filename_context = {
            'Name': filename,
            'Malicious': {
                'Vendor': 'Flashpoint',
                'Description': 'Found in malicious indicators dataset'
            }

        }

        flashpoint_filename_context = []
        for indicator in resp:
            indicator = indicator.get("Attribute", {})
            event = {
                'Filename': filename,
                'Category': indicator.get('category', ''),
                'Fpid': indicator.get('fpid', ''),
                'Href': indicator.get('href', ''),
                'Timestamp': indicator.get('timestamp', ''),
                'Type': indicator.get('type'),
                'Uuid': indicator.get('uuid', ''),
                'EventDetails': indicator.get('Event', []),
                'Comment': indicator['value'].get('comment', '')
            }
            flashpoint_filename_context.append(event)

        ec = {
            'DBotScore': dbot_context,
            'Filename(val.Name == obj.Name)': filename_context,
            FLASHPOINT_PATHS['Filename']: flashpoint_filename_context
        }

        return hr, ec, resp

    else:
        hr = '### Flashpoint Filename reputation for ' + filename + '\n'
        hr += 'Reputation: Unknown\n\n'
        ec = {
            'DBotScore': {
                'Indicator': filename,
                'Type': 'filename',
                'Vendor': 'Flashpoint',
                'Score': 0
            }
        }

        return hr, ec, resp


def url_lookup_command(client, url):
    """
    'url' command to lookup a particular url

    :param client: object of client class
    :param url: url as indicator
    :return: command output
    """
    encoded_url = urllib.parse.quote(url.encode('utf8'))

    query = r'+type:("url") +value.\*.keyword:"' + url + '"'
    resp = client.http_request("GET", url_suffix=get_url_suffix(query))

    if isinstance(resp, list):
        indicators = resp
    else:
        indicators = []

    if len(indicators) > 0:

        hr = '### Flashpoint URL reputation for ' + url + '\n'
        hr += 'Reputation: Malicious\n\n'

        events_details = parse_indicator_response(indicators)

        hr += tableToMarkdown('Events in which this IOC observed', events_details['events'],
                              ['Date Observed (UTC)', 'Name', 'Tags'])

        fp_link = client.url + '/home/search/iocs?group=indicator&ioc_type=url&ioc_value=' + encoded_url
        hr += '\nAll events and details (fp-tools): [{}]({})\n'.format(fp_link, fp_link)

        dbot_context = {
            'Indicator': url,
            'Type': 'url',
            'Vendor': 'Flashpoint',
            'Score': 3
        }

        url_context = {
            'Name': url,
            'Data': url,
            'Malicious': {
                'Vendor': 'Flashpoint',
                'Description': 'Found in malicious indicators dataset'
            }

        }

        flashpoint_url_context = []
        for indicator in resp:
            indicator = indicator.get("Attribute", {})
            event = {
                'Fpid': indicator.get('fpid', ''),
                'EventDetails': indicator['Event'],
                'Category': indicator.get('category', ''),
                'Href': indicator.get('href', ''),
                'Timestamp': indicator.get('timestamp', ''),
                'Type': indicator.get('type', ''),
                'Uuid': indicator.get('uuid', ''),
                'Comment': indicator['value'].get('comment', ''),
                'Url': indicator['value']['url']
            }
            flashpoint_url_context.append(event)

        ec = {
            'DBotScore': dbot_context,
            outputPaths['url']: url_context,
            FLASHPOINT_PATHS['Url']: flashpoint_url_context
        }

        return hr, ec, resp

    else:
        hr = '### Flashpoint URL reputation for ' + url + '\n'
        hr += 'Reputation: Unknown\n\n'
        ec = {
            'DBotScore': {
                'Indicator': url,
                'Type': 'url',
                'Vendor': 'Flashpoint',
                'Score': 0
            }
        }

        return hr, ec, resp


def file_lookup_command(client, file):
    """
    'file' command to lookup a particular file hash (md5, sha1, sha256, sha512)

    :param client: object of client class
    :param file: file as indicator
    :return: command output
    """

    query = r'+type:("md5", "sha1", "sha256", "sha512") +value.\*.keyword:"' + file + '"'
    resp = client.http_request("GET", url_suffix=get_url_suffix(query))

    if isinstance(resp, list):
        indicators = resp
    else:
        indicators = []

    if len(indicators) > 0:
        indicator_type = (indicators[0].get('Attribute', {}).get('type')).upper()
        hr = '### Flashpoint File reputation for ' + file + '\n'
        hr += 'Reputation: Malicious\n\n'

        events_details = parse_indicator_response(indicators)

        hr += tableToMarkdown('Events in which this IOC observed', events_details['events'],
                              ['Date Observed (UTC)', 'Name', 'Tags'])

        fp_link = client.url + '/home/search/iocs?group=indicator&ioc_type=md5%2Csha1%2Csha256%2Csha512' \
                               '&ioc_value=' + urllib.parse.quote(file.encode('utf8'))

        hr += '\nAll events and details (fp-tools): [{}]({})\n'.format(fp_link, fp_link)

        flashpoint_file_context = []
        for indicator in resp:
            indicator = indicator.get("Attribute", {})
            event = {
                str(indicator_type).upper(): file,
                'EventDetails': indicator.get('Event'),
                'Category': indicator.get('category', ''),
                'Fpid': indicator.get('fpid', ''),
                'Href': indicator.get('href', ''),
                'Timestamp': indicator.get('timestamp', ''),
                'Type': indicator.get('type', ''),
                'Uuid': indicator.get('uuid', ''),
                'Comment': indicator['value'].get('comment', '')
            }
            flashpoint_file_context.append(event)

        dbot_context = [
            {
                'Indicator': file,
                'Type': 'hash',
                'Vendor': 'Flashpoint',
                'Score': 3
            },

            {
                'Indicator': file,
                'Type': 'file',
                'Vendor': 'Flashpoint',
                'Score': 3
            }
        ]

        file_context = {
            indicator_type: file,
            'Malicious': {
                'Vendor': 'Flashpoint',
                'Description': 'Found in malicious indicators dataset'
            }
        }

        ec = {
            'DBotScore': dbot_context,
            outputPaths['file']: file_context,
            FLASHPOINT_PATHS['File']: flashpoint_file_context
        }

        return hr, ec, resp

    else:
        hr = '### Flashpoint File reputation for ' + file + '\n'
        hr += 'Reputation: Unknown\n\n'
        ec = {
            'DBotScore':
                [
                    {
                        'Indicator': file,
                        'Type': 'file',
                        'Vendor': 'Flashpoint',
                        'Score': 0
                    },
                    {
                        'Indicator': file,
                        'Type': 'hash',
                        'Vendor': 'Flashpoint',
                        'Score': 0
                    }

                ]
        }

        return hr, ec, resp


def email_lookup_command(client, email):
    """
    'email' command to lookup a particular email address or subject

    :param client: object of client class
    :param email: email address or subject
    :return: command output
    """
    query = r'+type:("email-dst", "email-src", "email-src-display-name", "email-subject") +value.\*.keyword:"' \
            + email + '" '
    resp = client.http_request("GET", url_suffix=get_url_suffix(query))

    if isinstance(resp, list):
        indicators = resp
    else:
        indicators = []

    if len(indicators) > 0:

        hr = '### Flashpoint Email reputation for ' + email + '\n'
        hr += 'Reputation: Malicious\n\n'

        events_details = parse_indicator_response(indicators)

        hr += tableToMarkdown('Events in which this IOC observed', events_details['events'],
                              ['Date Observed (UTC)', 'Name', 'Tags'])

        fp_link = client.url + '/home/search/iocs?group=indicator&ioc_type=email-dst%2Cemail-src%2Cemail-src' \
                               '-display-name%2Cemail-subject&ioc_value=' + urllib.parse.quote(email.encode('utf8'))
        hr += '\nAll events and details (fp-tools): [{}]({})\n'.format(fp_link, fp_link)

        email_context = {
            'Name': email,
            'Malicious': {
                'Vendor': 'Flashpoint',
                'Description': 'Found in malicious indicators dataset'
            }
        }

        dbot_context = {
            'Indicator': email,
            'Type': 'email',
            'Vendor': 'Flashpoint',
            'Score': 3
        }

        flashpoint_email_context = []
        for indicator in resp:
            indicator = indicator.get("Attribute", {})
            event = {
                'EventDetails': indicator.get('Event', ''),
                'Category': indicator.get('category', ''),
                'Fpid': indicator.get('fpid', ''),
                'Href': indicator.get('href', ''),
                'Timestamp': indicator.get('timestamp', ''),
                'Type': indicator.get('type', ''),
                'Uuid': indicator.get('uuid', ''),
                'Comment': indicator['value'].get('comment', '')
            }
            flashpoint_email_context.append(event)

        ec = {
            'DBotScore': dbot_context,
            outputPaths['email']: email_context,
            FLASHPOINT_PATHS['Email']: flashpoint_email_context
        }

        return hr, ec, resp

    else:
        hr = '### Flashpoint Email reputation for ' + email + '\n'
        hr += 'Reputation: Unknown\n\n'
        ec = {
            'DBotScore': {
                'Indicator': email,
                'Type': 'email',
                'Vendor': 'Flashpoint',
                'Score': 0
            }
        }

        return hr, ec, resp


def common_lookup_command(client, indicator_value):
    """
    Command to lookup all types of the indicators

    :param client: object of client class
    :param indicator_value: value of the indicator to lookup
    :return: command output
    """
    encoded_value = urllib.parse.quote(indicator_value.encode('utf8'))

    try:
        ipaddress.ip_address(indicator_value)
        query = r'+type:("ip-src","ip-dst") +value.\*:"' + indicator_value + '"'
    except ValueError:
        try:
            ipaddress.IPv6Address(indicator_value)
            query = r'+type:("ip-src","ip-dst") +value.\*:"' + indicator_value + '"'
        except ValueError:
            query = r'+value.\*.keyword:"' + indicator_value + '"'

    resp = client.http_request("GET", url_suffix=get_url_suffix(query))

    if isinstance(resp, list):
        indicators = resp
    else:
        indicators = []

    if len(indicators) > 0:

        indicator_type = indicators[0].get('Attribute', {}).get('type')

        hr = '### Flashpoint reputation for ' + indicator_value + '\n'
        hr += 'Reputation: Malicious\n\n'

        events_details = parse_indicator_response(indicators)

        hr += tableToMarkdown('Events in which this IOC observed', events_details['events'],
                              ['Date Observed (UTC)', 'Name', 'Tags'])

        fp_link = client.url + '/home/search/iocs?group=indicator&ioc_value=' + encoded_value
        hr += '\nAll events and details (fp-tools): [{}]({})\n'.format(fp_link, fp_link)

        ec = {'DBotScore': {
            'Indicator': indicator_value,
            'Type': indicator_type,
            'Vendor': 'Flashpoint',
            'Score': 3
        }}

        return hr, ec, resp

    else:
        hr = '### Flashpoint reputation for ' + indicator_value + '\n'
        hr += 'Reputation: Unknown\n\n'
        ec = {}

        return hr, ec, resp


def get_reports_command(client, report_search):
    """
    Get reports matching the given search term or query

    :param client: object of client class
    :param report_search: search term or query
    :return: command output
    """
    url_suffix = '/reports/?query=' + urllib.parse.quote(report_search) + '&limit=5'
    resp = client.http_request("GET", url_suffix=url_suffix)
    reports = resp.get("data", [])

    hr = '### Flashpoint Intelligence reports related to search: ' + report_search + '\n'
    ec: Dict[Any, Any] = {}

    if reports:
        hr += 'Top 5 reports:\n\n'
        report_details = []
        index = 0
        for report in reports:
            title = report.get('title', 'N/A')
            platform_url = report.get('platform_url', '')
            summary = report.get('summary', 'N/A')
            index += 1
            hr += '' + str(index) + ') [{}]({})'.format(title, platform_url) + '\n'
            if report.get('summary'):
                hr += '   Summary: ' + str(summary) + '\n\n\n'
            else:
                hr += '   Summary: N/A\n\n\n'

            report_detail = {
                'ReportId': report.get('id', 'N/A'),
                'UpdatedAt': report.get('updated_at', ''),
                'PostedAt': report.get('posted_at', ''),
                'NotifiedAt': report.get('notified_at', ''),
                'PlatformUrl': platform_url,
                'Title': title,
                'Summary': summary
            }
            report_details.append(report_detail)

        fp_url = client.url + '/home/search/reports?query=' + urllib.parse.quote(report_search)
        hr += 'Link to Report-search on Flashpoint platform: [{}]({})\n'.format(fp_url, fp_url)

        ec[FLASHPOINT_PATHS['Report']] = report_details

    else:
        hr += 'No reports found for the search.'

    return hr, ec, resp


def get_report_by_id_command(client, report_id):
    """
    Get specific report using its fpid

    :param client: object of client class
    :param report_id: report's fpid
    :return: command output
    """
    url_suffix = '/reports/' + urllib.parse.quote(report_id.encode('utf-8'))
    resp = client.http_request("GET", url_suffix=url_suffix)
    report = resp

    hr = '### Flashpoint Intelligence Report details\n'
    ec: Dict[Any, Any] = {}

    if report:

        if report.get('tags') is None:
            raise ValueError("No record found for given argument(s): Not Found")

        timestamp = None
        try:
            time_str = report.get('posted_at', '')[:-10] + 'UTC'
            timestamp = time.strptime(time_str, '%Y-%m-%dT%H:%M:%S%Z')
        except TypeError:
            pass
        except ValueError:
            pass

        tags = report.get('tags', [])
        tag_string = ""
        for tag in tags:
            tag_string += ", " + str(tag)
        if tag_string:
            tag_string = tag_string[2:]

        if timestamp:
            timestamp_str = time.strftime('%b %d, %Y  %H:%M', timestamp)
        else:
            timestamp_str = 'N/A'

        report_details = [{
            'Title': '[{}]({})'.format(report.get('title', 'N/A'), report.get('platform_url', '')),
            'Date Published (UTC)': timestamp_str,
            'Summary': report.get('summary', 'N/A'),
            'Tags': tag_string
        }]

        hr += tableToMarkdown('Below are the details found:', report_details,
                              ['Title', 'Date Published (UTC)', 'Summary', 'Tags'])
        hr += '\n'
        ec[FLASHPOINT_PATHS['Report']] = {
            'ReportId': report.get('id', ''),
            'UpdatedAt': report.get('updated_at', ''),
            'PostedAt': report.get('posted_at', ''),
            'NotifiedAt': report.get('notified_at', ''),
            'PlatformUrl': report.get('platform_url', ''),
            'Title': report.get('title', ''),
            'Summary': report.get('summary', '')
        }

    else:
        hr += 'No report found for the given ID.'

    return hr, ec, resp


def get_related_reports_command(client, report_id):
    """
    Get reports related to given report

    :param report_id: report id which is related to other reports
    :param client: object of client class
    :return: command output
    """
    url_suffix = '/reports/' + urllib.parse.quote(report_id.encode('utf-8')) + '/related?limit=5'
    resp = client.http_request("GET", url_suffix=url_suffix)
    reports = resp.get("data", [])

    hr = '### Flashpoint Intelligence related reports:\n'
    ec: Dict[Any, Any] = {}

    if reports:
        hr += 'Top 5 related reports:\n\n'
        report_details = []
        index = 0
        for report in reports:
            title = report.get('title', 'N/A')
            platform_url = report.get('platform_url', '')
            summary = report.get('summary', 'N/A')
            index += 1
            hr += '' + str(index) + ') [{}]({})'.format(title, platform_url) + '\n'
            hr += '   Summary: ' + str(summary) + '\n\n\n'
            report_detail = {
                'ReportId': report.get('id', 'N/A'),
                'UpdatedAt': report.get('updated_at', ''),
                'PostedAt': report.get('posted_at', ''),
                'NotifiedAt': report.get('notified_at', ''),
                'PlatformUrl': platform_url,
                'Title': title,
                'Summary': summary
            }
            report_details.append(report_detail)

        fp_url = client.url + '/home/intelligence/reports/report/' + report_id + '#detail'
        hr += 'Link to the given Report on Flashpoint platform: [{}]({})\n'.format(fp_url, fp_url)
        ec[FLASHPOINT_PATHS['Report']] = report_details

    else:
        hr += 'No related reports found for the search.'

    return hr, ec, resp


def get_event_by_id_command(client, event_id):
    """
    Get specific event using its event id

    :param client: object of client class
    :param event_id: event's fpid
    :return: command output
    """
    url_suffix = '/indicators/event/' + urllib.parse.quote(event_id.encode('utf-8'))
    resp = client.http_request("GET", url_suffix=url_suffix)

    hr = '### Flashpoint Event details\n'
    ec: Dict[Any, Any] = {}

    if len(resp) <= 0:
        hr += 'No event found for the given ID.'
        return hr, ec, resp

    event = resp[0].get('Event', '')
    fpid = resp[0].get('fpid', '')
    href = resp[0].get('href', '')

    events = []
    if event:
        event = parse_event_response(client, event, fpid, href)
        events.append(event)
        hr += tableToMarkdown('Below are the detail found:', events, ['Observed time (UTC)', 'Name', 'Tags'])

        ec[FLASHPOINT_PATHS['Event']] = {
            'EventId': events[0]['EventId'],
            'Name': events[0]['Name'],
            'Tags': events[0]['Tags'],
            'ObservedTime': events[0]['Observed time (UTC)'],
            'EventCreatorEmail': event['EventCreatorEmail'],
            'Href': href
        }

    return hr, ec, resp


def get_events_command(client, limit, report_fpid, attack_ids, time_period):
    """
    Get events matching the given parameters

    :param client: object of client class
    :param limit: limit of the records
    :param report_fpid: report fpid to fetch events
    :param attack_ids: array of attack ids of event
    :param time_period: time period i.e 2M, 3d etc
    :return: command output
    """
    url_suffix = '/indicators/event?sort_timestamp=desc&'
    getvars = {}
    if limit:
        getvars['limit'] = limit

    if report_fpid:
        getvars['report'] = report_fpid

    if attack_ids:
        getvars['attack_ids'] = attack_ids

    if time_period:
        getvars['time_period'] = time_period

    url_suffix = url_suffix + urllib.parse.urlencode(getvars)

    resp = client.http_request("GET", url_suffix=url_suffix)
    indicators = resp
    hr = ''
    ec: Dict[Any, Any] = {}
    if len(indicators) > 0:
        hr += '### Flashpoint Events\n\n'

        events = []
        for indicator in indicators:
            href = indicator.get('href', '')
            event = indicator.get('Event', {})
            fpid = indicator.get('fpid', '')
            event = parse_event_response(client, event, fpid, href)
            events.append(event)

        hr += tableToMarkdown('Below are the detail found:', events, ['Observed time (UTC)', 'Name', 'Tags'])

        fp_link = client.url + '/home/search/iocs'
        if attack_ids:
            fp_link = fp_link + '?attack_ids=' + urllib.parse.quote(attack_ids)
        hr += '\nAll events and details (fp-tools): [{}]({})\n'.format(fp_link, fp_link)

        # Replacing the dict keys for ec  to strip any white spaces and special charcters
        for event in events:
            replace_key(event, 'ObservedTime', 'Observed time (UTC)')

        ec[FLASHPOINT_PATHS['Event']] = events

    else:
        hr += 'No event found for the argument.'

    return hr, ec, resp


def get_forum_details_by_id_command(client, forum_id):
    """
    Get specific forum details by its fpid

    :param client: object of client class
    :param forum_id: forum's fpid
    :return: command output
    """
    url_suffix = '/forums/sites/' + urllib.parse.quote(forum_id.encode('utf-8'))
    resp = client.http_request("GET", url_suffix=url_suffix)

    hr = '### Flashpoint Forum details\n'
    ec = {}

    if resp:
        forum_details = parse_forum_response(resp)
        hr += tableToMarkdown('Below are the details found:', forum_details, ['Name', 'Hostname', 'Tags'])
        hr += '\n'

        ec[FLASHPOINT_PATHS['Forum']] = {
            'ForumId': resp['id'],
            'Hostname': resp['hostname'],
            'Description': resp['description'],
            'Name': resp['name'],
            'Stats': resp['stats'],
            'Tags': resp['tags']
        }

    else:
        hr += 'No forum detail found for given forum id.'

    return hr, ec, resp


def get_room_details_by_id_command(client, room_id):
    """
    Get room details by its room id

    :param client: object of client class
    :param room_id: room's fpid
    :return: command output
    """
    url_suffix = '/forums/rooms/' + urllib.parse.quote(room_id.encode('utf-8')) + '?embed=forum'
    resp = client.http_request("GET", url_suffix=url_suffix)

    hr = '### Flashpoint Room details\n'
    ec = {}

    if resp:
        forum_name = resp['embed']['forum']['name']
        url = resp.get('url', '')
        title = resp.get('title', '')

        room_details = {
            'Forum Name': forum_name,
            'Title': title,
            'URL': url
        }

        hr += tableToMarkdown('Below are the detail found:', room_details, ['Forum Name', 'Title', 'URL'])
        hr += '\n'

        ec[FLASHPOINT_PATHS['Room']] = {
            'RoomId': resp['id'],
            'Title': title,
            'Url': url,
            'Forum': resp['embed']['forum']
        }

    else:
        hr += 'No room details found for given room id'

    return hr, ec, resp


def get_user_details_by_id_command(client, user_id):
    """
    Get user details by user's fpid

    :param client: object of client class
    :param user_id: user's fpid
    :return: command output
    """
    url_suffix = '/forums/users/' + urllib.parse.quote(user_id.encode('utf-8')) + '?embed=forum'
    resp = client.http_request("GET", url_suffix=url_suffix)

    hr = '### Flashpoint User details\n'
    ec = {}

    if resp:
        forum_name = resp['embed']['forum']['name']
        url = resp.get('url', '')
        name = resp.get('name', '')

        user_details = {
            'Forum Name': forum_name,
            'Name': name,
            'URL': url
        }

        hr += tableToMarkdown('Below are the detail found:', user_details, ['Forum Name', 'Name', 'URL'])
        hr += '\n'

        ec[FLASHPOINT_PATHS['User']] = {
            'UserId': resp['id'],
            'Name': name,
            'Url': url,
            'PlatformUrl': resp.get('platform_url', ''),
            'Forum': resp['embed']['forum']
        }

    else:
        hr += 'No user details found for given user id'

    return hr, ec, resp


def get_post_details_by_id_command(client, post_id):
    """
    Get forum post details by post's fpid

    :param client: object of client class
    :param post_id: fpid of post
    :return: command output
    """
    url_suffix = '/forums/posts/' + urllib.parse.quote(
        post_id.encode('utf-8')) + '?body_html=stripped&embed=author,room,forum,thread'
    resp = client.http_request("GET", url_suffix=url_suffix)

    hr = '### Flashpoint Post details\n'
    ec = {}

    if resp:
        published_at = resp.get('published_at', '')
        url = resp.get('url', '')
        platform_url = resp.get('platform_url', '')
        forum_name = resp['embed']['forum']['name']
        room_title = resp['embed']['room']['title']
        author_name = resp['embed']['author']['name']
        thread_title = resp['embed']['thread']['title']

        post_details = {
            'Published at': published_at,
            'Forum Name': forum_name,
            'Room Title': room_title,
            'Author Name': author_name,
            'Thread Title': thread_title,
            'URL': url,
            'Platform url': "[{}]({})".format(platform_url, platform_url)
        }

        hr += tableToMarkdown('Below are the detail found:', post_details,
                              ['Published at', 'Forum Name', 'Room Title', 'Author Name', 'Thread Title', 'URL',
                               'Platform url'])
        hr += '\n'
        post_ec = get_post_context(resp)
        ec[FLASHPOINT_PATHS['Post']] = post_ec

    else:
        hr += 'No post details found for given post id'

    return hr, ec, resp


def get_forum_sites_command(client, site_search):
    """
    Get forum sites matching search keyword or query

    :param client: object of client class
    :param site_search: site's keyword or query
    :return: command output
    """
    url_suffix = '/forums/sites/?query=' + urllib.parse.quote(site_search.encode('utf8')) + '&limit=10'
    resp = client.http_request("GET", url_suffix=url_suffix)
    sites = resp.get("data", [])

    hr = '### Flashpoint Forum sites related to search: ' + site_search + '\n'
    ec: Dict[Any, Any] = {}

    if sites:
        hr += 'Top 10 sites:\n\n'
        site_details = []
        for site in sites:
            site_detail = {
                'SiteId': site.get('id', ''),
                'Name': site.get('name', 'N/A'),
                'Hostname': site.get('hostname', 'N/A'),
                'Description': site.get('description', 'N/A'),
                'PlatformUrl': site.get('platform_url', ''),
                'Tags': site.get('tags', [])
            }

            site_details.append(site_detail)

        hr += tableToMarkdown('Below are the detail found:', site_details, ['Name', 'Hostname', 'Description'])
        hr += '\n'

        ec = {
            FLASHPOINT_PATHS['Site']: site_details
        }

    else:
        hr += 'No forum sites found for the search'

    return hr, ec, resp


def get_forum_posts_command(client, post_search):
    """
    Get forum posts details matching given keyword or query

    :param client: object of client class
    :param post_search: keyword or query for search in posts
    :return: command output
    """
    url_suffix = '/forums/posts/?query=' + urllib.parse.quote(
        post_search.encode('utf8')) + '&limit=10&embed=forum,room,author,thread'
    resp = client.http_request("GET", url_suffix=url_suffix)
    posts = resp.get("data", [])

    hr = '### Flashpoint Forum posts related to search: ' + post_search + '\n'
    ec: Dict[Any, Any] = {}

    if posts:
        hr += 'Top 10 posts:\n\n'
        post_details = []
        post_entry_context = []
        for post in posts:
            platform_url = post.get('platform_url', '')
            thread_title = post['embed']['thread']['title']
            post_ec = get_post_context(post)
            post_entry_context.append(post_ec)
            post_detail = {
                'Forum Name': post['embed']['forum']['name'],
                'Thread Title': thread_title[:30] + '....',
                'Room Title': post['embed']['room']['title'],
                'Author Name': post['embed']['author']['name'],
                'Platform URL': '[{}]({})'.format(platform_url[:30] + '...', platform_url)
            }
            post_details.append(post_detail)

        hr += tableToMarkdown('Below are the detail found:', post_details,
                              ['Forum Name', 'Thread Title', 'Room Title', 'Author Name', 'Platform URL'])
        hr += '\n'

        fp_url = client.url + '/home/search/forums?query=' + urllib.parse.quote(post_search.encode('utf8'))
        hr += 'Link to forum post-search on Flashpoint platform: [{}]({})\n'.format(fp_url, fp_url)

        ec[FLASHPOINT_PATHS['Post']] = post_entry_context

    else:
        hr += 'No forum posts found for the search'

    return hr, ec, resp


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    api_key = get_apikey()
    url = demisto.params()["url"]
    verify_certificate = not demisto.params().get('insecure', False)

    proxies = handle_proxy()
    try:
        client = Client(api_key, url, verify_certificate, proxies)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            ip_lookup_command(client, "8.8.8.8")
            demisto.results('ok')

        elif demisto.command() == 'ip':
            ip = demisto.args()['ip']
            reputation_operation_command(client, ip, ip_lookup_command)

        elif demisto.command() == 'domain':
            domain = demisto.args()['domain']
            reputation_operation_command(client, domain, domain_lookup_command)

        elif demisto.command() == 'filename':
            filename = demisto.args()['filename']
            reputation_operation_command(client, filename, filename_lookup_command)

        elif demisto.command() == 'url':
            url = demisto.args()['url']
            reputation_operation_command(client, url, url_lookup_command)

        elif demisto.command() == 'file':
            file = demisto.args()['file']
            reputation_operation_command(client, file, file_lookup_command)

        elif demisto.command() == 'email':
            email = demisto.args()['email']
            reputation_operation_command(client, email, email_lookup_command)

        elif demisto.command() == 'flashpoint-common-lookup':
            indicator_value = demisto.args()['indicator']
            reputation_operation_command(client, indicator_value, common_lookup_command)

        elif demisto.command() == 'flashpoint-search-intelligence-reports':
            report_search = demisto.args()['report_search']
            return_outputs(*get_reports_command(client, report_search))

        elif demisto.command() == 'flashpoint-get-single-intelligence-report':
            report_id = demisto.args()['report_id']
            return_outputs(*get_report_by_id_command(client, report_id))

        elif demisto.command() == 'flashpoint-get-related-reports':
            report_id = demisto.args()['report_id']
            return_outputs(*get_related_reports_command(client, report_id))

        elif demisto.command() == 'flashpoint-get-single-event':
            event_id = demisto.args()['event_id']
            return_outputs(*get_event_by_id_command(client, event_id))

        elif demisto.command() == 'flashpoint-get-events':
            args = demisto.args()
            limit = args.get('limit', 10)
            report_fpid = args.get('report_fpid')
            attack_ids = args.get('attack_ids')
            time_period = args.get('time_period')
            return_outputs(*get_events_command(client, limit, report_fpid, attack_ids, time_period))

        elif demisto.command() == 'flashpoint-get-forum-details':
            forum_id = demisto.args()['forum_id']
            return_outputs(*get_forum_details_by_id_command(client, forum_id))

        elif demisto.command() == 'flashpoint-get-forum-room-details':
            room_id = demisto.args()['room_id']
            return_outputs(*get_room_details_by_id_command(client, room_id))

        elif demisto.command() == 'flashpoint-get-forum-user-details':
            user_id = demisto.args()['user_id']
            return_outputs(*get_user_details_by_id_command(client, user_id))

        elif demisto.command() == 'flashpoint-get-forum-post-details':
            post_id = demisto.args()['post_id']
            return_outputs(*get_post_details_by_id_command(client, post_id))

        elif demisto.command() == 'flashpoint-search-forum-sites':
            site_search = demisto.args()['site_search']
            return_outputs(*get_forum_sites_command(client, site_search))

        elif demisto.command() == 'flashpoint-search-forum-posts':
            post_search = demisto.args()['post_search']
            return_outputs(*get_forum_posts_command(client, post_search))

    except ValueError as v_err:
        return_error(str(v_err))
    except requests.exceptions.ConnectionError as c:
        """ Caused mostly when URL is altered."""
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(c)}')
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
