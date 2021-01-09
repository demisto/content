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

    def __init__(self, api_key, url, verify, proxies, query, tags):
        self.url = url
        self.api_key = api_key
        self.verify = verify
        self.proxies = proxies
        self.query = query
        self.tags = tags

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

def fetch_indicators(client: Client, tags: str, query: str) -> List[Dict]:
    """Retrieves indicators and reports from the feed

    Args:
        client: Client object with request
        feed_tags: feed tags.
        feed_query: reports query to specify what reports to search.
    Returns:
        List. Processed reports from feed.
    """
    query = query if query else client.query
    tags = tags if tags else client.tags


    url_suffix = '/reports/?query=' + urllib.parse.quote(feed_query) + '&limit=5'
    url_suffix = url_suffix + "&tags=" + feed_tags if feed_tags else url_suffix
    resp = client.http_request("GET", url_suffix=url_suffix)
    reports = resp.get("data", [])


    for type_, objects in client.objects_data.items():
        demisto.info(f'Fetched {len(objects)} Unit42 {type_} objects.')


    return reports

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


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    api_key = get_apikey()
    url = demisto.params().get('url')
    verify_certificate = not demisto.params().get('insecure', False)
    query = demisto.parmas().get('query')
    tags = demisto.parmas().get('tags')

    proxies = handle_proxy()
    try:
        client = Client(api_key, url, verify_certificate, proxies, query, tags)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            get_reports_command(client, 'report')
            demisto.results('ok')
        elif demisto.command() == 'flashpoint-search-intelligence-reports': #TODO: remove command
            report_search = demisto.args()['report_search']
            return_outputs(*get_reports_command(client, report_search))
        elif demisto.command() == 'flashpoint-get-indicators':
            return_results(fetch_indicators(client, tags, query))
    except ValueError as v_err:
        return_error(str(v_err))
    except requests.exceptions.ConnectionError as c:
        """ Caused mostly when URL is altered.""" #TODO: handle unknown command, handle bad url better
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(c)}')
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
