import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests
from distutils.util import strtobool
from collections import defaultdict

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

USERNAME = demisto.params().get('credentials').get('identifier')
PASSWORD = demisto.params().get('credentials').get('password')
SERVER = (demisto.params()['url'][:-1]
          if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url'])
USE_SSL = not demisto.params().get('insecure', False)
BASE_URL = SERVER + '/api/v1/'
HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}
NONE_DATE = '0001-01-01T00:00:00Z'

FETCH_TIME = demisto.params().get('fetch_time', '').strip()
FETCH_LIMIT = demisto.params().get('fetch_limit', 10)
RAISE_EXCEPTION_ON_ERROR = False


''' HELPER FUNCTIONS '''


def http_request(method, path, params=None, data=None):
    """
    Sends an HTTP request using the provided arguments
    :param method: HTTP method
    :param path: URL path
    :param params: URL query params
    :param data: Request body
    :return: JSON response
    """
    params = params if params is not None else {}
    data = data if data is not None else {}
    res = None

    try:
        res = requests.request(
            method,
            BASE_URL + path,
            auth=(USERNAME, PASSWORD),
            verify=USE_SSL,
            params=params,
            data=json.dumps(data),
            headers=HEADERS)
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout,
            requests.exceptions.TooManyRedirects, requests.exceptions.RequestException) as e:
        return_error('Could not connect to PhishLabs IOC Feed: {}'.format(str(e)))

    if res.status_code < 200 or res.status_code > 300:
        status = res.status_code
        message = res.reason
        details = ''
        try:
            error_json = res.json()
            message = error_json.get('statusMessage')
            details = error_json.get('message')
        except Exception:
            pass
        error_message = ('Error in API call to PhishLabs IOC API, status code: {}, reason: {}, details: {}'
                         .format(status, message, details))
        if RAISE_EXCEPTION_ON_ERROR:
            raise error_message
        else:
            return_error(error_message)
    try:
        return res.json()
    except Exception:
        error_message = 'Failed parsing the response from PhishLabs IOC API: {}'.format(res.content)
        if RAISE_EXCEPTION_ON_ERROR:
            raise error_message
        else:
            return_error(error_message)


def populate_context(dbot_scores, domain_entries, file_entries, url_entries, email_entries=None):
    """
    Populate the context object with entries as tuples -
    the first element contains global objects and the second contains PhishLabs objects
    :param dbot_scores: Indicator DBotScore
    :param domain_entries: Domain indicators
    :param file_entries: File indicators
    :param url_entries: URL indicators
    :param email_entries: Email indicators
    :return: The context object
    """
    context = {}
    if url_entries:
        context[outputPaths['url']] = createContext(list(map(lambda u: u[0], url_entries)))
        context['PhishLabs.URL(val.ID && val.ID === obj.ID)'] = createContext(list(map(lambda u: u[1], url_entries)))
    if domain_entries:
        context[outputPaths['domain']] = createContext(list(map(lambda d: d[0], domain_entries)))
        context['PhishLabs.Domain(val.ID && val.ID === obj.ID)'] = createContext(list(map(lambda d: d[1],
                                                                                          domain_entries)))
    if file_entries:
        context[outputPaths['file']] = createContext(list(map(lambda f: f[0], file_entries)))
        context['PhishLabs.File(val.ID && val.ID === obj.ID)'] = createContext(list(map(lambda f: f[1], file_entries)))
    if email_entries:
        context['Email'] = createContext(list(map(lambda e: e[0], email_entries)))
        context['PhishLabs.Email(val.ID && val.ID === obj.ID)'] = createContext(list(map(lambda e: e[1],
                                                                                         email_entries)))
    if dbot_scores:
        context[outputPaths['dbotscore']] = dbot_scores
    return context


def get_file_properties(indicator):
    """
    Extract the file properties from the indicator attributes
    :param indicator: The file indicator
    :return: 
    """
    file_name_attribute = list(filter(lambda a: a.get('name') == 'name', indicator.get('attributes', [])))
    file_name = file_name_attribute[0].get('value') if file_name_attribute else ''
    file_type_attribute = list(filter(lambda a: a.get('name') == 'filetype', indicator.get('attributes', [])))
    file_type = file_type_attribute[0].get('value') if file_type_attribute else ''
    file_md5_attribute = list(filter(lambda a: a.get('name') == 'md5', indicator.get('attributes', [])))
    file_md5 = file_md5_attribute[0].get('value') if file_md5_attribute else ''

    return file_md5, file_name, file_type


def get_email_properties(indicator):
    """
    Extract the email properties from the indicator attributes
    :param indicator: The email indicator
    :return:
    """
    email_to_attribute = list(filter(lambda a: a.get('name') == 'to', indicator.get('attributes', [])))
    email_to = email_to_attribute[0].get('value') if email_to_attribute else ''
    email_from_attribute = list(filter(lambda a: a.get('name') == 'from', indicator.get('attributes', [])))
    email_from = email_from_attribute[0].get('value') if email_from_attribute else ''
    email_body_attribute = list(filter(lambda a: a.get('name') == 'email-body', indicator.get('attributes', [])))
    email_body = email_body_attribute[0].get('value') if email_body_attribute else ''

    return email_body, email_to, email_from


def create_domain_context(indicator):
    """
    Create a domain context object
    :param indicator: The domain indicator
    :return: The domain context object
    """
    return {
        'Name': indicator.get('value')
    }


def create_url_context(indicator):
    """
    Create a URL context object
    :param indicator: The URL indicator
    :return: The URL context object
    """
    return {
        'Data': indicator.get('value'),
        'Malicious': {
            'Vendor': 'PhishLabs',
            'Description': 'URL in PhishLabs feed'
        }
    }


def create_phishlabs_object(indicator):
    """
    Create the context object for the PhishLabs path
    :param indicator: The indicator
    :return: The context object
    """
    return {
        'ID': indicator.get('id'),
        'CreatedAt': indicator.get('createdAt'),
        'UpdatedAt': indicator.get('updatedAt'),
        'Type': indicator.get('type'),
        'Attribute': [{
            'Name': a.get('name'),
            'Type': a.get('type'),
            'Value': a.get('value'),
            'CreatedAt': a.get('createdAt')
        } for a in indicator.get('attributes', [])]
    }


def create_indicator_content(indicator):
    """
    Create content for the human readable object
    :param indicator: The indicator
    :return: The object to return to the War Room
    """
    return {
        'ID': indicator.get('id'),
        'Indicator': indicator.get('value'),
        'Type': indicator.get('type'),
        'CreatedAt': indicator.get('createdAt'),
        'UpdatedAt': indicator['updatedAt'] if indicator.get('updatedAt', '') != NONE_DATE else '',
        'FalsePositive': indicator.get('falsePositive')
    }


''' COMMANDS'''


def test_module():
    """
    Performs basic get request to get item samples
    """
    get_global_feed_request(limit=1)
    demisto.results('ok')


def get_global_feed_command():
    """
    Gets the global feed data using the provided arguments
    """
    indicator_headers = ['Indicator', 'Type', 'CreatedAt', 'UpdatedAt', 'ID', 'FalsePositive']
    contents = []
    url_entries = []
    domain_entries = []
    file_entries = []
    dbot_scores = []
    context = {}

    since = demisto.args().get('since')
    limit = demisto.args().get('limit')
    indicator = demisto.args().get('indicator_type')
    offset = demisto.args().get('offset')
    remove_protocol = demisto.args().get('remove_protocol')
    remove_query = demisto.args().get('remove_query')
    false_positive = demisto.args().get('false_positive')

    feed = get_global_feed_request(since, limit, indicator, offset, remove_protocol, remove_query, false_positive)

    if feed and feed.get('data'):
        results = feed['data']

        for result in results:
            contents.append(create_indicator_content(result))

            indicator_type = result.get('type')
            phishlabs_object = create_phishlabs_object(result)

            dbot_score = {
                'Indicator': result.get('value'),
                'Vendor': 'PhishLabs',
                'Score': 3
            }

            if indicator_type == 'URL':
                context_object = create_url_context(result)
                phishlabs_object['Data'] = result.get('value')
                dbot_score['type'] = 'url'
                url_entries.append((context_object, phishlabs_object))

            elif indicator_type == 'Domain':
                context_object = create_domain_context(result)
                phishlabs_object['Name'] = result.get('value')
                dbot_score['type'] = 'domain'
                domain_entries.append((context_object, phishlabs_object))

            elif indicator_type == 'Attachment':
                file_md5, file_name, file_type = get_file_properties(result)

                context_object = {
                    'Name': file_name,
                    'Type': file_type,
                    'MD5': file_md5
                }

                phishlabs_object['Name'] = file_name
                phishlabs_object['Type'] = file_type
                phishlabs_object['MD5'] = file_md5

                file_entries.append((context_object, phishlabs_object))
                dbot_score['type'] = 'file'

            dbot_scores.append(dbot_score)

        context = populate_context(dbot_scores, domain_entries, file_entries, url_entries)
        human_readable = tableToMarkdown('PhishLabs Global Feed', contents, headers=indicator_headers,
                                         removeNull=True, headerTransform=pascalToSpace)
    else:
        human_readable = 'No indicators found'

    return_outputs(human_readable, context, feed)


def get_global_feed_request(since=None, limit=None, indicator=None, offset=None,
                            remove_protocol=None, remove_query=None, false_positive=None):
    """
    Sends a request to PhishLabs global feed with the provided arguments
    :param since: Data updated within this duration of time from now
    :param limit: Limit the number of rows to return
    :param indicator: Indicator type filter
    :param offset: Number of rows to skip
    :param remove_protocol: Removes the protocol part from indicators when the rule can be applied.
    :param remove_query: Removes the query string part from indicators when the rules can be applied.
    :param false_positive: Filter by indicators that are false positives.
    :return: Global feed indicators
    """
    path = 'globalfeed'
    params = {}

    if since:
        params['since'] = since
    if limit:
        params['limit'] = int(limit)
    if offset:
        params['offset'] = int(offset)
    if indicator:
        params['indicator'] = indicator
    if remove_protocol:
        params['remove_protocol'] = remove_protocol
    if remove_query:
        params['remove_query'] = remove_query
    if false_positive:
        params['false_positive'] = false_positive

    response = http_request('GET', path, params)

    return response


def get_incident_indicators_command():
    """
    Gets the indicators for the specified incident
    """
    indicator_headers = ['Indicator', 'Type', 'CreatedAt', 'UpdatedAt', 'ID', 'FalsePositive']
    attribute_headers = ['Name', 'Type', 'Value', 'CreatedAt']
    url_entries = []
    domain_entries = []
    file_entries = []
    email_entries = []
    dbot_scores = []
    context = {}

    incident_id = demisto.args().get('id')
    since = demisto.args().get('since')
    limit = demisto.args().get('limit')
    indicator = demisto.args().get('indicator_type')
    offset = demisto.args().get('offset')
    classification = demisto.args().get('indicators_classification', 'Suspicious')
    human_readable = 'Indicators for incident ' + incident_id + '\n'

    feed = get_feed_request(since, limit, indicator, offset)
    if feed and feed.get('data'):
        results = list(filter(lambda f: f.get('referenceId', '') == incident_id, feed['data']))
        if results:
            for result in results[0].get('indicators', []):
                human_readable += tableToMarkdown('Indicator', create_indicator_content(result),
                                                  headers=indicator_headers,
                                                  removeNull=True, headerTransform=pascalToSpace)
                phishlabs_object = create_phishlabs_object(result)

                if phishlabs_object.get('Attribute'):
                    human_readable += tableToMarkdown('Attributes', phishlabs_object['Attribute'],
                                                      headers=attribute_headers,
                                                      removeNull=True, headerTransform=pascalToSpace)
                else:
                    human_readable += 'No attributes for this indicator'

                indicator_type = result.get('type')

                dbot_score = {
                    'Indicator': result.get('value'),
                    'Vendor': 'PhishLabs',
                    'Score': 3 if classification == 'Malicious' else 2
                }

                if indicator_type == 'URL':
                    context_object = create_url_context(result)
                    phishlabs_object['Data'] = result.get('value')
                    dbot_score['type'] = 'url'
                    url_entries.append((context_object, phishlabs_object))

                elif indicator_type == 'Domain':
                    context_object = create_domain_context(result)
                    phishlabs_object['Name'] = result.get('value')
                    dbot_score['type'] = 'domain'
                    domain_entries.append((context_object, phishlabs_object))

                elif indicator_type == 'Attachment':
                    file_md5, file_name, file_type = get_file_properties(result)

                    context_object = {
                        'Name': file_name,
                        'Type': file_type,
                        'MD5': file_md5
                    }

                    phishlabs_object['Name'] = file_name
                    phishlabs_object['Type'] = file_type
                    phishlabs_object['MD5'] = file_md5

                    file_entries.append((context_object, phishlabs_object))
                    dbot_score['type'] = 'file'

                elif indicator_type == 'E-mail':
                    email_body, email_to, email_from = get_email_properties(result)

                    context_object = {
                        'To': email_to,
                        'From': email_from,
                        'Body': email_body,
                        'Subject': result.get('value')
                    }

                    phishlabs_object['To'] = email_to,
                    phishlabs_object['From'] = email_from,
                    phishlabs_object['Body'] = email_body
                    phishlabs_object['Subject'] = result.get('value')

                    email_entries.append((context_object, phishlabs_object))

                if indicator_type != 'E-mail':
                    # We do not know what we have for an email
                    dbot_scores.append(dbot_score)

            context = populate_context(dbot_scores, domain_entries, file_entries, url_entries, email_entries)
        else:
            human_readable = 'Incident not found, check your arguments'
    else:
        human_readable = 'No incidents found, check your arguments'

    return_outputs(human_readable, context, feed)


def get_feed_request(since=None, limit=None, indicator=None, offset=None):
    """
    Sends a request to PhishLabs user feed with the provided arguments
    :param since: Data updated within this duration of time from now
    :param limit: Limit the number of rows to return
    :param indicator: Indicator type filter
    :param offset: Number of rows to skip
    :return: User feed
    """
    path = 'feed'
    params = {}

    if since:
        params['since'] = since
    if limit:
        params['limit'] = int(limit)
    if offset:
        params['offset'] = int(offset)
    if indicator:
        params['indicator'] = indicator

    response = http_request('GET', path, params)

    return response


def fetch_incidents():
    """
    Fetches incidents from the PhishLabs user feed.
    :return: Demisto incidents
    """
    last_run = demisto.getLastRun()
    last_fetch = last_run.get('time') if last_run else None

    incidents = []
    count = 0
    feed = get_feed_request(since=FETCH_TIME, limit=FETCH_LIMIT)
    last_fetch = (datetime.strptime(last_fetch, '%Y-%m-%dT%H:%M:%SZ') if last_fetch
                  else datetime.strptime(NONE_DATE, '%Y-%m-%dT%H:%M:%SZ'))
    max_time = last_fetch
    results = feed.get('data', [])
    for result in results:
        if count > FETCH_LIMIT:
            break
        incident_time = datetime.strptime(result.get('createdAt', NONE_DATE), '%Y-%m-%dT%H:%M:%SZ')
        if last_fetch and incident_time <= last_fetch:
            continue

        incident = {
            'name': 'PhishLabs IOC Incident ' + result.get('referenceId'),
            #'occurred': datetime.strftime(incident_time, '%Y-%m-%dT%H:%M:%S'),
            'rawJSON': json.dumps(result)
        }
        incidents.append(incident)
        if max_time < incident_time:
            max_time = incident_time
        count += 1

    demisto.incidents(incidents)
    demisto.setLastRun({'time': datetime.strftime(max_time, '%Y-%m-%dT%H:%M:%SZ')})


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is {}'.format(demisto.command()))
handle_proxy()

COMMAND_DICT = {
    'test-module': test_module,
    'fetch-incidents': fetch_incidents,
    'phishlabs-global-feed': get_global_feed_command,
    'phishlabs-get-incident-indicators': get_incident_indicators_command
}


try:
    command_func = COMMAND_DICT[demisto.command()]
    if demisto.command() == 'fetch-incidents':
        RAISE_EXCEPTION_ON_ERROR = True
    command_func()

except Exception as e:
    LOG(str(e))
    LOG.print_log()
    if RAISE_EXCEPTION_ON_ERROR:
        raise
    else:
        return_error(str(e))
