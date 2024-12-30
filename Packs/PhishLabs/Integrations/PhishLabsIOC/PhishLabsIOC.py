import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests
from collections.abc import Callable

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # type: ignore

''' GLOBALS/PARAMS '''

HEADERS: dict = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}
NONE_DATE: str = '0001-01-01T00:00:00Z'

RAISE_EXCEPTION_ON_ERROR: bool = False
SEC_IN_DAY: int = 86400


class Client:

    def __init__(self, base_url: str, user_name: str, password: str, use_ssl: bool,
                 reliability: str = DBotScoreReliability.B):
        self.base_url = base_url
        self.user_name = user_name
        self.password = password
        self.use_ssl = use_ssl
        self.reliability = reliability

    @logger
    def http_request(self, method: str, path: str, params: dict = None, data: dict = None) -> dict:
        """
        Sends an HTTP request using the provided arguments
        :param method: HTTP method
        :param path: URL path
        :param params: URL query params
        :param data: Request body
        :return: JSON response
        """
        params: dict = params if params is not None else {}
        data: dict = data if data is not None else {}

        try:
            res: requests.Response = requests.request(
                method,
                self.base_url + path,
                auth=(self.user_name, self.password),
                verify=self.use_ssl,
                params=params,
                data=json.dumps(data),
                headers=HEADERS)
        except requests.exceptions.SSLError:
            ssl_error = 'Could not connect to PhishLabs IOC Feed: Could not verify certificate.'
            if RAISE_EXCEPTION_ON_ERROR:
                raise Exception(ssl_error)
            return return_error(ssl_error)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout,
                requests.exceptions.TooManyRedirects, requests.exceptions.RequestException) as e:
            connection_error = f'Could not connect to PhishLabs IOC Feed: {str(e)}'
            if RAISE_EXCEPTION_ON_ERROR:
                raise Exception(connection_error)
            return return_error(connection_error)

        if res.status_code < 200 or res.status_code > 300:
            status: int = res.status_code
            message: str = res.reason
            try:
                error_json: dict = res.json()
                message = error_json.get('error', '')
            except Exception:
                pass
            error_message: str = (f'Error in API call to PhishLabs IOC API, status code: {status}')
            if status == 401:
                error_message = 'Could not connect to PhishLabs IOC Feed: Wrong credentials'
            if message:
                error_message += ', reason:' + message
            if RAISE_EXCEPTION_ON_ERROR:
                raise Exception(error_message)
            else:
                return return_error(error_message)
        try:
            return res.json()
        except Exception:
            error_message = f'Failed parsing the response from PhishLabs IOC API: {res.content!r}'
            if RAISE_EXCEPTION_ON_ERROR:
                raise Exception(error_message)
            else:
                return return_error(error_message)


''' HELPER FUNCTIONS '''


@logger
def populate_context(dbot_scores: list, domain_entries: list, file_entries: list,
                     url_entries: list, email_entries: list = None) -> dict:
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
    context: dict = {}
    if url_entries:
        context[outputPaths['url']] = createContext([u[0] for u in url_entries])
        context['PhishLabs.URL(val.ID && val.ID === obj.ID)'] = createContext([u[1] for u in url_entries],
                                                                              removeNull=True)
    if domain_entries:
        context[outputPaths['domain']] = createContext([d[0] for d in domain_entries])
        context['PhishLabs.Domain(val.ID && val.ID === obj.ID)'] = createContext([d[1] for d in domain_entries],
                                                                                 removeNull=True)
    if file_entries:
        context[outputPaths['file']] = createContext([f[0] for f in file_entries])
        context['PhishLabs.File(val.ID && val.ID === obj.ID)'] = createContext([f[1] for f in file_entries],
                                                                               removeNull=True)
    if email_entries:
        context['Email'] = createContext([e[0] for e in email_entries])
        context['PhishLabs.Email(val.ID && val.ID === obj.ID)'] = createContext([e[1] for e in email_entries],
                                                                                removeNull=True)
    if dbot_scores:
        context[outputPaths['dbotscore']] = dbot_scores
    return context


@logger
def get_file_properties(indicator: dict) -> tuple:
    """
    Extract the file properties from the indicator attributes.
    Example:
    Indicator: {
            "attributes": [
                {
                    "createdAt": "2019-05-14T13:03:45Z",
                    "id": "xyz",
                    "name": "md5",
                    "value": "c8092abd8d581750c0530fa1fc8d8318" # guardrails-disable-line
                },
                {
                    "createdAt": "2019-05-14T13:03:45Z",
                    "id": "abc",
                    "name": "filetype",
                    "value": "application/zip"
                },
                {
                    "createdAt": "2019-05-14T13:03:45Z",
                    "id": "qwe",
                    "name": "name",
                    "value": "Baycc.zip"
                }
            ],
            "createdAt": "2019-05-14T13:03:45Z",
            "falsePositive": false,
            "id": "def",
            "type": "Attachment",
            "updatedAt": "0001-01-01T00:00:00Z",
            "value": "c8092abd8d581750c0530fa1fc8d8318" # guardrails-disable-line
        }
    Return values: c8092abd8d581750c0530fa1fc8d8318, Baycc.zip, application/zip
    :param indicator: The file indicator
    :return: File MD5, name and type
    """
    file_name_attribute: list = list(filter(lambda a: a.get('name') == 'name', indicator.get('attributes', [])))
    file_name: str = file_name_attribute[0].get('value') if file_name_attribute else ''
    file_type_attribute: list = list(filter(lambda a: a.get('name') == 'filetype', indicator.get('attributes', [])))
    file_type: str = file_type_attribute[0].get('value') if file_type_attribute else ''
    file_md5_attribute: list = list(filter(lambda a: a.get('name') == 'md5', indicator.get('attributes', [])))
    file_md5: str = file_md5_attribute[0].get('value') if file_md5_attribute else ''

    return file_md5, file_name, file_type


@logger
def get_email_properties(indicator: dict) -> tuple:
    """
    Extract the email properties from the indicator attributes.
    Example:
    Indicator:
    {
    "attributes":
    [
        {
            "createdAt": "2019-05-13T16:54:18Z",
            "id": "abc",
            "name": "email-body",
            "value": "\r\n\r\n-----Original Message-----\r\nFrom: A \r\nSent:
            Monday, May 13, 2019 12:22 PM\r\nTo:
        },
        {
            "createdAt": "2019-05-13T16:54:18Z",
            "id": "def",
            "name": "from",
            "value": "foo@test.com"
        },
        {
            "createdAt": "2019-05-13T16:54:18Z",
            "id": "cf3182ca-92ec-43b6-8aaa-429802a99fe5",
            "name": "to",
            "value": "example@gmail.com"
        }
    ],
    "createdAt": "2019-05-13T16:54:18Z",
    "falsePositive": false,
    "id": "ghi",
    "type": "E-mail",
    "updatedAt": "0001-01-01T00:00:00Z",
    "value": "FW: Task"
    }
    Return values:
    :param indicator: The email indicator
    :return: Email body, To and From
    """
    email_to_attribute: list = list(filter(lambda a: a.get('name') == 'to', indicator.get('attributes', [])))
    email_to: str = email_to_attribute[0].get('value') if email_to_attribute else ''
    email_from_attribute: list = list(filter(lambda a: a.get('name') == 'from', indicator.get('attributes', [])))
    email_from: str = email_from_attribute[0].get('value') if email_from_attribute else ''
    email_body_attribute: list = list(filter(lambda a: a.get('name') == 'email-body', indicator.get('attributes', [])))
    email_body: str = email_body_attribute[0].get('value') if email_body_attribute else ''

    return email_body, email_to, email_from


@logger
def create_domain_context(indicator: dict, classification: str) -> dict:
    """
    Create a domain context object
    :param indicator: The domain indicator
    :param classification: The indicator classification
    :return: The domain context object
    """
    domain_object = {
        'Name': indicator.get('value')
    }

    if classification == 'Malicious':
        domain_object['Malicious'] = {
            'Vendor': 'PhishLabs',
            'Description': 'Domain in PhishLabs feed'
        }

    return domain_object


@logger
def create_url_context(indicator: dict, classification: str) -> dict:
    """
    Create a URL context object
    :param indicator: The URL indicator
    :param classification: The indicator classification
    :return: The URL context object
    """

    url_object: dict = {
        'Data': indicator.get('value')
    }

    if classification == 'Malicious':
        url_object['Malicious'] = {
            'Vendor': 'PhishLabs',
            'Description': 'URL in PhishLabs feed'
        }

    return url_object


@logger
def create_phishlabs_object(indicator: dict) -> dict:
    """
    Create the context object for the PhishLabs path
    :param indicator: The indicator
    :return: The context object
    """
    return {
        'ID': indicator.get('id'),
        'CreatedAt': indicator.get('createdAt'),
        'UpdatedAt': indicator['updatedAt'] if indicator.get('updatedAt', NONE_DATE) != NONE_DATE else '',
        'Attribute': [{
            'Name': a.get('name'),
            'Type': a.get('type'),
            'Value': a.get('value'),
            'CreatedAt': a.get('createdAt')
        } for a in indicator.get('attributes', [])]
    }


def indicator_type_finder(indicator_data: dict):
    """Find the indicator type of the given indicator

    Args:
        indicator_data(dict): The data about the indicator

    Returns:
        str. The indicator type
    """
    indicator = indicator_data.get('value')
    # PhishLabs IOC does not classify Email indicators correctly giving them typing of "ReplayTo", "HeaderReplyTo"
    # "ReturnPath" and so on - to combat that we find the Email indicator type by regex
    # returned URLs could fit the email regex at some cases so we exclude them
    if re.match(str(emailRegex), str(indicator)) and str(indicator_data.get('type')).lower() != 'url':
        return 'Email'

    else:
        return indicator_data.get('type')


@logger
def create_indicator_content(indicator: dict) -> dict:
    """
    Create content for the human readable object
    :param indicator: The indicator
    :return: The object to return to the War Room
    """

    return {
        'ID': indicator.get('id'),
        'Indicator': indicator.get('value'),
        'Type': indicator_type_finder(indicator),
        'CreatedAt': indicator.get('createdAt'),
        'UpdatedAt': indicator['updatedAt'] if indicator.get('updatedAt', NONE_DATE) != NONE_DATE else '',
        'FalsePositive': indicator.get('falsePositive')
    }


''' COMMANDS'''


def test_module(client: Client):
    """
    Performs basic get request to get item samples
    """
    get_global_feed_request(client, limit='1')
    demisto.results('ok')


def get_global_feed_command(client: Client):
    """
    Gets the global feed data using the provided arguments
    """
    indicator_headers: list = ['Indicator', 'Type', 'CreatedAt', 'UpdatedAt', 'FalsePositive']
    contents: list = []
    url_entries: list = []
    domain_entries: list = []
    file_entries: list = []
    dbot_scores: list = []
    context: dict = {}

    since: str = demisto.args().get('since')
    limit: str = demisto.args().get('limit')
    indicator: list = argToList(demisto.args().get('indicator_type', []))
    remove_protocol: str = demisto.args().get('remove_protocol')
    remove_query: str = demisto.args().get('remove_query')
    false_positive: str = demisto.args().get('false_positive')

    feed: dict = get_global_feed_request(client, since, limit, indicator, remove_protocol, remove_query, false_positive)
    results: list = feed.get('data', []) if feed else []

    if results:
        if not isinstance(results, list):
            results = [results]
        for result in results:
            contents.append(create_indicator_content(result))
            indicator_false_positive = result.get('falsePositive', False)
            indicator_type: str = result.get('type')
            phishlabs_object: dict = create_phishlabs_object(result)

            dbot_score: dict = {
                'Indicator': result.get('value'),
                'Vendor': 'PhishLabs',
                'Score': 3 if not indicator_false_positive else 1,
                'Reliability': client.reliability
            }

            if indicator_type == 'URL':
                context_object = create_url_context(result, 'Malicious' if not indicator_false_positive else 'Good')
                phishlabs_object['Data'] = result.get('value')
                dbot_score['type'] = 'url'
                url_entries.append((context_object, phishlabs_object))

            elif indicator_type == 'Domain':
                context_object = create_domain_context(result, 'Malicious' if not indicator_false_positive else 'Good')
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
        human_readable: str = tableToMarkdown('PhishLabs Global Feed', contents, headers=indicator_headers,
                                              removeNull=True, headerTransform=pascalToSpace)
    else:
        human_readable = 'No indicators found'

    return_outputs(human_readable, context, feed)


@logger
def get_global_feed_request(client: Client, since: str = None, limit: str = None, indicator: list = None,
                            remove_protocol: str = None, remove_query: str = None, false_positive: str = None) -> dict:
    """
    Sends a request to PhishLabs global feed with the provided arguments
    :param client: The client with the http request
    :param since: Data updated within this duration of time from now
    :param limit: Limit the number of rows to return
    :param indicator: Indicator type filter
    :param remove_protocol: Removes the protocol part from indicators when the rule can be applied.
    :param remove_query: Removes the query string part from indicators when the rules can be applied.
    :param false_positive: Filter by indicators that are false positives.
    :return: Global feed indicators
    """
    path: str = 'globalfeed'
    params: dict = {}

    if since:
        params['since'] = since
    if limit:
        params['limit'] = int(limit)
    if indicator:
        params['indicator'] = indicator
    if remove_protocol:
        params['remove_protocol'] = remove_protocol
    if remove_query:
        params['remove_query'] = remove_query
    if false_positive:
        params['false_positive'] = false_positive

    response = client.http_request('GET', path, params)

    return response


def get_incident_indicators_command(client: Client):
    """
    Gets the indicators for the specified incident
    """
    indicator_headers: list = ['Indicator', 'Type', 'CreatedAt', 'UpdatedAt', 'FalsePositive']
    attribute_headers: list = ['Name', 'Type', 'Value', 'CreatedAt']
    url_entries: list = []
    domain_entries: list = []
    file_entries: list = []
    email_entries: list = []
    dbot_scores: list = []
    context: dict = {}

    incident_id: str = demisto.args()['incident_id']
    since: str = demisto.args().get('since')
    limit: str = demisto.args().get('limit')
    indicator: list = argToList(demisto.args().get('indicator_type', []))
    classification: str = demisto.args().get('indicators_classification', 'Suspicious')
    remove_protocol: str = demisto.args().get('remove_protocol')
    remove_query: str = demisto.args().get('remove_query')

    human_readable: str = '## Indicators for incident ' + incident_id + '\n'

    feed: dict = get_feed_request(client, since, indicator=indicator, remove_protocol=remove_protocol, remove_query=remove_query)
    results: list = feed.get('data', []) if feed else []

    if results:
        if not isinstance(results, list):
            results = [results]
        results = list(filter(lambda f: f.get('referenceId', '') == incident_id, results))
        if results:
            indicators = results[0].get('indicators', [])
            if limit:
                indicators = indicators[:int(limit)]
            for result in indicators:
                human_readable += tableToMarkdown('Indicator', create_indicator_content(result),
                                                  headers=indicator_headers,
                                                  removeNull=True, headerTransform=pascalToSpace)
                phishlabs_object = create_phishlabs_object(result)

                if phishlabs_object.get('Attribute'):
                    human_readable += tableToMarkdown('Attributes', phishlabs_object['Attribute'],
                                                      headers=attribute_headers,
                                                      removeNull=True, headerTransform=pascalToSpace)
                else:
                    human_readable += 'No attributes for this indicator\n'

                indicator_type: str = result.get('type')

                dbot_score: dict = {
                    'Indicator': result.get('value'),
                    'Vendor': 'PhishLabs',
                    'Score': 3 if classification == 'Malicious' else 2,
                    'Reliability': client.reliability
                }

                if indicator_type == 'URL':
                    context_object = create_url_context(result, classification)
                    phishlabs_object['Data'] = result.get('value')
                    dbot_score['type'] = 'url'
                    url_entries.append((context_object, phishlabs_object))

                elif indicator_type == 'Domain':
                    context_object = create_domain_context(result, classification)
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
            human_readable = 'Incident not found'
    else:
        human_readable = 'No incidents found'

    return_outputs(human_readable, context, feed)


@logger
def get_feed_request(client: Client, since: str = None, limit: str = None, indicator: list = None,
                     remove_protocol: str = None, remove_query: str = None,
                     offset: str = None, sort: bool = False) -> dict:
    """
    Sends a request to PhishLabs user feed with the provided arguments
    :param client: The client with the http request
    :param since: Data updated within this duration of time from now
    :param limit: Limit the number of rows to return
    :param indicator: Indicator type filter
    :param remove_protocol: Removes the protocol part from indicators when the rule can be applied.
    :param remove_query: Removes the query string part from indicators when the rules can be applied.
    :param offset: Number of incidents to skip
    :param sort: If true, the incidents will be sorted by their creation time in ascending order.
    :return: User feed
    """
    path: str = 'feed'
    params: dict = {}

    if since:
        params['since'] = since
    if limit:
        params['limit'] = int(limit)
    if offset:
        params['offset'] = int(offset)
    if indicator:
        params['indicator'] = indicator
    if remove_query:
        params['remove_query'] = remove_query
    if remove_protocol:
        params['remove_protocol'] = remove_protocol

    if sort:
        params['sort'] = 'created_at'
        params['direction'] = 'asc'

    response = client.http_request('GET', path, params)

    return response


def get_sec_time_delta(last_fetch_time):
    # try in UTC first
    fetch_delta = datetime.utcnow() - last_fetch_time
    fetch_delta_in_sec = fetch_delta.seconds

    # if negative then try in current time
    if fetch_delta_in_sec < 0:
        fetch_delta = datetime.now() - last_fetch_time
        fetch_delta_in_sec = fetch_delta.seconds

    # if negative default to 1 day
    if fetch_delta_in_sec < 0:
        fetch_delta_in_sec = SEC_IN_DAY

    return str(fetch_delta_in_sec) + "s"


def fetch_incidents(client: Client, fetch_time, fetch_limit):
    """
    Fetches incidents from the PhishLabs user feed.
    :return: Demisto incidents
    """
    last_run: dict = demisto.getLastRun()
    last_fetch: str = last_run.get('time', '') if last_run else ''
    last_fetch_time: datetime = (datetime.strptime(last_fetch, '%Y-%m-%dT%H:%M:%SZ') if last_fetch
                                 else datetime.strptime(NONE_DATE, '%Y-%m-%dT%H:%M:%SZ'))

    incidents: list = []
    count: int = 1
    limit = int(fetch_limit)
    if not last_fetch:
        feed: dict = get_feed_request(client, since=fetch_time)

    else:
        feed = get_feed_request(client, since=get_sec_time_delta(last_fetch_time))

    max_time: datetime = last_fetch_time
    results: list = feed.get('data', []) if feed else []

    if results:
        results = sorted(results, key=lambda r: datetime.strptime(r.get('createdAt', NONE_DATE), '%Y-%m-%dT%H:%M:%SZ'))
        if not isinstance(results, list):
            results = [results]

        for result in results:
            if count > limit:
                break
            incident_time: datetime = datetime.strptime(result.get('createdAt', NONE_DATE), '%Y-%m-%dT%H:%M:%SZ')
            if last_fetch_time and incident_time <= last_fetch_time:
                continue

            incident: dict = {
                'name': 'PhishLabs IOC Incident ' + result.get('referenceId', ''),
                'occurred': datetime.strftime(incident_time, '%Y-%m-%dT%H:%M:%SZ'),
                'rawJSON': json.dumps(result)
            }
            incidents.append(incident)
            if max_time < incident_time:
                max_time = incident_time
            count += 1

    demisto.setLastRun({'time': datetime.strftime(max_time, '%Y-%m-%dT%H:%M:%SZ')})
    demisto.incidents(incidents)


''' MAIN'''


def main():
    """
    Main function
    """

    params = demisto.params()

    server: str = (params.get('url')[:-1]
                   if (params.get('url') and params.get('url').endswith('/'))
                   else params.get('url'))

    reliability = demisto.params().get('integrationReliability')
    reliability = reliability if reliability else DBotScoreReliability.B

    if DBotScoreReliability.is_valid_type(reliability):
        reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability)
    else:
        raise Exception("Please provide a valid value for the Source Reliability parameter.")

    client = Client(
        base_url=f'{str(server)}/api/v1/',
        user_name=params.get('credentials', {}).get('identifier'),
        password=params.get('credentials', {}).get('password'),
        use_ssl=not params.get('insecure', False),
        reliability=reliability
    )

    global RAISE_EXCEPTION_ON_ERROR
    LOG(f'Command being called is {demisto.command()}')
    handle_proxy()
    command_dict = {
        'test-module': test_module,
        'fetch-incidents': fetch_incidents,
        'phishlabs-global-feed': get_global_feed_command,
        'phishlabs-get-incident-indicators': get_incident_indicators_command
    }
    try:
        command_func: Callable = command_dict[demisto.command()]  # type:ignore[assignment]
        if demisto.command() == 'fetch-incidents':
            RAISE_EXCEPTION_ON_ERROR = True
            command_func(client, params.get('fetch_time', '').strip(), params.get('fetch_limit', '10'))
        else:
            command_func(client)

    except Exception as e:
        if RAISE_EXCEPTION_ON_ERROR:
            LOG(str(e))
            LOG.print_log()
            raise
        else:
            return_error(str(e))


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
