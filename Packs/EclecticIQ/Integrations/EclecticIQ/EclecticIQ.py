import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
''' IMPORTS '''
from typing import Literal
from CommonServerUserPython import *
import json
import requests
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

USERNAME = demisto.params().get('credentials', {}).get('identifier')
PASSWORD = demisto.params().get('credentials', {}).get('password')
URL = demisto.params().get('url', '')
SERVER = URL[:-1] if (URL and URL.endswith('/')) else URL
USE_SSL = not demisto.params().get('insecure', False)
HEADERS = {}  # type: Dict[str, str]
IP_THRESHOLD = demisto.params().get('ip_threshold', '').lower()
URL_THRESHOLD = demisto.params().get('url_threshold', '').lower()
FILE_THRESHOLD = demisto.params().get('file_threshold', '').lower()
EMAIL_THRESHOLD = demisto.params().get('email_threshold', '').lower()
DOMAIN_THRESHOLD = demisto.params().get('domain_threshold', '').lower()
MALICOUS_LVL = Literal['unknown', 'safe', 'low', 'medium', 'high']
MALICIOUSNESS = {
    'unknown': 0,
    'safe': 1,
    'low': 2,
    'medium': 2,
    'high': 3
}
PROXIES = handle_proxy()

''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, headers=HEADERS, cmd_json=None):  # pragma: no cover

    res = requests.request(
        method,
        SERVER + url_suffix,
        headers=headers,
        json=cmd_json,
        proxies=PROXIES,
        verify=USE_SSL
    )

    if res.status_code not in {200}:
        if res.status_code == 405:
            return_error(
                'Error in API call to EclecticIQ Integration: [405] - Not Allowed - Might occur cause of an invalid '
                'URL. '
            )
        try:  # Parse the error message
            errors = json.loads(res.text).get('errors', {})[0]
            title = errors.get('title', '')
            detail = errors.get('detail', '')
            return_error(
                f'Error in API call to EclecticIQ Integration: [{res.status_code}] - {title} - {detail}'
            )
        except Exception:  # In case error message is not in expected format
            return_error(res.content)

    try:  # Verify we can generate json from the response
        return res.json()
    except ValueError:
        return_error(res)


def maliciousness_to_dbotscore(maliciousness: MALICOUS_LVL, threshold: MALICOUS_LVL) -> int:
    """
    Translates EclecticIQ obversable maliciousness confidence level to DBotScore based on given threshold

    Parameters
    ----------
    maliciousness : str
        EclecticIQ obversable maliciousness confidence level.
    threshold : str
        Minimum maliciousness confidence level to consider the IOC malicious.

    Returns
    -------
    number
        Translated DBot Score
    """
    if maliciousness not in MALICIOUSNESS:
        raise ValueError(f'{maliciousness=} whereas acceptable values are only {MALICIOUSNESS.keys()}')
    if threshold not in MALICIOUSNESS:
        raise ValueError(f'{threshold=} whereas acceptable values are only {MALICIOUSNESS.keys()}')
    if MALICIOUSNESS.get(maliciousness) >= MALICIOUSNESS.get(threshold):  # type: ignore
        return MALICIOUSNESS.get('high')  # type: ignore
    return MALICIOUSNESS.get(maliciousness)  # type: ignore


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():  # pragma: no cover
    """
    The function which runs when clicking on Test in integration settings


    Returns
    -------
    str
        ok if getting observable successfully
    """
    get_observable('8.8.8.8')
    demisto.results('ok')


def login():  # pragma: no cover
    """
    Logins to EclecticIQ API with given credentials and sets the returned token in the headers
    """
    cmd_url = '/api/auth'
    cmd_json = {
        'password': PASSWORD,
        'username': USERNAME
    }
    response = http_request('POST', cmd_url, cmd_json=cmd_json)
    if 'token' in response:
        token = response['token']
    else:
        return_error('Failed to retrieve token')
    HEADERS['Authorization'] = f'Bearer {token}'


def ip_command():  # pragma: no cover
    """
    Gets reputation of an EclecticIQ IPv4 observable

    Parameters
    ----------
    ip : str
        IPv4 to get reputation of

    Returns
    -------
    entry
        Reputation of given IPv4
    """
    ip = demisto.args()['ip']

    response = get_observable(ip)

    if 'total_count' in response and response['total_count'] == 0:
        human_readable = 'No results found'

    integration_outputs = []
    standard_ip_outputs = []

    observables = response.get('data')

    score = 0

    for observable in observables:
        meta = observable.get('meta', {})
        maliciousness = meta.get('maliciousness')
        score = maliciousness_to_dbotscore(maliciousness, IP_THRESHOLD)

        integration_outputs.append({
            'Address': ip,
            'Created': observable.get('created_at'),
            'LastUpdated': observable.get('last_updated_at'),
            'ID': observable.get('id'),
            'Maliciousness': maliciousness
        })

        standard_ip_output = {
            'Address': ip
        }
        if score == 3:
            standard_ip_output['Malicious'] = {
                'Vendor': 'EclectiqIQ',
                'Description': 'EclectiqIQ maliciousness confidence level: ' + maliciousness
            }

        standard_ip_outputs.append(standard_ip_output)

    dbot_output = {
        'Type': 'ip',
        'Indicator': ip,
        'Vendor': 'EclecticIQ',
        'Score': score
    }

    context = {
        'DBotScore': dbot_output
    }  # type: dict

    if observables:
        human_readable_title = f'EclecticIQ IP reputation - {ip}'
        human_readable = tableToMarkdown(human_readable_title, integration_outputs)
        context['EclecticIQ.IP'] = createContext(data=integration_outputs, id='ID', removeNull=True)
        context[outputPaths['ip']] = standard_ip_outputs

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': context
    })


def url_command():  # pragma: no cover
    """
    Gets reputation of an EclecticIQ URI observable

    Parameters
    ----------
    url : str
        URL to get reputation of

    Returns
    -------
    entry
        Reputation of given URL
    """
    url = demisto.args()['url']

    response = get_observable(url)

    if 'total_count' in response and response['total_count'] == 0:
        human_readable = 'No results found.'

    integration_outputs = []
    standard_url_outputs = []

    observables = response.get('data')

    score = 0

    for observable in observables:
        meta = observable.get('meta', {})
        maliciousness = meta.get('maliciousness')
        score = maliciousness_to_dbotscore(maliciousness, URL_THRESHOLD)

        integration_outputs.append({
            'Data': url,
            'Created': observable.get('created_at'),
            'LastUpdated': observable.get('last_updated_at'),
            'ID': observable.get('id'),
            'Maliciousness': maliciousness
        })

        standard_url_output = {
            'Data': url
        }
        if score == 3:
            standard_url_output['Malicious'] = {
                'Vendor': 'EclectiqIQ',
                'Description': 'EclectiqIQ maliciousness confidence level: ' + maliciousness
            }

        standard_url_outputs.append(standard_url_output)

    dbot_output = {
        'Type': 'url',
        'Indicator': url,
        'Vendor': 'EclecticIQ',
        'Score': score,
        'Reliability': demisto.params().get('integrationReliability')
    }

    context = {
        'DBotScore': dbot_output
    }  # type: dict

    if observables:
        human_readable_title = f'EclecticIQ URL reputation - {url}'
        human_readable = tableToMarkdown(human_readable_title, integration_outputs)
        context['EclecticIQ.URL'] = createContext(data=integration_outputs, id='ID', removeNull=True)
        context[outputPaths['url']] = standard_url_outputs

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': context
    })


def file_command():  # pragma: no cover
    """
    Gets reputation of an EclecticIQ hash observable

    Parameters
    ----------
    file : str
        File hash to get reputation of

    Returns
    -------
    entry
        Reputation of given file hash
    """
    file = demisto.args()['file']

    hash_type = get_hash_type(file).upper()

    response = get_observable(file)

    if 'total_count' in response and response['total_count'] == 0:
        human_readable = 'No results found.'

    integration_outputs = []
    standard_file_outputs = []

    observables = response.get('data')

    score = 0

    for observable in observables:
        meta = observable.get('meta', {})
        maliciousness = meta.get('maliciousness')
        score = maliciousness_to_dbotscore(maliciousness, FILE_THRESHOLD)

        integration_outputs.append({
            hash_type: file,
            'Created': observable.get('created_at'),
            'LastUpdated': observable.get('last_updated_at'),
            'ID': observable.get('id'),
            'Maliciousness': maliciousness
        })

        standard_file_output = {
            hash_type: file
        }
        if score == 3:
            standard_file_output['Malicious'] = {
                'Vendor': 'EclectiqIQ',
                'Description': 'EclectiqIQ maliciousness confidence level: ' + maliciousness
            }

        standard_file_outputs.append(standard_file_output)

    dbot_output = {
        'Type': 'file',
        'Indicator': file,
        'Vendor': 'EclecticIQ',
        'Score': score,
        'Reliability': demisto.params().get('integrationReliability')
    }

    context = {
        'DBotScore': dbot_output
    }  # type: dict

    if observables:
        human_readable_title = f'EclecticIQ File reputation - {file}'
        human_readable = tableToMarkdown(human_readable_title, integration_outputs)
        context['EclecticIQ.File'] = createContext(data=integration_outputs, id='ID', removeNull=True)
        context[outputPaths['file']] = standard_file_outputs

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': context
    })


def email_command():  # pragma: no cover
    """
    Gets reputation of an EclecticIQ email address observable

    Parameters
    ----------
    email : str
        Email address to get reputation of

    Returns
    -------
    entry
        Reputation of given email address
    """
    email = demisto.args()['email']

    response = get_observable(email)

    if 'total_count' in response and response['total_count'] == 0:
        human_readable = 'No results found.'

    integration_outputs = []
    standard_email_outputs = []

    observables = response.get('data')

    score = 0

    for observable in observables:
        meta = observable.get('meta', {})
        maliciousness = meta.get('maliciousness')
        score = maliciousness_to_dbotscore(maliciousness, EMAIL_THRESHOLD)

        integration_outputs.append({
            'Address': email,
            'Created': observable.get('created_at'),
            'LastUpdated': observable.get('last_updated_at'),
            'ID': observable.get('id'),
            'Maliciousness': maliciousness
        })

        standard_email_output = {
            'Address': email
        }
        if score == 3:
            standard_email_output['Malicious'] = {
                'Vendor': 'EclectiqIQ',
                'Description': 'EclectiqIQ maliciousness confidence level: ' + maliciousness
            }

        standard_email_outputs.append(standard_email_output)

    dbot_output = {
        'Type': 'email',
        'Indicator': email,
        'Vendor': 'EclecticIQ',
        'Score': score,
        'Reliability': demisto.params().get('integrationReliability')
    }

    context = {
        'DBotScore': dbot_output
    }  # type: dict

    if observables:
        human_readable_title = f'EclecticIQ Email reputation - {email}'
        human_readable = tableToMarkdown(human_readable_title, integration_outputs)
        context['EclecticIQ.Email'] = createContext(data=integration_outputs, id='ID', removeNull=True)
        context[outputPaths['email']] = standard_email_outputs

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': context
    })


def domain_command():  # pragma: no cover
    """
    Gets reputation of an EclecticIQ domain observable

    Parameters
    ----------
    domain : str
        Domain address to get reputation of

    Returns
    -------
    entry
        Reputation of given domain address
    """
    domain = demisto.args()['domain']

    response = get_observable(domain)

    if 'total_count' in response and response['total_count'] == 0:
        human_readable = 'No results found.'

    integration_outputs = []
    standard_domain_outputs = []

    observables = response.get('data')

    score = 0

    for observable in observables:
        meta = observable.get('meta', {})
        maliciousness = meta.get('maliciousness')
        score = maliciousness_to_dbotscore(maliciousness, DOMAIN_THRESHOLD)

        integration_outputs.append({
            'Name': domain,
            'Created': observable.get('created_at'),
            'LastUpdated': observable.get('last_updated_at'),
            'ID': observable.get('id'),
            'Maliciousness': maliciousness
        })

        standard_email_output = {
            'Name': domain
        }
        if score == 3:
            standard_email_output['Malicious'] = {
                'Vendor': 'EclectiqIQ',
                'Description': 'EclectiqIQ maliciousness confidence level: ' + maliciousness
            }

        standard_domain_outputs.append(standard_email_output)

    dbot_output = {
        'Type': 'domain',
        'Indicator': domain,
        'Vendor': 'EclecticIQ',
        'Score': score,
        'Reliability': demisto.params().get('integrationReliability')
    }

    context = {
        'DBotScore': dbot_output
    }  # type: dict

    if observables:
        human_readable_title = f'EclecticIQ Domain reputation - {domain}'
        human_readable = tableToMarkdown(human_readable_title, integration_outputs)
        context['EclecticIQ.Domain'] = createContext(data=integration_outputs, id='ID', removeNull=True)
        context[outputPaths['domain']] = standard_domain_outputs

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': context
    })


def get_observable(ioc):  # pragma: no cover
    """
    Send API query to EclecticIQ to get reputation of an observable

    Parameters
    ----------
    ioc : str
        IOC to get reputation of

    Returns
    -------
    response
        Python requests response object
    """
    cmd_url = f'/api/observables?filter[value]={ioc}'
    response = http_request('GET', cmd_url)
    return response


def get_observable_related_entity_command():  # pragma: no cover
    """
    Get EclecticIQ related entities to an observable

    Parameters
    ----------
    observable_id : str
        EclecticIQ observable ID to get related entites of

    Returns
    -------
    entry
        Observable related entities data
    """
    observable_id = demisto.args()['observable_id']

    processed_extract_response = processed_extract(observable_id)

    original_extract_response = original_extract(observable_id)

    response = dict(processed_extract_response)
    response['data'].extend(original_extract_response['data'])
    response['total_count'] += original_extract_response['total_count']

    if 'total_count' in response and response['total_count'] == 0:
        demisto.results('No results found')
        return

    context_outputs = []
    human_readable = ''

    entities = response.get('data')

    for entity in entities:  # type: ignore

        entity_data = entity.get('data', {})
        test_mechanisms = entity_data.get('test_mechanisms', {})
        entity_meta = entity.get('meta', {})

        context_output = {
            'Title': entity_data.get('title'),
            'ID': entity.get('id'),
            'Analysis': entity_data.get('description'),
            'EstimatedStartTime': entity_meta.get('estimated_threat_start_time'),
            'EstimatedObservedTime': entity_meta.get('estimated_observed_time'),
            'HalfLife': entity_meta.get('half_life')
        }

        if context_output['Analysis']:
            # Removing unnecessary whitespaces from the string
            context_output['Analysis'] = ' '.join(context_output['Analysis'].split())

        if context_output['HalfLife']:
            # API returns a number, we add the time format to it
            context_output['HalfLife'] = str(context_output['HalfLife']) + ' Days'

        human_readable += tableToMarkdown(f'Observable ID {observable_id} related entities', context_output)

        test_mechanisms_output = []

        for mechanism in test_mechanisms:

            mechanism_output = {
                'Type': mechanism.get('test_mechanism_type')
            }

            mechanism_rules = mechanism.get('rules')

            mechanism_rules_outputs = []

            for rule in mechanism_rules:

                mechanism_rules_outputs.append(rule.get('value'))

            mechanism_output['Rule'] = mechanism_rules_outputs

            test_mechanisms_output.append(mechanism_output)

        if test_mechanisms_output:

            context_output['TestMechanism'] = test_mechanisms_output
            human_readable += tableToMarkdown('Test mechanisms', test_mechanisms_output, removeNull=True)

        sources = entity.get('sources')

        sources_output = []

        for source in sources:

            sources_output.append({
                'Name': source.get('name'),
                'Type': source.get('source_type'),
                'Reliability': source.get('source_reliability')
            })

        if sources_output:
            context_output['Source'] = sources_output
            human_readable += tableToMarkdown('Sources', sources_output, removeNull=True)

        exposure = entity.get('exposure')

        exposure_output = {
            'Exposed': True if exposure.get('exposed') is True else False,
            'Detection': True if exposure.get('detect_feed') is True else False,
            'Prevention': True if exposure.get('prevent_feed') is True else False,
            'Community': True if exposure.get('community_feed') is True else False,
            'Sighting': True if exposure.get('sighted') is True else False
        }

        context_output['Exposure'] = exposure_output
        human_readable += tableToMarkdown('Exposure', exposure_output, removeNull=True)

        context_outputs.append(context_output)

    context = {
        'EclecticIQ.Entity': createContext(data=context_outputs, id='ID', removeNull=True)
    }

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': human_readable,
        'EntryContext': context
    })


def processed_extract(observable_id):  # pragma: no cover
    """
    Send API query to EclecticIQ to get extracted processed data of an observable

    Parameters
    ----------
    observable_id : str
        EclecticIQ observable ID to get extracted processed data of of

    Returns
    -------
    response
        Python requests response object
    """
    cmd_url = f'/private/entities/processed-extract/{observable_id}'
    response = http_request('GET', cmd_url)
    return response


def original_extract(observable_id):  # pragma: no cover
    """
    Send API query to EclecticIQ to get extracted orginial data of an observable

    Parameters
    ----------
    observable_id : str
        EclecticIQ observable ID to get extracted orginial data of of

    Returns
    -------
    response
        Python requests response object
    """
    cmd_url = f'/private/entities/original-extract/{observable_id}'
    response = http_request('GET', cmd_url)
    return response


''' COMMANDS MANAGER / SWITCH PANEL '''

COMMANDS = {
    'test-module': test_module,
    'url': url_command,
    'ip': ip_command,
    'email': email_command,
    'file': file_command,
    'domain': domain_command,
    'eclecticiq-get-observable-related-entity': get_observable_related_entity_command
}


def main():  # pragma: no cover
    try:
        LOG(f'Command being called is {demisto.command()}')
        login()
        command_func = COMMANDS.get(demisto.command())
        if command_func is not None:
            command_func()
    except Exception as e:
        return_error(f'Error has occurred in EclecticIQ integration: {type(e)}\n {e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
