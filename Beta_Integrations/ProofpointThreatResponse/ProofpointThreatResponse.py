import demistomock as demisto
from CommonServerPython import *
''' IMPORTS '''
import requests
import json
requests.packages.urllib3.disable_warnings()

if not demisto.getParam('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

''' GLOBAL VARS '''
BASE_URL = demisto.params().get('url')
if BASE_URL[-1] != '/':
    BASE_URL += '/'
API_KEY = demisto.params().get('apikey')
VERIFY_CERTIFICATE = False

''' COMMAND FUNCTIONS '''


def get_list(list_id):
    fullurl = BASE_URL + 'api/lists/{}/members.json'.format(list_id)
    res = requests.get(
        fullurl,
        headers={
            'Content-Type': 'application/json',
            'Authorization': API_KEY
        },
        verify=VERIFY_CERTIFICATE
    )

    if res.status_code < 200 or res.status_code >= 300:
        return_error('Get list failed. URL: {}, StatusCode: {}, Response: {}'.format(fullurl, res.status_code, res.text))

    return res.json()


def get_list_command():
    ''' Retrieves all indicators of a the given list ID in Threat Response '''
    list_id = demisto.args().get('list-id')
    list_items = get_list(list_id)

    demisto.results({'list': list_items})


def add_to_list(list_id, indicator, comment, expiration):
    fullurl = BASE_URL + 'api/lists/{}/members.json'.format(list_id)

    indicator = {
        'member': indicator
    }
    if comment:
        indicator['description'] = comment

    if expiration:
        indicator['expiration'] = expiration

    res = requests.post(
        fullurl,
        headers={
            'Authorization': API_KEY
        },
        verify=VERIFY_CERTIFICATE,
        json=indicator
    )

    if res.status_code < 200 or res.status_code >= 300:
        return_error('Add to list failed. URL: {}, Request Body: {}, StatusCode: {}, Response: {}'.format(
            fullurl, json.dumps(indicator), res.status_code, res.content))

    return res.json()


def add_to_list_command():
    ''' Adds given indicators to the given list ID in Threat Response '''
    list_id = demisto.args().get('list-id')
    indicators = argToList(demisto.args().get('indicator'))
    comment = demisto.args().get('comment')
    expiration = demisto.args().get('expiration')

    message = ''
    for indicator in indicators:
        add_to_list(list_id, indicator, comment, expiration)
        message += '{} added successfully to {}\n'.format(indicator, list_id)

    demisto.results(message)


def block_ip_command():
    ''' Adds given IPs to the relevant blacklist in Threat Response '''
    list_id = demisto.params().get('blacklist_ip')
    ips = argToList(demisto.args().get('ip'))
    expiration = demisto.args().get('expiration')

    message = ''
    for ip in ips:
        add_to_list(list_id, ip, None, expiration)
        message += '{} added successfully to block_ip list\n'.format(ip)

    demisto.results(message)


def block_domain_command():
    ''' Adds given domains to the relevant blacklist in Threat Response '''
    list_id = demisto.params().get('blacklist_domain')
    domains = argToList(demisto.args().get('domain'))
    expiration = demisto.args().get('expiration')

    message = ''
    for domain in domains:
        add_to_list(list_id, domain, None, expiration)
        message += '{} added successfully to block_domain list\n'.format(domain)

    demisto.results(message)


def block_url_command():
    ''' Adds given URLs to the relevant blacklist in Threat Response '''
    list_id = demisto.params().get('blacklist_url')
    urls = argToList(demisto.args().get('url'))
    expiration = demisto.args().get('expiration')

    message = ''
    for url in urls:
        add_to_list(list_id, url, None, expiration)
        message += '{} added successfully to block_url list\n'.format(url)

    demisto.results(message)


def block_hash_command():
    ''' Adds given hashes to the relevant blacklist in Threat Response '''
    list_id = demisto.params().get('blacklist_hash')
    hashes = argToList(demisto.args().get('hash'))
    expiration = demisto.args().get('expiration')

    message = ''
    for h in hashes:
        add_to_list(list_id, h, None, expiration)
        message += '{} added successfully to block_hash list\n'.format(h)

    demisto.results(message)


def search_indicators(list_id, indicator_filter):
    list_indicators = get_list(list_id)
    found_items = []
    for item in list_indicators:
        item_indicator = demisto.get(item, 'host.host')
        if indicator_filter in item_indicator:
            found_items.append(item)

    return found_items


def search_indicator_command():
    ''' Retrieves indicators of a list, using a filter '''
    list_id = demisto.args().get('list-id')
    indicator_filter = demisto.args().get('filter')
    found = search_indicators(list_id, indicator_filter)

    demisto.results({'indicators': found})


def delete_indicator(list_id, indicator_filter):
    indicator = search_indicators(list_id, indicator_filter)
    if len(indicator) == 0:
        return_error('{} not exists in {}'.format(indicator_filter, list_id))

    indicator_id = indicator.get('id')  # pylint: disable=E1101
    fullurl = BASE_URL + 'api/lists/{}/members/{}.json'.format(list_id, indicator_id)
    res = requests.delete(
        fullurl,
        headers={
            'Authorization': API_KEY
        },
        verify=VERIFY_CERTIFICATE
    )
    if res.status_code < 200 or res.status_code >= 300:
        return_error('Delete indicator failed. URL: {}, StatusCode: {}, Response: {}'.format(fullurl, res.status_code, res.text))


def delete_indicator_command():
    ''' Deletes an indicator from a list '''
    list_id = demisto.args().get('list-id')
    indicator = demisto.args().get('indicator')
    delete_indicator(list_id, indicator)

    demisto.results('{} deleted successfully from list {}'.format(list_id, indicator))


def test():
    get_list(demisto.params().get('blacklist_ip'))


''' EXECUTION CODE '''
LOG('command is %s' % (demisto.command(), ))
if demisto.command() == 'test-module':
    test()
    demisto.results('ok')

elif demisto.command() == 'proofpoint-tr-get-list':
    get_list_command()

elif demisto.command() == 'proofpoint-tr-add-to-list':
    add_to_list_command()

elif demisto.command() == 'proofpoint-tr-block-ip':
    block_ip_command()

elif demisto.command() == 'proofpoint-tr-block-domain':
    block_domain_command()

elif demisto.command() == 'proofpoint-tr-block-url':
    block_url_command()

elif demisto.command() == 'proofpoint-tr-block-hash':
    block_hash_command()

elif demisto.command() == 'proofpoint-tr-delete-indicator':
    delete_indicator_command()

elif demisto.command() == 'proofpoint-tr-search-indicator':
    search_indicator_command()
