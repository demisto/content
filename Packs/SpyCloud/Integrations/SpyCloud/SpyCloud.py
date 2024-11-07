import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests
import urllib3

# Disable insecure warning
urllib3.disable_warnings()

BASE_URL = demisto.params().get('url')
API_KEY = demisto.params().get('apikey')
headers = {
    'X-Api-Key': API_KEY
}

"""MAIN FUNCTIONS"""


def download_data(URL_SUFFIX, cursor=' '):
    """ General download function for Spycloud breach data. Cannot be used for catalog """

    jdata = requests.get(URL_SUFFIX + "&cursor=" + str(cursor), headers=headers, timeout=10).json()

    return jdata


def get_breach_data():
    """Func to get a specific breach SpyCloud has"""
    breach_id = demisto.args().get('id')

    # form the URL with the arguments and execute GET request
    URL_SUFFIX = BASE_URL + "breach/catalog/{}".format(breach_id)
    resp = requests.get(URL_SUFFIX, headers=headers, timeout=30)
    jdata = resp.json()

    breachdata = []
    for r in jdata['results']:
        t = dict()
        t['uuid'] = transform(r, 'uuid')
        t['spycloud_publish_date'] = transform(r, 'spycloud_publish_date')
        t['num_records'] = transform(r, 'num_records')
        t['title'] = transform(r, 'title')
        t['type'] = transform(r, 'type')
        t['description'] = transform(r, 'description')
        t['site'] = transform(r, 'site')
        t['id'] = transform(r, 'id')
        t['acquisition_date'] = transform(r, 'acquisition_date')
        breachdata.append(t)

    command_results = CommandResults(
        outputs_prefix='SpyCloud.Breaches',
        outputs_key_field='uuid',
        outputs=breachdata
    )
    return command_results


def list_breaches():
    """Func to list the general breaches SpyCloud identifies"""
    since = demisto.args().get('since')
    until = demisto.args().get('until')
    query = demisto.args().get('query')

    # form the URL with the arguments and execute GET request
    if query == "empty":
        URL_SUFFIX = BASE_URL + "breach/catalog?&since={}&until={}".format(
            since, until
        )
    else:
        URL_SUFFIX = BASE_URL + "breach/catalog?&since={}&until={}&query={}".format(
            since, until, query
        )
    resp = requests.get(URL_SUFFIX, headers=headers, timeout=10)
    jdata = resp.json()

    breachdata = []
    for r in jdata['results']:
        t = dict()
        t['uuid'] = transform(r, 'uuid')
        t['spycloud_publish_date'] = transform(r, 'spycloud_publish_date')
        t['num_records'] = transform(r, 'num_records')
        t['title'] = transform(r, 'title')
        t['type'] = transform(r, 'type')
        t['description'] = transform(r, 'description')
        t['site'] = transform(r, 'site')
        t['id'] = transform(r, 'id')
        t['acquisition_date'] = transform(r, 'acquisition_date')
        breachdata.append(t)

    command_results = CommandResults(
        outputs_prefix='SpyCloud.Breaches',
        outputs_key_field='uuid',
        outputs=breachdata
    )

    return command_results


def get_domain_data():
    """Get all the messages from the domain monitored"""
    domain = demisto.args().get('domain')
    type_search = demisto.args().get('type')
    severity = demisto.args().get('severity')
    since = demisto.args().get('since')

    URL_SUFFIX = BASE_URL + \
        "breach/data/domains/{}/?type={}&severity={}&since={}".format(
            domain, type_search, severity, since
        )
    sc_data = []
    cursor = ' '
    total_records = download_data(URL_SUFFIX)['hits']
    total_queries = -(-total_records // 1000)

    for i in range(total_queries):
        data = download_data(URL_SUFFIX, cursor=cursor)
        cursor = data["cursor"]
        if "hits" in data and "results" in data:
            sc_results = data["results"]
            sc_data.extend(sc_results)

    spydata = []
    for r in sc_data:
        t = dict()
        t['document_id'] = transform(r, 'document_id')
        t['spycloud_publish_date'] = transform(r, 'spycloud_publish_date')
        t['username'] = transform(r, 'username')
        t['email'] = transform(r, 'email')
        t['target_domain'] = transform(r, 'target_domain')
        t['infected_time'] = transform(r, 'infected_time')
        t['source_id'] = transform(r, 'source_id')
        t['password_plaintext'] = transform(r, 'password_plaintext')
        spydata.append(t)

    command_results = CommandResults(
        outputs_prefix='SpyCloud.Results',
        outputs_key_field='document_id',
        outputs=spydata
    )

    return command_results


def get_email_data():
    """Get all the data for one email address"""
    emailaddr = demisto.args().get('emailaddr')
    breach_id = demisto.args().get('breach_id')
    severity = demisto.args().get('severity')
    since = demisto.args().get('since')
    until = demisto.args().get('until')

    URL_SUFFIX = BASE_URL + \
        "breach/data/emails/{}?since={}".format(
            emailaddr, since
        )
    if severity != "empty":
        URL_SUFFIX + "&severity={}".format(severity)
    if until != "empty":
        URL_SUFFIX + "&until={}".format(until)
    if breach_id != "empty":
        URL_SUFFIX + "&source_id={}".format(breach_id)

    sc_data = []
    cursor = ' '
    total_records = download_data(URL_SUFFIX)['hits']
    total_queries = -(-total_records // 1000)

    while cursor:
        for i in range(total_queries):
            data = download_data(URL_SUFFIX, cursor=cursor)
            cursor = data["cursor"]
            if "hits" in data and "results" in data:
                sc_data.extend(data["results"])

    spydata = []
    for r in sc_data:
        t = dict()
        t['document_id'] = transform(r, 'document_id')
        t['spycloud_publish_date'] = transform(r, 'spycloud_publish_date')
        t['username'] = transform(r, 'username')
        t['email'] = transform(r, 'email')
        t['source_id'] = transform(r, 'source_id')
        t['domain'] = transform(r, 'domain')
        t['user_browser'] = transform(r, 'user_browser')
        t['password'] = transform(r, 'password_plaintext')
        t['target_url'] = transform(r, 'target_url')
        spydata.append(t)

    command_results = CommandResults(
        outputs_prefix='SpyCloud.Emails',
        outputs_key_field='document_id',
        outputs=spydata
    )
    return command_results


def get_watchlist_data():
    """Get all the data for watchlists """
    watchlist_type = demisto.args().get('watchlist_type')
    type_search = demisto.args().get('type')
    breach_id = demisto.args().get('breach_id')
    since = demisto.args().get('since')
    until = demisto.args().get('until')

    URL_SUFFIX = BASE_URL + \
        "breach/data/watchlist?watchlist_type={}&since={}&type={}".format(
            watchlist_type, since, type_search
        )
    if until != "empty":
        URL_SUFFIX + "&until={}".format(until)
    if breach_id != "empty":
        URL_SUFFIX + "&source_id={}".format(breach_id)

    sc_data = []
    cursor = ' '
    total_records = download_data(URL_SUFFIX)['hits']
    total_queries = -(-total_records // 1000)

    while cursor:
        for i in range(total_queries):
            data = download_data(URL_SUFFIX, cursor=cursor)
            cursor = data["cursor"]
            if "hits" in data and "results" in data:
                sc_data.extend(data["results"])

    spydata = []
    for r in sc_data:
        t = dict()
        t['document_id'] = transform(r, 'document_id')
        t['spycloud_publish_date'] = transform(r, 'spycloud_publish_date')
        t['username'] = transform(r, 'username')
        t['breach_id'] = transform(r, 'source_id')
        t['password'] = transform(r, 'password')
        t['target_url'] = transform(r, 'target_url')
        t['email'] = transform(r, 'email')
        t['domain'] = transform(r, 'domain')
        spydata.append(t)

    command_results = CommandResults(
        outputs_prefix='SpyCloud.Watchlist',
        outputs_key_field='document_id',
        outputs=spydata
    )

    return command_results


def transform(spydata, key):

    if key in spydata.keys():
        transformed_data = spydata[key]
    else:
        transformed_data = "empty"

    return transformed_data


def test_module():
    """Simple test function to verify it works from the BYOI screen"""
    URL_SUFFIX = BASE_URL + "breach/catalog"
    resp = requests.get(URL_SUFFIX, headers=headers, timeout=30)
    if resp.status_code == 200:
        demisto.results('ok')
    else:
        demisto.results('not ok')


def main():
    """ EXECUTION """
    try:
        if demisto.command() == 'spycloud-list-breaches':
            return_results(list_breaches())
        elif demisto.command() == 'spycloud-domain-data':
            return_results(get_domain_data())
        elif demisto.command() == 'spycloud-get-breach-data':
            return_results(get_breach_data())
        elif demisto.command() == 'spycloud-email-data':
            return_results(get_email_data())
        elif demisto.command() == 'spycloud-watchlist-data':
            return_results(get_watchlist_data())
        elif demisto.command() == 'test-module':
            test_module()
    except Exception as e:
        demisto.debug(f'exception was thrown: {e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
