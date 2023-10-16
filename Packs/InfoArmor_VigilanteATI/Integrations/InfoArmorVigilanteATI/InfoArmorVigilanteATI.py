import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import base64
import hashlib
import hmac
import json
import time

import requests
import urllib3

# disable insecure warnings
urllib3.disable_warnings()

BASE_URL = None
API_KEY = None
API_SECRET = None
VERIFY_SSL = None


def gen_hmac(method, timestamp, api_key, api_secret):
    """
    Generate HMAC string for VigilanteATI API service. The string is generated as follows:
    hmac('sha1', 'API_KEY' + 'TIMESTAMP' + 'METHOD_NAME', 'API_SECRET')
    """
    msg = f"{api_key}{timestamp}{method}{api_secret}".encode()
    hm = hmac.new(api_secret.encode(), msg, hashlib.sha1)
    return hm.hexdigest()


def http_request(method, url, hmac_url, params={}, data=None):
    if params is None:
        params = {}

    ts = int(time.time())
    hmacc = gen_hmac(hmac_url, ts, API_KEY, API_SECRET)

    fullurl = BASE_URL + url
    params['ts'] = ts
    params['key'] = API_KEY
    params['hmac'] = hmacc

    res = requests.request(
        method,
        fullurl,
        headers={
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        },
        params=params,
        verify=VERIFY_SSL,
        json=data
    )

    if res.status_code < 200 or res.status_code >= 300:
        return_error('Request failed.\nURL: {}\nStatusCode: {}\nResponse: \n{}'.format(fullurl, res.status_code, res.text))

    try:
        res.json()
    except Exception:
        return_error('Response failed, the response body is not json.\nURL: {}\nStatusCode: {}\nResponse: \n{}'.format(
            fullurl, res.status_code, res.text))

    return res


def query_infected_host_data(days_ago=None, limit=None, token=None, q_address=None, cc_ipaddress=None):
    params = {}
    if days_ago:
        params['days_ago'] = days_ago

    if limit:
        params['limit'] = limit

    if token:
        params['token'] = token

    if q_address:
        params['q_address'] = q_address

    if cc_ipaddress:
        params['cc_ipaddress'] = cc_ipaddress

    res = http_request('get', 'api/2/si/infected/query', 'si.infected.query', params)
    return res.json()


def query_infected_host_data_command(args):
    days_ago = args.get('days_ago')
    limit = args.get('limit')
    token = args.get('token')
    q_address = args.get('q_address')
    cc_ipaddress = args.get('cc_ipaddress')

    infected_hosts = query_infected_host_data(days_ago, limit, token, q_address, cc_ipaddress)
    markdown = tableToMarkdown('Infected hosts', infected_hosts.get('hosts'))
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': infected_hosts,
        'HumanReadable': markdown,
        'EntryContext': {
            'VigilanteATI.InfectedHost(val.ip == obj.ip)': infected_hosts.get('hosts'),
            'VigilanteATI.GetInfectedHostsToken(true==true)': infected_hosts.get('re_token')
        }
    })


def query_elasticsearch(max_rows, query):
    params = {}
    if max_rows:
        params['maxRows'] = max_rows

    if query:
        params['query'] = query

    res = http_request('get', 'api/1/es/fulltext/query', 'es.fulltext.query', params)
    return res.json()


def query_elasticsearch_command(args):
    max_rows = int(args.get('max_rows', 10))
    query = args.get('query')

    results = query_elasticsearch(max_rows, query)
    if len(results.get('results')) == 0:
        demisto.results('No results')

    markdown = tableToMarkdown('Elasticsearch Results', results.get('results'))

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': results,
        'HumanReadable': markdown,
        'EntryContext': {
            'VigilanteATI.ElasticsearchResults': results.get('results')
        }
    })


def search(query, days_ago, exact_match):
    params = {}
    if days_ago:
        params['daysAgo'] = days_ago

    if query:
        params['query'] = query

    if exact_match:
        params['exactMatch'] = exact_match

    res = http_request('get', 'api/1/fullext/query', 'fulltext.query', params)

    return res.json()


def search_command(args):
    days_ago = args.get('days_ago')
    query = args.get('query')
    exact_match = args.get('exact_match')

    results = search(query, days_ago, exact_match)
    if len(results.get('results')) == 0:
        demisto.results('No results')

    markdown = tableToMarkdown('Search Results', results.get('results'))

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': results,
        'HumanReadable': markdown,
        'EntryContext': {
            'SearchResults': results.get('results')
        }
    })


def get_vulnerable_host_data(limit, q_address, q_mask, q_type, re_token=None):
    params = {}
    if limit:
        params['limit'] = limit

    if q_address:
        params['q_address'] = q_address

    if q_mask:
        params['q_mask'] = q_mask

    if q_type:
        params['q_type'] = q_type

    if re_token:
        params['re_token'] = re_token

    res = http_request('get', 'api/2/vi/hosts/get', 'vi.hosts.get', params)
    return res.json()


def get_vulnerable_host_data_command(args):
    limit = int(args.get('limit', 100))
    q_address = args.get('q_address')
    q_mask = args.get('q_mask')
    q_type = args.get('q_type')

    raw_host_data = get_vulnerable_host_data(limit, q_address, q_mask, q_type)
    if len(raw_host_data.get('hosts')) == 0:
        demisto.results('No results')
        sys.exit(0)

    markdown = tableToMarkdown('Vulnerable host data from VI feed', raw_host_data.get('hosts'))

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': raw_host_data,
        'HumanReadable': markdown,
        'EntryContext': {
            'Hosts(val.ip === obj.ip)': raw_host_data.get('hosts')
        }
    })


def search_leaks(leak_id, days_ago, keyword, limit, token=None):
    """
    Retrieves the list of leaks from our database.
    """
    params = {}
    if leak_id:
        params['leakId'] = leak_id

    if days_ago:
        params['daysAgo'] = days_ago

    if keyword:
        params['keyword'] = keyword

    if limit:
        params['limit'] = limit

    if token:
        params['token'] = token

    res = http_request('get', 'api/1/leaks/info', 'leaks.info', params)
    return res.json()


def search_leaks_command(args):
    leak_id = args.get('leak_id')
    days_ago = args.get('days_ago')
    keyword = args.get('keyword')
    limit = int(args.get('limit', 20))
    token = args.get('token')

    raw_list_leaks = search_leaks(leak_id, days_ago, keyword, limit, token)
    markdown = tableToMarkdown('List of leaks', raw_list_leaks.get('leaks'), [
        'leak_id',
        'title',
        'leak_type',
        'score',
        'leak_date',
        'breach_date',
        'targets',
        'attackers',
        'num_entries',
        'password_type',
        'description',
        'source_refs',
        'attack_method',
        'target_industries',
        'media_refs',
        'password_hash',
        'num_domains_affected',
        'import_date'
    ])

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': raw_list_leaks,
        'HumanReadable': markdown,
        'EntryContext': {
            'VigilanteATI.LeakInfoToken(true==true)': raw_list_leaks.get('token'),
            'VigilanteATI.Leaks(val.leak_id === obj.leak_id)': raw_list_leaks.get('leaks')
        }
    })


def get_leak(leak_id, limit, domains, token):
    """
    Retrieve all the accounts related to this specific leak
    """
    params = remove_none_params({
        'leak_id': leak_id,
        'limit': limit,
        'domains': domains,
        'token': token
    })

    res = http_request('get', 'api/1/leaks/get', 'leaks.get', params)
    return res.json()


def get_leak_command(args):
    leak_id = args.get('leak_id')
    domains = args.get('domains')
    token = args.get('token')
    limit = int(args.get('limit', 20))

    leak = get_leak(leak_id, limit, domains, token)
    if not leak and len(leak.get('accounts')) == 0:
        demisto.results('Leak has no accounts related to it')
        sys.exit(0)

    accounts = leak.get('accounts')
    for i, _ in enumerate(accounts):
        account = accounts[i]
        account['email'] = account['plain']
        del account['plain']

    markdown = tableToMarkdown('Accounts related to leak {}'.format(
        leak_id), leak.get('accounts'), ['email', 'domain', 'password', 'type_id'])
    outputs = {
        'VigilanteATI.Leaks(val.leak_id === obj.leak_id)': {
            'leak_id': leak_id,
            'accounts': accounts
        }
    }
    if leak.get('token'):
        outputs['VigilanteATI.LeakAccountsToken(true==true)'] = leak.get('token')

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': leak,
        'HumanReadable': markdown,
        'EntryContext': outputs
    })


def remove_none_params(params_dict):
    """
    filter only the params that have values
    """
    return dict((k, v) for k, v in params_dict.items() if v is not None)


def query_ecrime_intelligence_database(query, q_forum, q_start_data, limit, re_token=None):
    params = remove_none_params({
        'query': query,
        'q_forum': q_forum,
        'q_start_data': q_start_data,
        'limit': limit,
        're_token': re_token
    })

    res = http_request('get', 'api/1/ecrime/posts/query', 'ecrime.posts.query', params)
    return res.json()


def query_ecrime_intelligence_database_command(args):
    query = args.get('query')
    q_forum = args.get('q_forum')
    q_start_data = args.get('q_start_data')
    limit = int(args.get('limit', 10))
    re_token = args.get('re_token')

    results = query_ecrime_intelligence_database(query, q_forum, q_start_data, limit, re_token)
    posts = results.get('posts')
    for post in posts:
        post['title'] = base64.b64decode(post['title']).decode('utf8')
        post['post'] = base64.b64decode(post['post']).decode('utf8')

    markdown = tableToMarkdown('ECrime Posts', posts)
    markdown += '\n**Total Count**: {}'.format(results.get('count'))
    markdown += '\n**Next Page Token**: \n{}'.format(results.get('re_token'))

    outputs = {
        'VigilanteATI.ECrimePosts': posts
    }
    if results.get('re_token'):
        outputs['VigilanteATI.ECrimeQueryToken(true==true)'] = results.get('re_token')

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': results,
        'HumanReadable': markdown,
        'EntryContext': outputs
    })


def query_accounts(account_identifier, limit, days_ago):
    if days_ago is not None:
        days_ago = int(days_ago)

    body = remove_none_params({
        'account_identifier': account_identifier,
        'limit': limit,
        'daysAgo': days_ago
    })

    res = http_request('post', 'api/3/accounts/query', 'accounts.query', None, data=body)
    return res.json()


def query_accounts_command(args):
    emails = argToList(args.get('emails'))
    days_ago = args.get('days_ago')
    limit = args.get('limit')

    results = query_accounts(emails, limit, days_ago)
    accounts = results.get('results')
    for i, _ in enumerate(accounts):
        account = accounts[i]
        account['email'] = account['plain']
        del account['plain']

    markdown = tableToMarkdown('Leaks related to email accounts \n{}'.format('\n'.join(emails)),
                               accounts, ['leak_id', 'email', 'password', 'source_type', 'type_id'])
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': results,
        'HumanReadable': markdown,
        'EntryContext': {
            'VigilanteATI.Account(val.email == obj.email && val.password == obj.password && val.leak_id && obj.leak_id)': accounts
        }
    })


def domain_info(domain_identifier, subdomains, days_ago):
    params = remove_none_params({
        'domain_identifier': domain_identifier,
        'subdomains': subdomains,
        'daysAgo': days_ago
    })

    res = http_request('get', 'api/1/domains/info', 'domains.info', params)
    domain_info = res.json()
    if not domain_info:
        return []

    if not isinstance(domain_info, list):
        # if it single object then return an array
        return [domain_info]

    return domain_info


def query_domains(domain, days_ago, limit, token=None):
    params = remove_none_params({
        'domain_identifier': domain,
        'limit': limit,
        'daysAgo': days_ago,
        'token': token
    })

    res = http_request('get', 'api/1/domains/query', 'domains.query', params)
    domains = res.json()
    return domains


def query_domains_command(args):
    domain = args.get('domain')
    limit = int(args.get('limit', 20))
    days_ago = args.get('days_ago')
    token = args.get('token')

    query_results = query_domains(domain, days_ago, limit, token)
    accounts = query_results.get('accounts')
    for i, _ in enumerate(accounts):
        account = accounts[i]
        account['email'] = account['plain']
        del account['plain']
    markdown = tableToMarkdown('Accounts related to domain: {}'.format(domain), accounts,
                               ['leak_id', 'email', 'password', 'source_type', 'type_id'])

    outputs = {
        'VigilanteATI.Domain(val.domain == obj.domain)': {
            'domain': query_results.get('domain_identifier'),
            'accounts': accounts
        }
    }
    if query_results.get('token'):
        outputs['DomainQueryToken'] = query_results.get('token')

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': query_results,
        'HumanReadable': markdown,
        'EntryContext': outputs
    })


def get_report(date, account_identifier, limit, token=None):
    params = remove_none_params({
        'date': date,
        'account_identifier': account_identifier,
        'limit': limit,
        'token': token
    })

    res = http_request('get', 'api/1/reports/get', 'reports.get', params)
    reports = res.json()
    return reports


def watchlist_add_accounts(account_identifiers, _type, tag):
    body = remove_none_params({
        'account_identifiers': account_identifiers,
        'type': _type,
        'tag': tag
    })

    params = {
        'account_identifiers': json.dumps(account_identifiers),
        'type': _type,
        'tag': tag
    }

    res = http_request('post', 'api/2/watchlist', 'watchlist.add', params, body)
    result = res.json()

    return result


def watchlist_add_accounts_command(args):
    account_identifiers = args.get('account_identifiers')
    if isinstance(account_identifiers, str):
        account_identifiers = account_identifiers.split(',')

    _type = args.get('type')
    tag = args.get('tag')

    result = watchlist_add_accounts(account_identifiers, _type, tag)
    markdown = ''
    added = result.get('added')
    already_on_watchlist = result.get('already on watchlist')
    invalid = result.get('invalid')

    if len(added) > 0:
        markdown += '### Added: {}\n\n'.format(','.join(added))

    if len(already_on_watchlist) > 0:
        markdown += '### Already on watchlist: {}'.format(','.join(already_on_watchlist))

    if len(invalid) > 0:
        markdown += '### Invalid: {}\n'.format(','.join(invalid))

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'HumanReadable': markdown
    })


def watchlist_remove_accounts(account_identifiers):
    params = remove_none_params({
        'account_identifiers': json.dumps(account_identifiers)
    })

    res = http_request('delete', 'api/2/watchlist', 'watchlist.remove', params)
    result = res.json()

    return result


def watchlist_remove_accounts_command(args):
    account_identifiers = args.get('account_identifiers')
    if isinstance(account_identifiers, str):
        account_identifiers = account_identifiers.split(',')

    result = watchlist_remove_accounts(account_identifiers)
    removed = result.get('removed')
    not_on_watchlist = result.get('not on watchlist')

    markdown = ''
    if len(removed) > 0:
        markdown += '### Removed: {}'.format(','.join(removed))

    if len(not_on_watchlist) > 0:
        markdown += '### Not on watchlist: {}'.format(','.join(not_on_watchlist))

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'HumanReadable': markdown
    })


def get_watchlist_accounts(limit, token=None):
    params = remove_none_params({
        'limit': limit,
        'token': token
    })

    res = http_request('get', 'api/2/watchlist', 'watchlist.info', params)
    reports = res.json()
    return reports


def get_watchlist_accounts_command(args):
    limit = int(args.get('limit', 20))
    token = args.get('token')

    watchlist = get_watchlist_accounts(limit, token)
    markdown = tableToMarkdown('Watchlist', watchlist.get('identifiers'))

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': watchlist,
        'HumanReadable': markdown,
        'EntryContext': {
            'VigilanteATI.WatchlistQueryToken(true==true)': watchlist.get('token'),
            'VigilanteATI.Watchlist(val.identifier == obj.identifier)': watchlist.get('identifiers')
        }
    })


def usage_info():
    res = http_request('get', 'api/1/usage/info', 'usage.info')
    usage = res.json()
    return usage


def usage_info_command():
    raw_usage = usage_info()
    usage = [{
        'Number of queries allowed': raw_usage.get('num_queries_allotted'),
        'Number of queries left': raw_usage.get('num_queries_left')
    }]
    markdown = tableToMarkdown('Usage Info', usage)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': usage,
        'HumanReadable': markdown
    })


def main():  # pragma: no coverage
    """
    main function, parses params and runs command functions
    """
    global BASE_URL, API_KEY, API_SECRET, VERIFY_SSL

    command = demisto.command()
    args = demisto.args()
    params = demisto.params()

    handle_proxy()

    BASE_URL = params.get('url')
    API_KEY = (params.get('apikey_new') or {}).get('password', '') or params.get('apikey')
    API_SECRET = (params.get('apisecret_new') or {}).get('password', '') or params.get('apisecret')
    VERIFY_SSL = not params.get('unsecure', False)

    if command == 'test-module':
        query_infected_host_data(
            days_ago=0,
            q_address='8.8.8.8',
            limit=1
        )
        usage_info()

        demisto.results('ok')
        sys.exit(0)

    if command == 'vigilante-query-infected-host-data':
        query_infected_host_data_command(args)
        sys.exit(0)

    elif command == 'vigilante-query-elasticsearch':
        query_elasticsearch_command(args)
        sys.exit(0)

    elif command == 'vigilante-search':
        search_command(args)
        sys.exit(0)

    elif command == 'vigilante-get-vulnerable-host-data':
        get_vulnerable_host_data_command(args)
        sys.exit(0)

    elif command == 'vigilante-search-leaks':
        search_leaks_command(args)
        sys.exit(0)

    elif command == 'vigilante-get-leak':
        get_leak_command(args)
        sys.exit(0)

    elif command == 'vigilante-query-ecrime-db':
        query_ecrime_intelligence_database_command(args)
        sys.exit(0)

    elif command == 'vigilante-query-accounts':
        query_accounts_command(args)
        sys.exit(0)

    elif command == 'vigilante-query-domains':
        query_domains_command(args)
        sys.exit(0)

    elif command == 'vigilante-watchlist-add-accounts':
        watchlist_add_accounts_command(args)
        sys.exit(0)

    elif command == 'vigilante-watchlist-remove-accounts':
        watchlist_remove_accounts_command(args)
        sys.exit(0)

    elif command == 'vigilante-get-watchlist':
        get_watchlist_accounts_command(args)
        sys.exit(0)

    elif command == 'vigilante-account-usage-info':
        usage_info_command()
        sys.exit(0)

    else:
        demisto.results('Command not implement yet')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
