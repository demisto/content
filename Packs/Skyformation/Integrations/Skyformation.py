import requests

requests.packages.urllib3.disable_warnings()

if not demisto.params()['proxy']:
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

# removes the last / from the url


def fix_url(url):
    if url.endswith("/"):
        return url[:-1]

    return url


USERNAME = demisto.params()['credentials']['identifier']
PASSWORD = demisto.params()['credentials']['password']
SERVER_URL = fix_url(demisto.params()['url'])
INSECURE = demisto.params().get('insecure')


def get_accounts_request():
    fullurl = '{}{}'.format(SERVER_URL, '/openapi/api/rest/v1/accounts')
    res = requests.get(fullurl, auth=(USERNAME, PASSWORD), verify=(not INSECURE))
    if res.status_code < 200 or res.status_code >= 300:
        raise Exception('Failed to get accounts. Status Code: {}'.format(res.status_code))

    return res.json()


def get_accounts():
    accounts = get_accounts_request()
    context = accounts
    accountsToContext = []
    for account in accounts:
        accountsToContext.append({
            'Id': account['id'],
            'Name': account['name'],
            'Application': account['application'],
            'TenantId': demisto.dt(account, 'tenant.id'),
            'TenantName': demisto.dt(account, 'tenant.name')
        })
    hr = tableToMarkdown('Accounts', accountsToContext, ['Application', 'Name', 'Id', 'TenantName', 'TenantId'])
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': accounts,
        'HumanReadable': hr,
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': {
            'Skyformation.Account(val.Id==obj.Id)': accountsToContext
        }
    })

# suspend_or_unsuspend_user_request will suspend user if suspend=True, otherwise it will un-suspend user


def suspend_or_unsuspend_user_request(suspend, account_id, user_email):
    query_params = {
        'userAttributeName': 'email',
        'userAttributeValue': user_email
    }

    fullurl = ''.join([
        SERVER_URL,
        '/openapi/api/rest/v1/remediation/',
        account_id,
        '/suspend-user' if suspend == True else '/un-suspend-user'
    ])
    demisto.info(fullurl)
    res = requests.post(fullurl, auth=(USERNAME, PASSWORD), verify=(not INSECURE), params=query_params)
    if res.status_code < 200 or res.status_code >= 300:
        raise Exception('Failed to get accounts.\nStatus Code: {}\nResponse Body: {}'.format(res.status_code, res.text))

    return res.json()


def suspend_user():
    account_id = demisto.args().get('accountId')
    user_email = demisto.args().get('userEmail')
    res = suspend_or_unsuspend_user_request(True, account_id, user_email)
    if not res['is-success']:
        demisto.results({
            'Type': entryTypes['error'],
            'ContentsFormat': formats['text'],
            'Contents': res['status-message']
        })
        return

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': res,
        'HumanReadable': user_email + ' was suspended successfully',
        'ReadableContentsFormat': formats['markdown']
    })


def unsuspend_user():
    account_id = demisto.args().get('accountId')
    user_email = demisto.args().get('userEmail')
    res = suspend_or_unsuspend_user_request(False, account_id, user_email)
    if not res['is-success']:
        demisto.results({
            'Type': entryTypes['error'],
            'ContentsFormat': formats['text'],
            'Contents': res['status-message']
        })
        return

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': res,
        'HumanReadable': user_email + ' was un-suspended successfully',
        'ReadableContentsFormat': formats['markdown']
    })


# The command demisto.command() holds the command sent from the user.
if demisto.command() == 'test-module':
    get_accounts_request()
    demisto.results('ok')
    sys.exit(0)
if demisto.command() == 'skyformation-get-accounts':
    get_accounts()
    sys.exit(0)
if demisto.command() == 'skyformation-suspend-user':
    suspend_user()
    sys.exit(0)
if demisto.command() == 'skyformation-unsuspend-user':
    unsuspend_user()
    sys.exit(0)
