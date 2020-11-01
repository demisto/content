import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests
from bs4 import BeautifulSoup
from base64 import b64decode, b64encode
from Crypto.PublicKey import RSA  # nosec
from Crypto.Cipher import PKCS1_v1_5  # nosec

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

USERNAME = demisto.params().get('username')
PASSWORD = demisto.params().get('password')
URL = demisto.params().get('url')

USE_SSL = False


def logout_traps():
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/74.0.3729.131 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,"
                  "application/signed-exchange;v=b3",
        "Accept-Language": "Accept-Language:en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate"
    }
    result = requests.request('GET', URL + '/EndpointSecurityManager/Account/Logout',
                              headers=headers, verify=USE_SSL)
    c = result.content
    demisto.results(c)


def get_new_request_token(cookies):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/74.0.3729.131 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,"
                  "application/signed-exchange;v=b3",
        "Accept-Language": "Accept-Language:en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate"
    }
    result = requests.request('GET', URL + '/EndpointSecurityManager/HashManagement/Hashes',
                              headers=headers, verify=USE_SSL, cookies=cookies)
    # Extracting Token
    c = result.content
    request_verification_token = None

    soup = BeautifulSoup(c, 'html.parser')
    request_verification_obj = soup.find('input', {"name": "__RequestVerificationToken"})
    request_verification_token = request_verification_obj['value']
    return request_verification_token


def get_ct_cookie():
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/74.0.3729.131 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,"
                  "application/signed-exchange;v=b3",
        "Accept-Language": "Accept-Language:en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate"
    }
    result = requests.request('GET', URL + '/EndpointSecurityManager/Account/Login',
                              headers=headers, verify=USE_SSL)
    # Extracting Token
    c = result.content
    soup = BeautifulSoup(c, 'html.parser')
    request_verification_obj = soup.find('input', {"name": "__RequestVerificationToken"})
    request_verification_token = request_verification_obj['value']

    # Extracting Cookie
    cookie_dough = result.cookies
    ct_value = None
    for cookie in cookie_dough:
        baked_cookie = cookie.__dict__
        if baked_cookie['name'] == 'ct':
            ct_value = baked_cookie['value']
    return request_verification_token, ct_value


def get_rsa_csid_key(request_verification_token, ct_value):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/74.0.3729.131 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,"
                  "application/signed-exchange;v=b3",
        "Accept-Language": "Accept-Language:en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "token": request_verification_token
    }
    cookies = {'ct': ct_value}
    result = requests.request('POST', URL + '/EndpointSecurityManager/Account/PublicKey',
                              headers=headers, cookies=cookies, verify=USE_SSL)
    # Extracting Cookie
    cookie_dough = result.cookies
    csid = None
    for cookie in cookie_dough:
        baked_cookie = cookie.__dict__
        if baked_cookie['name'] == 'csid':
            csid = baked_cookie['value']
    # Extracting RSA
    key = result.json().get('key')
    salt = result.json().get('salt')
    return key, salt, csid


def bytes_to_integer(data):
    output = 0
    size = len(data)
    for index in range(size):
        output |= data[index] << (8 * (size - 1 - index))
    return output


def get_auth_cookie():
    request_verification_token, ct_value = get_ct_cookie()
    key, salt, csid = get_rsa_csid_key(request_verification_token, ct_value)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/74.0.3729.131 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,"
                  "application/signed-exchange;v=b3",
        "Accept-Language": "Accept-Language:en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "token": request_verification_token
    }
    cookies = {
        'ct': ct_value,
        'csid': csid
    }
    salted_password = (salt + PASSWORD).encode()

    keyDER = b64decode(key)
    keyPub = RSA.importKey(keyDER)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_v1_5.new(keyPub)
    encrypted_pass = cipher_rsa.encrypt(salted_password)
    b64pass = b64encode(encrypted_pass)

    payload = {
        "Username": USERNAME,
        "Password": b64pass
    }
    result = requests.request('POST', URL + '/EndpointSecurityManager/Account/Login',
                              headers=headers, cookies=cookies, data=payload, verify=USE_SSL)
    # Extracting Cookie
    cookie_dough = result.cookies
    csid = None
    for cookie in cookie_dough:
        baked_cookie = cookie.__dict__
        if baked_cookie['name'] == 'auth':
            cookies['auth'] = baked_cookie['value']
    return request_verification_token, cookies


def traps_esm_hash_detail():
    request_verification_token, cookies = get_auth_cookie()
    file_hash = demisto.args().get('hash')
    token = get_new_request_token(cookies)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/74.0.3729.131 Safari/537.36",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Accept-Language": "Accept-Language:en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Referer": URL + "/EndpointSecurityManager/HashManagement/Hashes",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": URL,
        "Content-Type": "application/json; charset=UTF-8",
        "Token": token
    }
    payload_raw = {
        'hash': file_hash
    }

    payload = json.dumps(payload_raw)

    auth_cookie = {
        'ct': cookies['ct'],
        'csid': cookies['csid'],
        'auth': cookies['auth']
    }

    result = requests.request('POST', URL + '/EndpointSecurityManager/HashManagement/HashesDetail',
                              headers=headers, cookies=auth_cookie, data=payload, verify=USE_SSL)

    hash_results = json.loads(result.content)

    hr_table = {
        'Result': hash_results['LocalAnalysis'][0]['Result'],
        'Verdict History': hash_results['VerdictHistory'],
        'Quarantined': hash_results['Quarantined']
    }

    ec = {
        'TrapsESM': hash_results
    }

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': 'The verdict of hash {} is {}'.format(file_hash, hash_results['LocalAnalysis'][0]['Result']),
        'HumanReadable': tableToMarkdown('Hash Verdict for {}'.format(file_hash), hr_table),
        'EntryContext': ec
    })


def traps_esm_override_hash_verdict():
    request_verification_token, cookies = get_auth_cookie()
    token = get_new_request_token(cookies)
    file_hash = demisto.args().get('hash')
    verdict = demisto.args().get('verdict')
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/74.0.3729.131 Safari/537.36",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Accept-Language": "Accept-Language:en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": URL,
        "Content-Type": "application/json; charset=UTF-8",
        "token": token
    }
    payload = {
        'request': [file_hash],
        'verdict': verdict
    }

    result = requests.request('POST', URL + '/EndpointSecurityManager/HashManagement/OverrideHashVerdict',
                              headers=headers, cookies=cookies, data=payload, verify=USE_SSL)

    demisto.results(result.content)


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))

try:
    if demisto.command() == 'test-module':
        auth_cookie = get_auth_cookie()
        if auth_cookie:
            demisto.results('ok')
    elif demisto.command() == 'traps-esm-hash-detail':
        traps_esm_hash_detail()
    elif demisto.command() == 'traps-esm-override-hash-verdict':
        traps_esm_override_hash_verdict()

# Log exceptions
except Exception as e:
    LOG(str(e))
    LOG.print_log()
    raise
