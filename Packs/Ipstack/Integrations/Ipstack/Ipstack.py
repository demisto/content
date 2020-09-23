import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import os
import requests

BASE_URL = 'http://api.ipstack.com'
API_KEY = demisto.params().get('apikey')

if not demisto.params()['proxy']:
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

''' HELPER FUNCTIONS '''
# #returns a result of a api call


def http_request(method, path):
    """
    HTTP request helper function
    """
    url = BASE_URL + path
    res = requests.request(
        method=method,
        url=url
    )

    if not res.ok:
        txt = 'error in URL {} status code: {} reason: {}'.format(url, res.status_code, res.text)
        demisto.error(txt)
        raise Exception(txt)

    try:
        res_json = res.json()
        if res_json.get('code'):
            txt = 'error in URL {} status code: {} reason: {}'.format(url, res.status_code, res.text)
            demisto.error(txt)
            raise Exception(txt)
        else:
            return res_json

    except Exception as ex:
        demisto.debug(str(ex))
        demisto.results({"Type": entryTypes["error"], "ContentsFormat": formats["text"], "Contents": res.text})


''' Commands '''


def do_ip(ip):
    path = "/{}?access_key={}".format(ip, API_KEY)
    return http_request('GET', path)


def do_ip_command():
    ip = demisto.args().get('ip')
    raw_response = do_ip(ip)
    human_readable_data = {
        "Address": raw_response.get('ip'),
        "Country": raw_response.get('country_name'),
        "Latitude": raw_response.get('latitude'),
        "Longitude": raw_response.get('longitude')
    }

    outputs = {
        'IP(val.Address == obj.Address)': {
            'Address': raw_response.get('ip'),
            'Geo': {
                'Location': "{},{}".format(raw_response.get('latitude'), raw_response.get('longitude')),
                'Country': raw_response.get('country_name')
            }
        },
        'Ipstack.ip(val.ID==obj.ID)': {
            'address': raw_response.get('ip'),
            'type': raw_response.get('type'),
            'continent_name': raw_response.get('continent_name'),
            'latitude': raw_response.get('latitude'),
            'longitude': raw_response.get('longitude'),
        }
    }

    headers = ['Address', 'Country', 'Latitude', 'Longitude']
    human_readable = tableToMarkdown('Ipstack info on {}'.format(raw_response.get('ip')), human_readable_data, headers=headers)
    return_outputs(human_readable, outputs, raw_response)


def test_module():
    path = "/1.2.3.4?access_key={}".format(API_KEY)
    res = requests.request('GET', BASE_URL + path)
    if res.json().get('ip') == '1.2.3.4':
        demisto.results('ok')
    else:
        demisto.results('an error occurred. reason: {}'.format(res.text))


try:
    if demisto.command() == 'test-module':
        test_module()
    elif demisto.command() == 'ip':
        do_ip_command()
except Exception as e:
    return_error('Unable to perform command : {}, Reason: {}'.format(demisto.command, e))
