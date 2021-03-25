import datetime
import json

import demistomock as demisto  # noqa: F401
import pytz
import requests
from CommonServerPython import *  # noqa: F401

INDICATOR_TYPE_MAPPING = {
    'CIDR': 'CIDR',
    'CVE': "CVE",
    'domain': "Domain",
    'FileHash-IMPHASH': "File",
    'FileHash-MD5': "File MD5",
    'FileHash-PEHASH': "File",
    'FileHash-SHA1': "File SHA-1",
    'FileHash-SHA256': "File SHA-256",
    'IPv4': "IP",
    'IPv6': "IPv6",
    'URL': "URL"
}


def getIOCs(client, start_, end_, from_, type_, keyword_):
    today = datetime.datetime.now(pytz.timezone("Asia/Singapore")).strftime("%Y-%m-%d")
    one_day_ago = (datetime.datetime.now(pytz.timezone("Asia/Singapore")) - datetime.timedelta(days=1)).strftime("%Y-%m-%d")
    start_date = start_ if start_ else one_day_ago
    end_date = end_ if end_ else today
    from_index = int(from_)

    fetched_iocs = []
    payload = {
        "limit": 1000,
        "start_date": start_date,
        "end_date": end_date
    }
    if type_:
        payload['type'] = type_
    if keyword_:
        payload['keyword'] = keyword_

    count = 10000
    while from_index < count:
        payload["from"] = from_index
        res = client.request(payload)
        res = json.loads(res)
        # 1st call update count
        count = res['count']
        if 'results' in res:
            for record in res['results']:
                indicator = {}
                indicator_type = record.get('_source').get('type')
                indicator['type'] = INDICATOR_TYPE_MAPPING.get(indicator_type)
                indicator['value'] = record.get('_source').get('indicator')
                indicator['source'] = record.get('_source').get('references')
                indicator['expiration'] = (datetime.datetime.now(pytz.timezone("Asia/Singapore"))
                                           + datetime.timedelta(days=30)).strftime("%Y-%m-%d")
                indicator['reputation'] = 'bad'
                indicator['rawJSON'] = {
                    'value': record.get('_source').get('indicator'),
                    'type': INDICATOR_TYPE_MAPPING.get(indicator_type),
                    'reputation': 'bad'
                }
                fetched_iocs.append(indicator)
        from_index += 1000
    return fetched_iocs


def test_module(client):
    test_payload = {
        "limit": 20,
        "from": 0
    }
    try:
        res = client.request(test_payload)
        return 'ok'
    except Exception as err:
        return err


def main():
    params = demisto.params()
    CYBLE_URL = params.get('url')
    CYBLE_TOKEN = params.get('apikey')
    START = params.get('start')
    END = params.get('end')
    TYPE = params.get('type')
    KEYWORD = params.get('keyword')
    FROM = params.get('from')
    try:
        client = CybleClient(CYBLE_URL, CYBLE_TOKEN)
        if demisto.command() == 'test-module':
            demisto.results(test_module(client))
        elif demisto.command() == "fetch-indicators":
            fetched_iocs = getIOCs(client, START, END, FROM, TYPE, KEYWORD)
            for b in batch(fetched_iocs, batch_size=100):
                demisto.createIndicators(b)
        elif demisto.command() == "cyble-fetch-indicators":
            fetched_iocs = getIOCs(client, START, END, FROM, TYPE, KEYWORD)
            for b in batch(fetched_iocs, batch_size=100):
                demisto.createIndicators(b)
    except Exception as err:
        if isinstance(err, NotImplementedError) and COMMAND_NOT_IMPELEMENTED_MSG in str(err):
            raise
        return_error(str(err))

    finally:
        LOG.print_log()


class CybleClient:
    def __init__(self, url, apikey):
        self._url = url
        self._token = apikey
        self.iocs_url = url + "/iocs"

    def request(self, data, files=[]):
        headers = {
            "Cookie": "XSRF-TOKEN=" + self._token
        }
        data["token"] = self._token
        response = requests.request("POST", self.iocs_url, headers=headers, data=data, files=files)
        return response.text.encode("utf8")


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
