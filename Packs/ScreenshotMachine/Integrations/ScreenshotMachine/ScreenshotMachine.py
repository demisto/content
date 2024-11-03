import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import hashlib
from io import BytesIO
import traceback
import requests


API_KEY = demisto.params().get('apikey')


def site_lookup(params):
    api_url = "http://api.screenshotmachine.com"
    r = requests.get(api_url, params=params, allow_redirects=True)

    if r.status_code < 200 or r.status_code >= 300:
        return_error(
            f'Failed to update Content.\nURL: {api_url}, Status Code: {r.status_code}, Response: {r.text}'
        )

    return r


def decode_screenshot(r):
    i = BytesIO(r.content)
    res = fileResult('myfile', i.read(), file_type=EntryType.IMAGE)

    return res


def generateHash(url, secretKey):
    string_to_hash = url + secretKey
    return hashlib.md5(string_to_hash.encode('utf-8')).hexdigest()  # nosec


def get_screenshot(argDict):
    md5Secret = argDict.get('md5Secret', "")
    url = argDict.get("url")
    md5Hash = generateHash(url, md5Secret)

    params = {
        "url": url,
        "key": API_KEY,
        "dimension": argDict.get('dimension'),
        "device": argDict.get('device'),
        "format": 'jpg',
        "hash": md5Hash,
        "cacheLimit": argDict.get('cacheLimit'),
        "delay": argDict.get('delay')
    }

    screenshot = site_lookup(params)

    return screenshot


def main():
    try:
        if demisto.command() == 'test-module':
            argDict = demisto.args()
            argDict['url'] = "https://paloaltonetworks.com"
            get_screenshot(argDict)
            demisto.results("ok")

        elif demisto.command() == 'screenshot-machine-get-screenshot':
            argDict = demisto.args()
            raw_screenshot = get_screenshot(argDict)
            screenshot = decode_screenshot(raw_screenshot)
            demisto.results(screenshot)

        else:
            return_error('Command not found.')

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
