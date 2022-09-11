import demistomock as demisto
from CommonServerPython import *
import json
import re
import tempfile
from datetime import datetime

from stix.core import STIXPackage


PATTERNS_DICT = {
    "file:": FeedIndicatorType.File,
    "ipv6": FeedIndicatorType.IPv6,
    "ipv4-addr:": FeedIndicatorType.IP,
    "url:": FeedIndicatorType.URL,
    "domain-name:": FeedIndicatorType.Domain,
    "email": FeedIndicatorType.Email,
    "registry-key:key": FeedIndicatorType.Registry,
    "account": FeedIndicatorType.Account,
}


def convert_to_json(string):
    """Will try to convert given string to json.

    Args:
        string: str of stix/json file. may be xml, then function will fail

    Returns:
        json object if succeed
        False if failed
    """
    try:
        js = json.loads(string)
        return js
    except ValueError:
        return None


def parse_stix2(js_content):
    pass


def create_indicator_entry(
        indicator_type,
        value,
        pkg_id,
        ind_id,
        timestamp,
        source=None,
        score=None,
):
    """Creating a JSON object of given args

    Args:
        indicator_type: (str) indicator type
        value: (str) indicator value
        pkg_id: (str) package id
        ind_id: (str) indicator id
        timestamp: (str) timestamp
        source: (str) source of indicator (custom field)
        score: (str) score of indicator (custom field)

    Returns:
        dict:
            {
                "indicator_type": indicator_type,
                "value": value,
                "CustomFields": {
                    "indicatorId": ind_id,
                    "stixPackageId": pkg_id
                }
                "source": ind_id.split("-")[0] or source if provided
                "score": if source is "DBot" then score should be here.
            }
    """
    entry = dict()
    entry["indicator_type"] = indicator_type
    entry["value"] = value
    entry["CustomFields"] = {"indicatorId": ind_id, "stixPackageId": pkg_id}
    entry["source"] = source if source else ind_id.split("-")[0]
    entry["score"] = score
    # Times
    entry["timestamp"] = timestamp
    return entry


def main():
    args = demisto.args()

    indicator_txt = args.get('ioc_txt')
    entry_id = args.get('entry_id')

    if not indicator_txt and not entry_id:
        raise Exception('You must enter ioc_txt or entry_id of the Indicator.')
    elif entry_id:
        file_path = demisto.getFilePath(entry_id).get('path')
        with open(file_path, 'rb') as f:
            content = f.read()
    else:
        content = indicator_txt.encode('utf-8')

    if stix2 := convert_to_json(content):
        indicators = parse_stix2(stix2)
    else:
        with tempfile.NamedTemporaryFile() as temp:
            temp.write(demisto.args()["iocXml"].encode("utf-8"))
            temp.flush()
            stix_package = STIXPackage.from_xml(temp.name)

    stix_id = stix_package.id_
    if stix_package.indicators:
        for ind in stix_package.indicators:
            pass

from TAXII2ApiModule import *

if __name__ in ('__builtin__', 'builtins'):
    main()
