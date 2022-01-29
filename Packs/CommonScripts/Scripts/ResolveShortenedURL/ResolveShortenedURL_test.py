import demistomock as demisto
from ResolveShortenedURL import main, unshorten_using_requests
import io
import json


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_unshorten_using_requests(mocker):
    pass