import pytest

import demistomock as demisto
from CommonServerPython import *

from pathlib import Path

PATH = Path(__file__).parent / "test_data/valid_json.json"


from FlattenDictionary import flatten_dict

def test_flatten_dict():
    import json
    
    with PATH.open() as f:
        data = json.load(f)
        res = flatten_dict(data)
        assert res == {"a.b.c": "result", "a.d": "result2", "a.e":"result3"}