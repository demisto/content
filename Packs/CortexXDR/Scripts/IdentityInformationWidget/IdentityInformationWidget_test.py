"""Base Script for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

"""

from CommonServerPython import *
from IdentityInformationWidget import get_identity_info
import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_access_keys(mocker):
    mocker.patch.object(demisto, 'context', return_value=util_load_json('test_data/context_data.json'))
    get_identity_info()