from CommonServerPython import *
import json
import io
import knowbe4Phisher as ph
import pytest

client = ph.Client(base_url='dummy_url', verify=False, headers='some header')

fetch_parameters = [
    ({'first_fetch':'7 days','max_fetch':'50'})
    #({'first_fetch':'3 days','max_fetch':'10'})
]

@pytest.mark.parametrize("test_input,expected", [("3+5", 8), ("2+4", 6), ("6*9", 54)])
def test_eval(test_input, expected):
    assert eval(test_input) == expected

@pytest.mark.parametrize("params", fetch_parameters)
def test(params):
    assert params['first_fetch'] == '7 days'
    assert params['max_fetch'] == '50'