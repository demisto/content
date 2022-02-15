import io
import pytest
import json
from CommonServerPython import *
import CortexXDRRemediationActionsWidget


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.mark.parametrize('context_data, expected_result', [
    (util_load_json('test_data/context_data1.json'), util_load_json('test_data/expected_results1.json')),
    (util_load_json('test_data/context_data2.json'), util_load_json('test_data/expected_results2.json'))
])
def test_remediation_info(mocker, context_data, expected_result):
    mocker.patch.object(demisto, 'context', return_value=context_data)
    mocker.patch.object(CortexXDRRemediationActionsWidget, 'indicators_value_to_clickable',
                        side_effect=lambda x: {a: a for a in x})
    results = CortexXDRRemediationActionsWidget.get_remediation_info()
    assert len(expected_result.keys()) == len(results.keys())
    for expected_key, expected_value in expected_result.items():
        assert expected_key in results
        assert set(results[expected_key]) == set(expected_value)
