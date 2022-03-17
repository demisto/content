import io
import pytest
from CommonServerPython import *
import CortexXDRIdentityInformationWidget


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.mark.parametrize('context_data, expected_result', [
    (util_load_json('test_data/context_data1.json'), util_load_json('test_data/expected_results1.json')),
    (util_load_json('test_data/context_data2.json'), util_load_json('test_data/expected_results2.json'))
])
def test_additional_info(mocker, context_data, expected_result):
    mocker.patch.object(demisto, 'context', return_value=context_data)
    results = CortexXDRIdentityInformationWidget.get_identity_info()
    for actual_res, expected_res in zip(results, expected_result):
        actual_access_keys = actual_res.pop('Access Keys')
        expected_access_keys = expected_res.pop('Access Keys')
        assert actual_res == expected_res
        assert set(actual_access_keys) == set(expected_access_keys)  # the sorting of the access keys doesn't matter
