
import io
import pytest
from CommonServerPython import *
import CortexXDRAdditionalAlertInformationWidget


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.mark.parametrize('context_data, expected_result', [
    (util_load_json('test_data/context_data1.json'), util_load_json('test_data/expected_results1.json')),
    (util_load_json('test_data/context_data2.json'), util_load_json('test_data/expected_results2.json'))
])
def test_additional_info(mocker, context_data, expected_result):
    mocker.patch.object(demisto, 'context', return_value=context_data)
    mocker.patch.object(CortexXDRAdditionalAlertInformationWidget, 'indicators_value_to_clickable',
                        side_effect=lambda x: {a: a for a in x})
    results = CortexXDRAdditionalAlertInformationWidget.get_additonal_info()
    assert results == expected_result
