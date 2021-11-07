"""Base Script for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

"""

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
    mocker.patch.object(CortexXDRAdditionalAlertInformationWidget, 'indicator_to_clickable', side_effect=lambda x: x)

    results = CortexXDRAdditionalAlertInformationWidget.get_additonal_info()
    assert results == expected_result
