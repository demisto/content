"""Base Script for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

"""

import io
from CommonServerPython import *
import CortexXDRCloudProviderWidget
import pytest


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.mark.parametrize('incident_data, expected_result', [
    (util_load_json('test_data/incident_data.json'), {'AWS'}),
    (util_load_json('test_data/multi_clouds_incident_data.json'), {'AWS', 'GCP', 'Azure'})
])
def test_cloud_provider(mocker, incident_data, expected_result):
    mocker.patch.object(demisto, 'incident', return_value=incident_data)
    results = CortexXDRCloudProviderWidget.get_cloud_providers()
    assert set(results) == expected_result
