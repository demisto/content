"""
    QRadar_V3 integration for Cortex XSOAR - Unit Tests file
"""
import io
import json

import pytest
from QRadar_v3 import USECS_ENTRIES_MAPPING
from QRadar_v3 import convert_epoch_time_to_datetime, add_iso_entries_to_dict


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.mark.parametrize('epoch_time, expected',
                         [(0, None),
                          (None, None),
                          (1600000000000000, '2020-09-13T12:26:40+00:00')
                          ])
def test_convert_epoch_time_to_datetime_valid_cases(epoch_time, expected):
    """
    Given:
     - Time to be converted to date time in UTC timezone.

    When:
     - Case a: Epoch time is 0.
     - Case b: Epoch time is not given.
     - Case c: Valid epoch time is given.

    Then:
     - Case a: Ensure None is returned.
     - Case b: Ensure None is returned.
     - Case c: Ensure the corresponding date time string is returned.
    """
    assert convert_epoch_time_to_datetime(epoch_time) == expected


def test_add_iso_entries_to_dict():
    """
    Given:
     - Dict containing entries with epoch time.

    When:
     - Adding to entries with epoch time entries with iso time.

    Then:
     - All 'usecs' keys in the dict are replaced with 'iso time' entries with correct iso values.
    """
    tested_dict = {usec_entry: 1600000000000000 for usec_entry in USECS_ENTRIES_MAPPING.keys()}
    tested_dict['host_name'] = 'Nutanix Host'
    add_iso_entries_to_dict([tested_dict])
    assert tested_dict['host_name'] == 'Nutanix Host'
    assert all(
        tested_dict.get(iso_entry) == '2020-09-13T12:26:40+00:00' for iso_entry in USECS_ENTRIES_MAPPING.values())
    assert len(tested_dict) == (1 + (len(USECS_ENTRIES_MAPPING) * 2))
