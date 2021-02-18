from __future__ import print_function
import pytest
from PositiveDetectionsVSDetectionEngines import extract_engines_data_from_indicator

'''INDICATORS DATA FOR TESTING'''

detect_positive_not_zero_1 = {
    'CustomFields': {
        'detectionengines': 71,
        'positivedetections': 10
    },
    'ManuallyEditedFields': None,
    'account': '',
    'calculatedTime': '2019-11-11T14:17:11.846266+02:00',
    'comment': '',
    'context': [
        {
            'URL(val.Data && val.Data === obj.Data)': {'Data': 'some_url'}
        }
    ],
    'createdTime': '2019-11-11T10:18:13.293313+02:00',
    'firstSeen': '2019-11-11T10:18:13.293298+02:00',
    'firstSeenEntryID': '218@fb7e49c8-33d4-4f32-8220-63b9577575c3',
    'id': '53',
    'investigationIDs': [
        'fb7e49c8-33d4-4f32-8220-63b9577575c3',
        '1',
        '3'
    ],
    'investigationsCount': 3,
    'isIoc': False,
    'lastReputationRun': '2019-11-11T14:17:11.343302+02:00',
    'lastSeen': '2019-11-11T14:17:11.846266+02:00',
    'lastSeenEntryID': '242@fb7e49c8-33d4-4f32-8220-63b9577575c3',
    'manualSetTime': '0001-01-01T00:00:00Z',
    'modified': '2019-11-11T14:17:11.880389+02:00',
    'name': 'some_url',
    'rawName': 'some_url',
    'rawSource': 'DBot',
    'score': 3,
    'sortValues': None,
    'source': 'DBot',
    'type': 'URL',
    'version': 6
}

detect_positive_not_zero_2 = {
    'CustomFields': {
        'detectionengines': 71,
        'positivedetections': 8
    },
    'ManuallyEditedFields': None,
    'account': '',
    'calculatedTime': '2019-11-11T14:19:01.711812+02:00',
    'comment': '',
    'context': [
        {
            'URL(val.Data && val.Data === obj.Data)': {'Data': 'some_url'}
        }
    ],
    'createdTime': '2019-11-11T14:18:44.383082+02:00',
    'firstSeen': '2019-11-11T14:18:44.344787+02:00',
    'firstSeenEntryID': '244@fb7e49c8-33d4-4f32-8220-63b9577575c3',
    'id': '56',
    'investigationIDs': ['fb7e49c8-33d4-4f32-8220-63b9577575c3'],
    'investigationsCount': 1,
    'isIoc': False,
    'lastReputationRun': '2019-11-11T14:19:01.209773+02:00',
    'lastSeen': '2019-11-11T14:19:01.711812+02:00',
    'lastSeenEntryID': '246@fb7e49c8-33d4-4f32-8220-63b9577575c3',
    'manualSetTime': '0001-01-01T00:00:00Z',
    'modified': '2019-11-11T14:19:01.746424+02:00',
    'name': 'some_url',
    'rawName': 'some_url',
    'rawSource': 'DBot',
    'score': 2,
    'sortValues': None,
    'source': 'DBot',
    'type': 'URL',
    'version': 2
}

positive_zero = {
    'CustomFields': {
        'detectionengines': 71,
        'positivedetections': 0
    },
    'ManuallyEditedFields': None,
    'account': '',
    'calculatedTime': '2019-11-11T13:51:25.36382+02:00',
    'comment': '',
    'context': [
        {
            'URL(val.Data && val.Data === obj.Data)': {'Data': 'http://www.google.com'}
        }
    ],
    'createdTime': '2019-11-11T13:49:07.465511+02:00',
    'firstSeen': '2019-11-11T13:49:07.465474+02:00',
    'firstSeenEntryID': '220@fb7e49c8-33d4-4f32-8220-63b9577575c3',
    'id': '54',
    'investigationIDs': ['fb7e49c8-33d4-4f32-8220-63b9577575c3'],
    'investigationsCount': 1,
    'isIoc': False,
    'lastReputationRun': '2019-11-11T13:51:24.859501+02:00',
    'lastSeen': '2019-11-11T13:51:25.36382+02:00',
    'lastSeenEntryID': '226@fb7e49c8-33d4-4f32-8220-63b9577575c3',
    'manualSetTime': '0001-01-01T00:00:00Z',
    'modified': '2019-11-11T13:51:25.363844+02:00',
    'name': 'http://www.google.com',
    'rawName': 'http://www.google.com',
    'rawSource': 'DBot',
    'score': 1,
    'sortValues': None,
    'source': 'DBot',
    'type': 'URL',
    'version': 3
}

positive_missing = {
    'CustomFields': {
        'detectionengines': 71,
    }
}

detectengines_missing_1 = {
    'CustomFields': {
        'positivedetections': 71,
    }
}

detectengines_missing_2 = {
    'CustomFields': {
        'positivedetections': 0,
    }
}

no_engines_data = {
    'CustomFields': {},  # type: dict[any: any]
    'ManuallyEditedFields': None,
    'account': '',
    'calculatedTime': '2019-11-11T14:25:28.922329+02:00',
    'comment': '',
    'context': [
        {
            'URL(val.Data && val.Data === obj.Data)': {'Data': 'http://twitter.com'}
        }
    ],
    'createdTime': '2019-11-11T14:22:59.076607+02:00',
    'firstSeen': '2019-11-11T14:22:59.039955+02:00',
    'firstSeenEntryID': '247@fb7e49c8-33d4-4f32-8220-63b9577575c3',
    'id': '58',
    'investigationIDs': ['fb7e49c8-33d4-4f32-8220-63b9577575c3'],
    'investigationsCount': 1,
    'isIoc': False,
    'lastReputationRun': '2019-11-11T14:24:57.539514+02:00',
    'lastSeen': '2019-11-11T14:25:28.922329+02:00',
    'lastSeenEntryID': '252@fb7e49c8-33d4-4f32-8220-63b9577575c3',
    'manualSetTime': '0001-01-01T00:00:00Z',
    'modified': '2019-11-11T14:25:29.6606+02:00',
    'name': 'http://twitter.com',
    'rawName': 'http://twitter.com',
    'rawSource': 'DBot',
    'sortValues': None,
    'source': 'DBot',
    'type': 'URL',
    'version': 3
}


@pytest.mark.parametrize('indicator_data, expected_result', [
    (detect_positive_not_zero_1, (10, 61)),
    (detect_positive_not_zero_2, (8, 63)),
    (positive_zero, (0, 71))
])
def test_zero_not_treated_as_none(indicator_data, expected_result):
    extract_result = extract_engines_data_from_indicator(indicator_data)
    detection_engines = extract_result['Contents']['stats'][0]['data'][0]
    positive_detections = extract_result['Contents']['stats'][1]['data'][0]
    assert (detection_engines, positive_detections) == expected_result


@pytest.mark.parametrize('indicator_data', [no_engines_data])
def test_no_engines_data(indicator_data):
    res = extract_engines_data_from_indicator(indicator_data)
    stats = res['Contents']['stats']
    assert stats[0]['data'][0] == 0
    assert stats[1]['data'][0] == 0


def test_missing_fields_detection_engines():
    res = extract_engines_data_from_indicator(detectengines_missing_2)
    stats = res['Contents']['stats']
    assert stats[0]['data'][0] == 0
    assert stats[1]['data'][0] == 0


def test_missing_fields_positive_detections():
    res = extract_engines_data_from_indicator(positive_missing)
    stats = res['Contents']['stats']
    assert stats[0]['data'][0] == 0
    assert stats[1]['data'][0] == 71


def test_detection_engines_greater_than_positive_detections():
    err_raised = False
    try:
        extract_engines_data_from_indicator(detectengines_missing_1)
    except ValueError:
        err_raised = True
    assert err_raised
