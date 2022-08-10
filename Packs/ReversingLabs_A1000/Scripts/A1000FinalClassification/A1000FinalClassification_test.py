import pytest
import demistomock as demisto
import A1000FinalClassification
from A1000FinalClassification import main


test_args = {
    'a1000_full_report': {
        "results": [{
            "threat_status": "malicious",
            "sha1": "e5a64e300d880f3f9248a17124ccc49391c760f9"
        }]
    },
    "a1000_classification_report": {
        "threat_status": "MALICIOUS",
        "sha1": "e5a64e300d880f3f9248a17124ccc49391c760f9"
    }
}

test_data = [
    ('UNKNOWN', 'KNOWN', 1),
    ('UNKNOWN', 'MALICIOUS', 3),
    ('SUSPICIOUS', 'KNOWN', 2),
    ('KNOWN', 'MALICIOUS', 3),
    ('MALICIOUS', 'KNOWN', 3)
]


@pytest.mark.parametrize('a1000_classification, cloud_classification, expected_result', test_data)
def test_main__happy_path(mocker, a1000_classification, cloud_classification, expected_result):
    args = test_args.copy()
    args['a1000_classification_report']['threat_status'] = cloud_classification
    args['a1000_full_report']['results'][0]['threat_status'] = a1000_classification
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch('A1000FinalClassification.return_results')

    main()

    res = A1000FinalClassification.return_results.call_args[0][0]
    assert res.indicator.dbot_score.score == expected_result


@pytest.mark.parametrize('key_to_be_none', ['a1000_classification_report', 'a1000_full_report'])
def test_main__return_error(mocker, key_to_be_none):
    args = test_args.copy()
    args[key_to_be_none] = None
    mocker.patch.object(demisto, 'error')
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch('A1000FinalClassification.return_error')

    main()

    err_msg = A1000FinalClassification.return_error.call_args[0][0]
    assert 'not specified' in err_msg
