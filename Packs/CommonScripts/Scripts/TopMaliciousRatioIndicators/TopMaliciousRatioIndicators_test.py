import demistomock as demisto
from TopMaliciousRatioIndicators import main, find_indicators_with_mal_ratio
import io
import json


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_find_indicators_with_mal_ratio(mocker):
    """
        Given:
            - Result JSON's of the findIndicators script and the maliciousRatio script
        When:
            - Searching for indicators with malicious ratio when the minimumNumberOfInvs threshold set to 4
        Then:
            - Returns list of indicators that match the given criteria and the appropriate widget table
    """

    mocker.patch.object(demisto, 'args', return_value={})
    mocker.patch.object(demisto, 'executeCommand', side_effect=[
        util_load_json('./test_data/indicators_found.json'),
        util_load_json('./test_data/malicious_ratio_result.json')
    ])
    widget_table, sorted_indicators = find_indicators_with_mal_ratio(max_indicators=1000, min_number_of_invs=4,
                                                                     max_results=1000,
                                                                     from_date="30 days ago")
    assert '{"total": 2, "data": [{"ID": "7570", "Type": "URL", "Malicious Ratio": "0.11", "Value":' \
           ' "http://8.16.1.2/8.16.1.2", "Last Seen": "2021-11-22T15:15:54.958327+02:00"},' \
           ' {"ID": "7569", "Type": "Domain", "Malicious Ratio": "0.08", "Value": "gmail.com",' \
           ' "Last Seen": "2021-11-22T15:15:54.958278+02:00"}]}' == widget_table
    assert len(sorted_indicators) == 2


def test_find_indicators_with_mal_ratio__no_indicators(mocker):
    """
        Given:
            - Result JSON of the findIndicators script execution with no indicators
        When:
            - Searching for indicators with malicious ratio
        Then:
            - Returns widget table with 0 total results and an empty list of indicators
    """

    mocker.patch.object(demisto, 'args', return_value={})
    mocker.patch.object(demisto, 'executeCommand', return_value=util_load_json('./test_data/no_indicators.json'))
    widget_table, sorted_indicators = find_indicators_with_mal_ratio(max_indicators=1000, min_number_of_invs=5,
                                                                     max_results=1000,
                                                                     from_date="30 days ago")
    assert '{"total": 0, "data": []}' == widget_table
    assert not sorted_indicators


def test_main(mocker):
    """
        Given:
            - Result JSON's of the findIndicators script and the maliciousRatio script
        When:
            - Searching for indicators with malicious ratio when the minimumNumberOfInvs threshold set to 4
        Then:
            - Returns list of indicators that match the given criteria and the appropriate widget table
    """

    EXPECTED_HR = """### Top Malicious Ratio Indicators
|ID|Last Seen|Malicious Ratio|Type|Value|
|---|---|---|---|---|
| 7570 | 2021-11-22T15:15:54.958327+02:00 | 0.11 | URL | http://8.16.1.2/8.16.1.2 |
| 7569 | 2021-11-22T15:15:54.958278+02:00 | 0.08 | Domain | gmail.com |
"""
    mocker.patch.object(demisto, 'args',
                        return_value={
                            "maxNumberOfIndicators": "1000",
                            "minimumNumberOfInvs": "4",
                            "maximumNumberOfResults": "1000"
                        })
    mocker.patch.object(demisto, 'executeCommand', side_effect=[
        util_load_json('./test_data/indicators_found.json'),
        util_load_json('./test_data/malicious_ratio_result.json')
    ])

    mocker.patch.object(demisto, 'results')
    main()
    assert EXPECTED_HR == demisto.results.call_args[0][0]['HumanReadable']
