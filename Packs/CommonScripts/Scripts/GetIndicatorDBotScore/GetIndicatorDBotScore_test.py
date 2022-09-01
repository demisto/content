import pytest
import demistomock as demisto
import CommonServerPython


GetIndicatorDBotScoreFunc = 'GetIndicatorDBotScore.get_dbot_score_data'


@pytest.fixture(autouse=True)
def handle_calling_context(mocker):
    mocker.patch.object(demisto, 'callingContext', {'script': True})


@pytest.mark.parametrize(
    "indicator, indicator_type, expected",
    [
        ('test_indicator', 'File SHA-256', 'file'),
        ('test_indicator', 'File SHA256', 'file'),
        ('test_indicator', 'File', 'file'),
        ('test_indicator', 'CVE', 'cve'),
        ('test_indicator', 'IP', 'ip'),
        ('test_indicator', 'Email', 'email'),
        ('test_indicator', 'Url', 'url'),
        ('test_indicator', 'IPv6', 'ip')
    ]
)
def test_validate_indicator_type(indicator, indicator_type, expected):
    """
        Given:
            - an indicator's data

        When:
            - running the script

        Then:
            - validating the dbotScoreType matches the correct indicator type
    """
    from GetIndicatorDBotScore import get_dbot_score_data, INDICATOR_TYPES
    indicator_type_after_mapping = INDICATOR_TYPES.get(indicator_type, indicator_type).lower()
    res = get_dbot_score_data(indicator, indicator_type_after_mapping, 'source', 0)
    assert res.get('Type') == expected


RESPONSE = [
    {
        "Contents": [
            {
                "indicator_type": "IP",
                "manualScore": True,
                "moduleToFeedMap": {
                    "VirusTotal": {
                        "score": 1,
                        "type": "IP",
                        "value": "8.8.8.8"
                    },
                    "ipinfo": {
                        "score": 0,
                        "type": "IP",
                        "value": "8.8.8.8"
                    }
                },
                "score": 2,
                "value": "8.8.8.8"
            }
        ],
        "Type": 1
    }
]


@pytest.mark.parametrize(
    "indicator_input, expected_count",
    [
        ('test1', 1),
        (['test1', 'test2'], 2),
        (['test1', 'test2', 'test3'], 3),
        ('test1,test2', 1),
        ('https://expired.badssl.com/?q=1,2,3', 1),
        ('["https://expired.badssl.com/?q=1,2,3", "indicator2"]', 2),
    ]

)
def test_multiple_indicators(mocker, indicator_input, expected_count):
    """
    Given:
            - indicator list as input

        When:
            - running the script

        Then:
            - ensures that every indicator in the input returns one valid result (multiple indicators have multiple results)
    """

    from GetIndicatorDBotScore import main
    mocker.patch.object(CommonServerPython, 'appendContext')
    execute_command = mocker.patch.object(demisto, 'executeCommand', return_value=RESPONSE)
    mocker.patch.object(demisto, 'args', return_value={'indicator': indicator_input})
    main()
    assert execute_command.call_count == expected_count


class TestIterateIndicatorEntry:

    @staticmethod
    def set_input(score=2, indicator='8.8.8.8', indicator_type="IP", vendors='ipinfo', set_by=None):
        module_to_feed_map = {}
        vendors = [vendors] if not isinstance(vendors, list) else vendors
        for i, vendor in enumerate(vendors):
            module_to_feed_map[vendor] = {"score": i % 4, "type": indicator_type, "value": indicator}

        res = {
            "indicator_type": indicator_type,
            "moduleToFeedMap": module_to_feed_map,
            "score": score,
            "value": indicator
        }
        if set_by:
            res.update({"manualScore": bool(set_by), "setBy": set_by})
        return res

    def test_iterate_indicator_entry_without_vendor(self):
        from GetIndicatorDBotScore import iterate_indicator_entry
        input_data = self.set_input(vendors='')
        output = [x[0] for x in iterate_indicator_entry('8.8.8.8', input_data)]
        assert output == [{'Vendor': 'Cortex XSOAR', 'Indicator': '8.8.8.8', 'Score': 0, 'Type': 'ip'}]

    def test_iterate_indicator_entry_with_1_vendor(self):
        from GetIndicatorDBotScore import iterate_indicator_entry
        input_data = self.set_input(vendors='test')
        output = [x[0] for x in iterate_indicator_entry('8.8.8.8', input_data)]
        assert output == [{'Vendor': 'test', 'Indicator': '8.8.8.8', 'Score': 0, 'Type': 'ip'}]

    def test_iterate_indicator_entry_with_corupted_vendor(self):
        from GetIndicatorDBotScore import iterate_indicator_entry
        input_data = self.set_input(vendors=None)
        output = [x[0] for x in iterate_indicator_entry('8.8.8.8', input_data)]
        assert output == [{'Vendor': 'Cortex XSOAR', 'Indicator': '8.8.8.8', 'Score': 0, 'Type': 'ip'}]

    def test_iterate_indicator_entry_with_1_vendor_and_manual_edit(self):
        from GetIndicatorDBotScore import iterate_indicator_entry
        input_data = self.set_input(vendors='test', set_by='admin')
        output = [x[0] for x in iterate_indicator_entry('8.8.8.8', input_data)]
        assert output == [
            {'Vendor': 'test', 'Indicator': '8.8.8.8', 'Score': 0, 'Type': 'ip'},
            {'Vendor': 'admin', 'Indicator': '8.8.8.8', 'Score': 2, 'Type': 'ip'}
        ]

    def test_iterate_indicator_entry_with_2_vendors(self):
        from GetIndicatorDBotScore import iterate_indicator_entry
        input_data = self.set_input(vendors=['test1', 'test2'])
        output = [x[0] for x in iterate_indicator_entry('8.8.8.8', input_data)]
        assert output == [
            {'Vendor': 'test1', 'Indicator': '8.8.8.8', 'Score': 0, 'Type': 'ip'},
            {'Vendor': 'test2', 'Indicator': '8.8.8.8', 'Score': 1, 'Type': 'ip'}
        ]
