from WhiteListCIDR import *
import demistomock as demisto
import json

TEST_RESULT = json.load(open("./test_indicators.json"))
TEST_RESULT_MISSING_TAG = json.load(open("./test_indicators_notags.json"))
TEST_CIDR_RESULT = json.load(open("./test_cidr_indicators.json"))
TEST_CIDR_V6_RESULT = json.load(open("./test_cidr_indicators_v6.json"))
TEST_INDICATOR_DATA = TEST_RESULT[0]['Contents']
MOCK_ARGS = {
    "indicator_query": "type:IP",
    "cidr_whitelist_query": "type:CIDR",
    "add_tag": "test_tag"
}


def test_find_tag():
    """
    Test the logic of finding tags within indicator data
    :return:
    """
    indicator_no_tag = TEST_INDICATOR_DATA[0]
    test_tag = MOCK_ARGS.get("add_tag")
    r = find_tag(indicator_no_tag, test_tag)
    assert not r

    indicator_with_tag = TEST_INDICATOR_DATA[1]
    r = find_tag(indicator_with_tag, test_tag)
    assert r


def test_main_untag(mocker):
    """
    Check if we have an indicator currently tagged no longer in whitelist, we untag it
    """
    mocker.patch.object(demisto, "args", return_value=MOCK_ARGS)
    mocker.patch.object(demisto, "executeCommand", side_effect=[TEST_RESULT, TEST_CIDR_RESULT, True, True])
    r = main()
    assert len(r.get("Untagged")) == 1
    demisto.executeCommand.assert_called_with("removeIndicatorField", {'field': 'tags', 'fieldValue': 'test_tag',
                                                                       'indicatorsValues': '18.208.124.8'})


def test_main_tag(mocker):
    """
    Check if we have an indicator missing the tag no longer in whitelist and tag it
    """
    mocker.patch.object(demisto, "args", return_value=MOCK_ARGS)
    mocker.patch.object(demisto, "executeCommand", side_effect=[TEST_RESULT_MISSING_TAG, TEST_CIDR_RESULT, True, True])
    r = main()
    assert len(r.get("Tagged")) == 1
    demisto.executeCommand.assert_called_with("setIndicator", {'value': "52.100.1.1", 'tags': "test_tag"})


def test_main_tag_v6(mocker):
    """
    Check if we have an indicator missing the tag no longer in whitelist and tag it
    """
    mocker.patch.object(demisto, "args", return_value=MOCK_ARGS)
    mocker.patch.object(demisto, "executeCommand",
                        side_effect=[TEST_RESULT_MISSING_TAG, TEST_CIDR_V6_RESULT, True, True])
    r = main()
    assert len(r.get("Tagged")) == 1
    demisto.executeCommand.assert_called_with("setIndicator", {'value': "2506:b000::10", 'tags': "test_tag"})
