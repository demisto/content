import pytest
import demistomock as demisto
def test_convert_file(mocker):
    from ConvertXmlFileToJson import convert_file
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': './TestData/input.xml'})
    res = mocker.patch.object(demisto, 'setContext')
    convert_file(entry_id="mock_entry", verbose=False, context_key="Test")
    expected_result = {"note": {"to": "Tove", "from": "Jani", "heading": "Reminder", "body": "Don't forget me this weekend!"}}
    assert res.call_args[0][1] == expected_result


