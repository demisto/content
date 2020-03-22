# coding=utf-8
import demistomock as demisto


def test_empty_and_special_characters_in_xml(mocker, requests_mock):
    mocker.patch.object(demisto, 'params', return_value={"server": 'https://example.com',
                                                         "certificate": 'cert',
                                                         'severities': 'Emergency,Critical'
                                                         })
    mocker.patch.object(demisto, 'args', return_value={'number': '14'})
    mocker.patch.object(demisto, 'command', return_value="symantec-mss-get-incident")
    with open('./test_data/SymantecXML.txt', 'rb') as f:
        text_to_return = f.read()
    text_to_return = text_to_return.decode('UTF-8')
    requests_mock.post('https://example.com/SWS/incidents.asmx', text=text_to_return)
    import SymantecMSS as mss  # noqa
