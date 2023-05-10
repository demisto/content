from unittest.mock import patch, MagicMock, call
import demistomock as demisto
import json
from subprocess import PIPE

MOCK_DOMAIN = 'test.com'
expected_entry_result = {'Contents': 'hosts_json_test',
                         'ContentsFormat': 'json',
                         'EntryContext': {'Aquatone.discover': 'hosts_json_test'},
                         'HumanReadable': 'Output message',
                         'ReadableContentsFormat': 'markdown',
                         'Type': 1}

expected_calls = [call(['aquatone-discover', '--domain', 'test.com'], stdout=PIPE, stderr=PIPE, encoding='utf-8'),
                  call().communicate(),
                  call(['cat', '/root/aquatone/test.com/hosts.json'], stdout=PIPE, stderr=PIPE, encoding='utf-8'),
                  call().communicate()]


def test_AquatoneDiscover(mocker):
    """
    Given:
        - A domain

    When:
        - running AquatoneDiscover command

    Then:
        - Ensure that Popen and demisto.results were called with the expected arguments
    """
    from AquatoneDiscoverV2 import main
    with patch("AquatoneDiscoverV2.Popen") as Popen:
        proc = MagicMock()
        Popen.return_value = proc
        proc.communicate.return_value = ["Output message", "Error message"]
        proc.returncode = 0

        mocker.patch.object(demisto, 'args', return_value={'domain': MOCK_DOMAIN})
        mocker.patch.object(demisto, 'results')
        mocker.patch.object(json, 'loads', return_value="hosts_json_test")

        main()
        assert Popen.mock_calls == expected_calls
        assert Popen.call_count == 2
        assert demisto.results.call_count == 1
        results = demisto.results.call_args[0]
        assert results[0] == expected_entry_result
