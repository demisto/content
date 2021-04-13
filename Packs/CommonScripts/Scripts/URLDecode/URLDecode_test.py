from CommonServerPython import *
from URLDecode import main
import pytest


@pytest.mark.parametrize("url,res", [
    ('https:%2F%2Fexample.com', 'https://example.com'),
    ('https://example.com/?test%20this', 'https://example.com/?test this'),
])
def test_main(mocker, url, res):
    mocker.patch.object(demisto, 'args', return_value={'value': url})
    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0]
    assert results[0]['HumanReadable'] == res
    assert results[0]['Contents']['DecodedURL'] == res
