import pytest
import demistomock as demisto
from unittest.mock import patch
from SetRDPOverallScore import main

# Tests that the function returns the correct HTML string for an OverallScore of 0.
def test_happy_path_score_zero(mocker):
    mocker.patch.object(demisto, 'context', return_value={'OverallScore': '0'})
    expected_html = "<div style='color:#1DB846;font-size:32px;padding: 60px; text-align:center;padding-left: 70px'>0/100<br><br>No suspicious strings found</div>"
    main()
    result = demisto.context.call_args[0]
    assert result['Contents'] == expected_html