from Packs.CommonWidgets.Scripts.RSSWidget.RSSWidget import parse_feed_data
from CommonServerPython import DemistoException, parse_date_range
import pytest
from RSSWidget import collect_entries_data_from_response

@pytest.mark.parametrize('parsed_feed_data', [[], [{}]])
def test_empty_collect_entries_data_from_response():
    with pytest.raises(DemistoException):
        collect_entries_data_from_response()

# @pytest.mark.parametrize('parsed_feed_data, excected_result', [])
# def test_collect_entries_data_from_response(parse_feed_data):

