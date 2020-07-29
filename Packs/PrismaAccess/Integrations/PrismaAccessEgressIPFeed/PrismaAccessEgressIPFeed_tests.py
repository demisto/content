import pytest
from CommonServerPython import *
from PrismaAccessEgressIPFeed import get_indicators_command


@pytest.mark.parametrize('tags', [['tag1', 'tag2'], []])
def test_feed_tags(self, mocker, tags):
    """
    Given:
    - tags parameters
    When:
    - Executing any command on feed
    Then:
    - Validate the tags supplied exists in the indicators
    """
    client = Client([], 'apikey', False, False, tags)
    mocker.patch.object(client, 'build_iterator', return_value=[])
    _, _, raw_json = get_indicators_command(client, {'limit': 2, 'indicator_type': 'IPs'})
    assert tags == raw_json.get('raw_response')[0]['fields']['tags']