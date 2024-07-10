import json
import io

import FeedThreatFox as ftf
CLIENT = ftf.Client(base_url= 'https://threatfox-api.abuse.ch/')

def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_get_indicators_request(mocker):
    """
    Given:
        - A query.
    
    When:
        - Running get_indicators_request function.
    
    Then:
        - The http request is called with the right query.
    """
    from FeedThreatFox import get_indicators_request
    m = mocker.patch.object(CLIENT, '_http_request', return_value={})
    
