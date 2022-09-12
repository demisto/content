import demistomock as demisto
from EmailTopicDisplay import main
import json

def util_load_json(path):
    with open(path, mode='r') as f:
        return json.loads(f.read())


def test_main(mocker):
    mocker.patch.object(demisto,'incidents',return_value=util_load_json('test_data/incident.json'))
    mocker.patch.object(demisto,'results')
    expected_result = [
            "This is test 1",
            "This is test 2"
        ]
    result = main()
    assert result == expected_result