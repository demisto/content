from ServiceNowTroubleshoot import get_integrations_details
import sys
sys.path.append('/Users/mmorag/dev/demisto/content/Packs/ServiceNow/Scripts/ServiceNowTroubleshoot/demistomock.py')
import Packs.ServiceNow.Scripts.ServiceNowTroubleshoot.demistomock as demisto
import json
import pytest



def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


# TODO: REMOVE the following dummy unit test function
def test_get_active_incidents_by_instances():
    pass


def test_get_integrations_details(mocker):
    http_response = util_load_json("test_data/setting_integration_search_http_response.json")
    mocker.patch.object(demisto, 'internalHttpRequest', side_effect=http_response)
    expected = {}
    res = get_integrations_details()
    assert expected == res


def filter_instances_data():
    pass

def active_incidents_data():
    pass

def parse_disabled_instances():
    pass

def parse_enabled_instances():
    pass
    

