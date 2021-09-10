import json
from SalesforceLoadProvisioningRulesFromCSV import get_salesforce_provisioning_json


CITY_MAPPING_CSV_STRING = open("test_data/csv_city.txt").read()
EXPECTED_CITY_MAPPING = json.loads(open("test_data/expected_city_mapping.json").read())

LOCATION_REGION_MAPPING_CSV_STRING = open("test_data/csv_locationregion.txt").read()
EXPECTED_LOCATION_REGION_MAPPING = json.loads(open("test_data/expected_locationregion_mapping.json").read())

ORG_UNIT_MAPPING_CSV_STRING = open("test_data/csv_orgunit.txt").read()
EXPECTED_ORG_UNIT_MAPPING = json.loads(open("test_data/expected_orgunit_mapping.json").read())

ARGS = {
    'city_mapping_csv_list': 'city-mapping-csv',
    'location_region_mapping_csv_list': 'location-region-mapping-csv',
    'orgunit_mapping_csv_list': 'org-unit-mapping-csv',
}


def mock_get_list(list_name):
    if list_name == ARGS['city_mapping_csv_list']:
        return CITY_MAPPING_CSV_STRING

    elif list_name == ARGS['location_region_mapping_csv_list']:
        return LOCATION_REGION_MAPPING_CSV_STRING

    elif list_name == ARGS['orgunit_mapping_csv_list']:
        return ORG_UNIT_MAPPING_CSV_STRING

    return None


def test_get_salesforce_provisioning_json(mocker):
    """
    Given:
        CSV Salesforce city, location-region and org unit mappings stored in the following lists:
        - city-mapping-csv
        - location-region-mapping-csv
        - org-unit-mapping-csv

    When:
        Calling get_salesforce_provisioning_json() method

    Then:
        Ensure the JSON output is parsed as expected.

    """
    mocker.patch('SalesforceLoadProvisioningRulesFromCSV.get_list', side_effect=mock_get_list)

    output = get_salesforce_provisioning_json(ARGS)

    assert output.get('cityMapping') == EXPECTED_CITY_MAPPING
    assert output.get('locationRegionMapping') == EXPECTED_LOCATION_REGION_MAPPING
    assert output.get('orgUnitMapping') == EXPECTED_ORG_UNIT_MAPPING.get('orgUnitMapping')
    assert output.get('gcs') == EXPECTED_ORG_UNIT_MAPPING.get('gcs')
    assert output.get('field marketing') == EXPECTED_ORG_UNIT_MAPPING.get('field marketing')
