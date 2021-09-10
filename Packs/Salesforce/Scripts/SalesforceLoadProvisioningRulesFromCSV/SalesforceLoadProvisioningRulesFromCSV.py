import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import csv
import io


GCS_ORG_UNIT = 'gcs'
MARKETING_FIELD_ORG_UNIT = 'field marketing'
MARKETING_ORG_UNIT = 'marketing'
LEGAL_ORG_UNIT = 'legal'
SALES_ORG_UNIT = 'sales'

KEY_FORMAT_FIELD = 'keyFormat'
DEFAULT_LOOKUP_KEY_FIELD = 'default'
PROFILE_MAPPINGS_FIELD = 'profileMappings'

SALESFORCE_KEY_FORMAT_MAPPING = {
    "gcs": "jobfunction|jobfamily|orglevel1|orglevel2|orglevel3|peoplemanagerflag|directorflag|vpflag|locationregion",
    "field marketing": "orglevel1|orglevel2|locationregion",
    "marketing": "orglevel1|orglevel2",
    "legal": "jobfunction|jobfamily|orglevel3",
    "sales": "jobfunction|jobfamily|suporglevel2|suporglevel3"
}

SALESFORCE_BOOLEAN_KEYS = ["UserPermissionsSupportUser", "UserPermissionsMobileUser", "UserPermissionsSFContentUser",
                           "UserPermissionsMarketingUser", "UserPermissionsOfflineUser", "UserPermissionsAvantgoUser",
                           "UserPermissionsCallCenterAutoLogin", "UserPermissionsKnowledgeUser", "UserPermissionsInteractionUser",
                           "UserPermissionsChatterAnswersUser", "ForecastEnabled"]

SALESFORCE_LIST_KEYS = ["permissionSetLicences", "permissionSetLicenceNames", "permissionSets", "permissionSetsNames",
                        "packageLicences", "packageLicenceNames"]


def get_city_location_region_mapping_json(salesforce_provisioning_settings_key, mapping_csv):
    reader = csv.DictReader(io.StringIO(mapping_csv))

    if salesforce_provisioning_settings_key == 'cityMapping':
        lookup_column_header = 'city'
    elif salesforce_provisioning_settings_key == 'locationRegionMapping':
        lookup_column_header = 'locationRegion'

    salesforce_rules_json = {}
    for row in reader:
        if lookup_column_header not in row:
            return_error(
                f'Column {lookup_column_header} is required in the CSV input. That is the lookup key in salesforce settings')
        lookup_key = row[lookup_column_header]

        # All the lookup keys in Salesforce json are in lower case
        lookup_key = lookup_key.lower()

        # Deleting city from the values since that is the lookup key.
        del row[lookup_column_header]
        salesforce_rules_json[lookup_key] = row
    json_data = {salesforce_provisioning_settings_key: salesforce_rules_json}

    return json_data


def get_org_unit_mapping_json(org_unit_csv):
    reader = csv.DictReader(io.StringIO(org_unit_csv))
    json_data = {}

    for org_unit in SALESFORCE_KEY_FORMAT_MAPPING.keys():
        org_unit = org_unit.lower()
        key_format = SALESFORCE_KEY_FORMAT_MAPPING[org_unit]

        # Parse the key format and prepare the lookup key
        lookup_key_fields_list = key_format.split('|')

        salesforce_rules_json: Dict[str, Any] = {}
        salesforce_rules_json[KEY_FORMAT_FIELD] = key_format
        profile_mappings = {}

        # Loop through each CSV row that's in dict format
        for row in reader:
            lookup_key_values_list = []
            # Prepare a list of all the values that's needed to form the key. It'll be concatenated later.
            for lookup_key_field in lookup_key_fields_list:
                cell_data = row.get(lookup_key_field, '')
                if not cell_data:
                    return_error(f"Column {lookup_key_field} not found. It's needed to build a lookup key. Row: {row}")

                lookup_key_values_list.append(cell_data)

                # Deleting the value from dict since it's part of key, not salesforce data.
                # Any CSV column that is not part of the lookup key will be included in the rules json
                del row[lookup_key_field]

            # Handle Boolean Data. CSV stores even boolean data as string. Convert it to boolean in JSON
            convert_csv_string_values_to_boolean(row)

            # Handle List Data. Convert comma separated list string to list.
            convert_csv_string_values_to_list(row)

            # Join all the field values. Order matters because it's a used as lookup key in playbooks
            lookup_key = "|".join(lookup_key_values_list)

            # All the lookup keys in Salesforce json are in lower case
            lookup_key = lookup_key.lower()

            # Check if there is a default key configured. For default keys the lookup key will be "default"
            if 'default' in lookup_key:
                lookup_key = DEFAULT_LOOKUP_KEY_FIELD

            profile_mappings[lookup_key] = row

        salesforce_rules_json[PROFILE_MAPPINGS_FIELD] = profile_mappings
        json_data.update({org_unit: salesforce_rules_json})

    return json_data


def convert_csv_string_values_to_boolean(row):
    for key, value in row.items():
        if key in SALESFORCE_BOOLEAN_KEYS and value:
            value = value.lower()
            if value == 'true':
                row[key] = True
            elif value == 'false':
                row[key] = False
            else:
                return_error(f"Unknown string value in {key}. Unable to convert it to boolean. Value: {value}")


def convert_csv_string_values_to_list(row):
    for key, value in row.items():
        if key in SALESFORCE_LIST_KEYS and value:
            value = value.split(',')
            row[key] = value


def get_list(list_name):
    get_list_response = demisto.executeCommand("getList", {"listName": list_name})

    if isError(get_list_response[0]):
        raise Exception(f'Error: Could not read the list: {list_name}')
    else:
        list_data = demisto.get(get_list_response[0], "Contents")

    return list_data


def get_salesforce_provisioning_json(args):
    city_csv = get_list(args.get('city_mapping_csv_list'))
    json_data = get_city_location_region_mapping_json('cityMapping', city_csv)

    location_region_csv = get_list(args.get('location_region_mapping_csv_list'))
    json_data.update(get_city_location_region_mapping_json('locationRegionMapping', location_region_csv))

    org_unit_csv = get_list(args.get('orgunit_mapping_csv_list'))
    org_unit_mapping = get_org_unit_mapping_json(org_unit_csv)
    json_data.update(org_unit_mapping)
    json_data.update({'orgUnitMapping': {k: k for k in org_unit_mapping.keys()}})
    return json_data


def set_list(list_name, list_data):
    set_list_response = demisto.executeCommand("createList", {"listName": list_name, "listData": list_data})

    if isError(set_list_response[0]):
        raise Exception(f'Could not create the list {list_name}: {set_list_response[0]["Contents"]}')


def main():
    args = demisto.args()
    json_data = get_salesforce_provisioning_json(args)
    set_list("salesforce-provisioning-settings", json.dumps(json_data))
    return_outputs(readable_output=None, raw_response=json_data)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
