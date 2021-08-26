import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback

""" CONSTANTS """
SFDC_PROVISIONING_SETTINGS_LIST = 'salesforce-provisioning-settings'
ORG_UNIT_MAPPING_FIELD = 'orgUnitMapping'
LOCATION_REGION_MAPPING_FIELD = 'locationRegionMapping'
CITY_MAPPING_FIELD = 'cityMapping'
KEY_FORMAT_FIELD = 'keyFormat'
PROFILE_MAPPINGS_FIELD = 'profileMappings'
EMAIL_NOTIFICATION_LIST_FIELD = 'emailNotificationList'

USERNAME_FIELD = 'username'
EMAIL_ADDRESS_FIELD = 'email'
MANAGER_EMAIL_FIELD = 'manageremail'
CITY_FIELD = 'city'
LOCATION_REGION_FIELD = 'locationregion'

"""
Parses the Salesforce Provisioning settings List value and returns the parsed details
"""


def get_list(list_name: str) -> Dict:
    get_list_response = demisto.executeCommand("getList", {"listName": list_name})
    if is_error(get_list_response):
        raise Exception(f"Could not read the list: {list_name}. Error: {get_list_response[0]['Contents']}")

    list_data = demisto.get(get_list_response[0], "Contents")
    return safe_load_json(list_data)


def get_org_settings(org_level_1, org_level_2, org_level_3, salesforce_provisioning_settings_list):
    if not (org_level_1 or org_level_2 or org_level_3):
        raise Exception("You must provide at least one of the Org Level values.")

    # Get the org name based on the orgUnit mappings
    org_unit_mapping = salesforce_provisioning_settings_list.get(ORG_UNIT_MAPPING_FIELD)

    for org_level in [org_level_1, org_level_2, org_level_3]:
        if org_level and org_level.lower() in org_unit_mapping:
            org_unit = org_unit_mapping[org_level.lower()]
            org_settings = salesforce_provisioning_settings_list.get(org_unit)
            if not org_settings:
                raise Exception(f"No config found for org: {org_unit}")
            return org_unit, org_settings

    return None, {}


def get_lookup_key(user_profile, org_unit, org_settings):
    # Parses the key format and prepares the lookup key. Lookup key will be used to get the provisioning details
    key_format = org_settings.get(KEY_FORMAT_FIELD)
    if not key_format:
        raise Exception(f'Missing key "{KEY_FORMAT_FIELD}" in the org unit "{org_unit}".')
    
    lookup_key_values_list = [user_profile.get(field, '') for field in key_format.split('|')]
    return '|'.join(lookup_key_values_list).lower()


def get_basic_provisioning_settings(org_unit, user_profile, org_settings):
    # Gets the user provisioning settings by a lookup key defined in the org settings.
    if not org_unit:
        return None, None

    lookup_key = get_lookup_key(user_profile, org_unit, org_settings)

    provisioning_settings = org_settings.get(PROFILE_MAPPINGS_FIELD, {}).get(lookup_key)
    if not provisioning_settings:
        provisioning_settings = org_settings.get(PROFILE_MAPPINGS_FIELD, {}).get('default')

    return lookup_key, provisioning_settings


def get_location_region_settings(user_profile, salesforce_provisioning_settings_list):
    # Gets the location region settings from salesforce provisioning settings list
    location_region_mapping = salesforce_provisioning_settings_list.get(LOCATION_REGION_MAPPING_FIELD)
    location_region = user_profile.get(LOCATION_REGION_FIELD, '')
    location_region_provisioning_settings = location_region_mapping.get(location_region.lower())
    if not location_region_provisioning_settings:
        raise Exception(f"No match found for location region mapping. LocationRegion: {location_region}")

    return location_region_provisioning_settings


def get_city_provisioning_settings(user_profile, salesforce_provisioning_settings_list):
    # Gets the city settings from salesforce provisioning settings list
    city_mapping = salesforce_provisioning_settings_list.get(CITY_MAPPING_FIELD)
    city = user_profile.get(CITY_FIELD, '')
    return city_mapping.get(city.lower(), {})


def get_manager(user_profile, app_instance):
    username = user_profile.get(USERNAME_FIELD)
    manager_email = user_profile.get(MANAGER_EMAIL_FIELD)
    if not manager_email:
        demisto.info(f'{username}: No manager email was provided in the user profile.')
    else:
        try:
            # Manager might have multiple accounts with the same email - looking up based on username.
            command_args = {
                'user-profile': json.dumps({"username": manager_email}),
                'using': app_instance
            }
            res = demisto.executeCommand("iam-get-user", command_args)
            if is_error(res):
                demisto.error(get_error(res))
            else:
                user_data = demisto.get(res[0], 'Contents.IAM.Vendor')
                if isinstance(user_data, dict) and user_data.get('success'):
                    return user_data.get('id'), user_data.get('details')
                demisto.error(f'{username}: Unable to get user manager from Salesforce. Response: {user_data}')

        except Exception as e:
            demisto.error(
                f'{username}: Unable to get user manager. '
                f'An error occurred while calling iam-get-user command from Salesforce: {traceback.format_exc()}')
            raise e
    return None, {}



def update_user_profile_with_salesforce_attributes(user_profile, salesforce_provisioning_settings, app_instance):
    """ Adds Salesforce specific attributes to User Profile data """
    salesforce_attributes = {}
    manager_id, manager_profile = get_manager(user_profile, app_instance)

    if manager_id:
        salesforce_attributes['ManagerId'] = manager_id
    else:
        demisto.log(f"Manager not found")

    for key, value in salesforce_provisioning_settings.items():
        if value == 'default_to_manager':
            salesforce_attributes[key] = manager_profile.get(key, '')
        else:
            salesforce_attributes[key] = value

    user_profile.update(salesforce_attributes)


def main():
    args = demisto.args()
    app_instance = args.get('app_instance')
    user_profile = safe_load_json(args.get('user_profile'))
    email = user_profile.get(EMAIL_ADDRESS_FIELD)

    try:
        org_level_1 = args.get('org_level_1') or user_profile.get('orglevel1')
        org_level_2 = args.get('org_level_2') or user_profile.get('orglevel2')
        org_level_3 = args.get('org_level_3') or user_profile.get('orglevel3')

        salesforce_provisioning_settings_list = get_list(SFDC_PROVISIONING_SETTINGS_LIST)
        org_unit, org_settings = get_org_settings(org_level_1, org_level_2, org_level_3, salesforce_provisioning_settings_list)

        lookup_key, provisioning_settings = get_basic_provisioning_settings(org_unit, user_profile, org_settings)
        if not provisioning_settings:
            readable_output = tableToMarkdown('Neither of Org Level 1, 2 or 3 is mapped in Salesforce Provisioning Settings',
                                              {"Org Level 1": org_level_1,
                                               "Org Level 2": org_level_2,
                                               "Org Level 3": org_level_3})
            return_outputs(readable_output)

        else:
            location_region_settings = get_location_region_settings(user_profile, salesforce_provisioning_settings_list)
            provisioning_settings.update(location_region_settings)

            city_provisioning_settings = get_city_provisioning_settings(user_profile, salesforce_provisioning_settings_list)
            provisioning_settings.update(city_provisioning_settings)

            provisioning_settings[EMAIL_NOTIFICATION_LIST_FIELD] = org_settings.get(EMAIL_NOTIFICATION_LIST_FIELD)

            update_user_profile_with_salesforce_attributes(user_profile, provisioning_settings, app_instance)
            
            results = [
                CommandResults(
                    outputs_prefix='IAM.Vendor', 
                    outputs_key_field='instanceName', 
                    outputs={
                        'email': email,
                        'action': 'SalesforceIAMExtendUserProfileData',
                        'brand': 'Salesforce IAM',
                        'instanceName': app_instance,
                        'success': True,
                    }),
                CommandResults(
                    outputs_prefix='Salesforce',
                    readable_output=tableToMarkdown('Salesforce Provisioning Settings', provisioning_settings),
                    outputs={
                        'OrgUnit': org_unit,
                        'LookupKey': lookup_key,
                        'ProvisioningSettings': provisioning_settings,
                        'UserProfile': user_profile
                    })
            ]
            return_results(results)

    except Exception as e:
        result = CommandResults(
            outputs_prefix='IAM.Vendor', 
            outputs_key_field='instanceName', 
            readable_output=f'Error while parsing Salesforce provisioning settings. Error is: {traceback.format_exc()}',
            outputs={
                'email': email,
                'action': 'SalesforceIAMExtendUserProfileData',
                'brand': 'Salesforce IAM',
                'success': False,
                'instanceName': app_instance,
                'errorMessage': str(e),
            }
        )
        return_results(result)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
