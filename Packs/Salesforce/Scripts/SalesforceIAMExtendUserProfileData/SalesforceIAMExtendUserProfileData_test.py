def test_get_org_settings():
    """
    Given:
        - A User Profile's Org Level 1, 2 and 3.
        - Salesforce Provisioning JSON data.

    When:
        - Org settings exist in the JSON data.

    Then:
        - Ensure org unit and org settings are retrieved as expected from the get_org_settings() call.
    """
    from SalesforceIAMExtendUserProfileData import get_org_settings
    org_unit, org_settings = get_org_settings(
        org_level_1=None,
        org_level_2='sales test',
        org_level_3='test',
        salesforce_provisioning_settings_list={
            "sales": "mock_sales_org_settings",
            "orgUnitMapping": {
                "sales test": "sales",
                "gcs test": "gcs"
            }
        }
    )
    assert org_unit == 'sales'
    assert org_settings == 'mock_sales_org_settings'


def test_get_org_settings__no_config_found():
    """
    Given:
        - A User Profile's Org Level 1, 2 and 3.
        - Salesforce Provisioning JSON data.

    When:
        - No org settings in the JSON data.

    Then:
        - Ensure an exception is raised as expected.
    """
    from SalesforceIAMExtendUserProfileData import get_org_settings
    try:
        org_unit, org_settings = get_org_settings(
            org_level_1=None,
            org_level_2='sales test',
            org_level_3='test',
            salesforce_provisioning_settings_list={
                "sales": {},
                "orgUnitMapping": {
                    "sales test": "sales"
                }
            }
        )
        assert False
    except Exception as e:
        assert str(e) == 'No config found for org: sales'


def test_get_lookup_key():
    """
    Given:
        - User Profile data.
        - The user's org unit.
        - The user's org settings.

    When:
        - Calling get_lookup_key() method.

    Then:
        - Ensure the lookup key is returned as expected.
    """
    user_profile = {"k1": "v1", "k2": "v2", "k3": "v3", "k5": "v5"}
    org_unit = 'gcs'
    org_settings = {"keyFormat": "k1|k2|k4|k5"}

    from SalesforceIAMExtendUserProfileData import get_lookup_key
    lookup_key = get_lookup_key(user_profile, org_unit, org_settings)
    assert lookup_key == "v1|v2||v5"


def test_get_location_region_settings():
    """
    Given:
        - User Profile data.
        - Salesforce Provisioning JSON data.

    When:
        - Calling get_location_region_settings() method.

    Then:
        - Ensure the location region settings are returned as expected.
    """
    from SalesforceIAMExtendUserProfileData import get_location_region_settings
    output = get_location_region_settings(
        user_profile={'locationregion': 'Americas'},
        salesforce_provisioning_settings_list={
            'locationRegionMapping': {'americas': {'theatre': 'NAM'}}
        }
    )
    assert output == {'theatre': 'NAM'}


def test_update_user_profile_with_salesforce_attributes(mocker):
    """
    Given:
        - User Profile data.
        - Salesforce Provisioning JSON data.

    When:
        - Calling update_user_profile_with_salesforce_attributes() method.

    Then:
        - Ensure the user profile is updated with the salesforce attributes as expected.
    """
    from SalesforceIAMExtendUserProfileData import update_user_profile_with_salesforce_attributes
    user_profile = {}
    salesforce_provisioning_settings = {"k1": "v1", "k2": "v2", "k3": "v3", "k4": "default_to_manager"}
    app_instance = 'mock_app_instance'
    manager_id, manager = 'mock_id', {"k1": "v11", "k2": "v22", "k3": "v33", "k4": "v44"}

    mocker.patch('SalesforceIAMExtendUserProfileData.get_manager', return_value=(manager_id, manager))

    update_user_profile_with_salesforce_attributes(user_profile, salesforce_provisioning_settings, app_instance)
    assert user_profile == {"ManagerId": "mock_id", "k1": "v1", "k2": "v2", "k3": "v3", "k4": "v44"}
