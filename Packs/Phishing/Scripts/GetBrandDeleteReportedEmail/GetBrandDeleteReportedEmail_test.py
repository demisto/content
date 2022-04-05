from GetBrandDeleteReportedEmail import *

INTEGRATION_INSTANCES = {
    'statusCode': 200, 'body': {'instances': [
        {
            'name': 'DeleteReportedEmail_Integration_instance1',
            'brand': 'DeleteReportedEmail_Integration', 'enabled': 'true'},
        {
            'name': 'DeleteReportedEmail_Integration_instance2',
            'brand': 'DeleteReportedEmail_Integration', 'enabled': 'true'},
        {
            'name': 'DeleteReportedEmail_Integration_instance3',
            'brand': 'DeleteReportedEmail_Integration', 'enabled': 'false'},
        {
            'name': 'NoMailIntegration_instance1',
            'brand': 'NoMailIntegration', 'enabled': 'true'},
        {
            'name': 'NoMailIntegration_instance2',
            'brand': 'NoMailIntegration', 'enabled': 'false'}],
    }}


def test_get_enabled_instances(mocker):
    """

    Given:
        - A successful demisto response

    When:
        - The "Delete Reported Email" single select field try to populate the available instances

    Then:
        - Get the integration instances that can be used for the Delete Reported Email script

    """
    mocker.patch.object(demisto, 'internalHttpRequest', return_value=INTEGRATION_INSTANCES)
    mocker.patch('json.loads', return_value=INTEGRATION_INSTANCES.get('body'))
    result = get_enabled_instances()

    assert all(argToBoolean(item.get('enabled')) for item in result)


def test_get_enabled_instances_failure(mocker):
    """
    Given:
        - A failed demisto response

    When:
        - The "Delete Reported Email" single select field try to populate the available instances

    Then:
        - Validate that when no results, empty list returned

    """
    mocker.patch.object(demisto, 'internalHttpRequest', return_value={'statusCode': 400})
    assert get_enabled_instances() == []
