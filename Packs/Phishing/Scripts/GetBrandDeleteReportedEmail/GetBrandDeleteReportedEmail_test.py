from GetBrandDeleteReportedEmail import *


def test_get_delete_reported_email_integrations(mocker):
    """
       Given:
           - All enabled integration instances

       When:
           - Filtering the suitable integrations for deleting an email

       Then:
           - Return only the suitable integrations brand name

       """

    mock_modules = {
        'instanceName1': {'state': 'active', 'brand': 'EWSO365'},
        'instanceName2': {'state': 'disabled', 'brand': 'SecurityAndCompliance'}
    }
    mocker.patch.object(demisto, 'getModules', return_value=mock_modules)
    assert get_delete_reported_email_integrations() == ['EWSO365']


def test_get_brand_delete_reported_email(mocker):
    """
       Given:
           - All enabled integration instances that are also suitable for this script

       When:
           - Running the script

       Then:
           - Results object with the suitable brand names

       """
    import GetBrandDeleteReportedEmail
    mocker.patch.object(GetBrandDeleteReportedEmail, 'get_delete_reported_email_integrations', return_value=['EWSO365'])

    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_args[0][0]['options'] == ['EWSO365']
