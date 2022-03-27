import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

EMAIL_INTEGRATIONS = ['Gmail', 'EWSO365', 'EWS v2', 'Agari Phishing Defense', 'MicrosoftGraphMail',
                      'SecurityAndCompliance']


def get_enabled_instances():
    """
    Get all enabled integration instances via an API request using demisto rest api
    Returns:
        List of all enabled integration instances
    """
    integration_search = demisto.internalHttpRequest('POST', '/settings/integration/search', '{\"size\":1000}')
    if integration_search and integration_search['statusCode'] == 200:
        integration_search = json.loads(integration_search.get('body', '{}'))
        return [instance for instance in integration_search['instances'] if instance['enabled'] == 'true']
    demisto.debug('Did not receive expected response from Demisto API: /settings/integration/search')
    return []


def get_delete_reported_email_integrations():
    """
    Get all enabled integration instances that can be used for deleting an email using the DeleteReportedEmail script.
    Returns:
        List of enabled integrations suitable for DeleteReportedEmail script.

    """
    return [instance['name'] for instance in get_enabled_instances() if instance['brand'] in EMAIL_INTEGRATIONS]


def main():
    try:
        return_results({"hidden": False,
                        "options": get_delete_reported_email_integrations()
                        })

    except Exception as err:
        return_error(str(err), error=traceback.format_exc())


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
