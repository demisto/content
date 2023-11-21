import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

EMAIL_INTEGRATIONS = ['Gmail', 'EWSO365', 'EWS v2', 'Agari Phishing Defense', 'MicrosoftGraphMail',
                      'SecurityAndCompliance', 'SecurityAndComplianceV2']


def get_delete_reported_email_integrations():
    """
    Get all enabled integration instances that can be used for deleting an email using the DeleteReportedEmail script.
    Returns:
        List of enabled integrations suitable for the DeleteReportedEmail script.

    """
    instances = demisto.getModules()
    return [data.get('brand') for data in instances.values() if data.get('state') == 'active' and data.get('brand')
            in EMAIL_INTEGRATIONS]


def main():
    try:
        return_results({"hidden": False,
                        "options": get_delete_reported_email_integrations()
                        })

    except Exception as err:
        return_error(str(err), error=traceback.format_exc())


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
