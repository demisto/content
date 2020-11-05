import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


HTML_TEMPLATE = (
    "</br>"
    "<div style='line-height:36px; color:#404142; text-align:center; font-size:20px; line-height:36px;'>"
    "{fetched}/{total}"
    "</div>"

    "<div class='editable-field-wrapper' style='text-align:center; padding-top:10px;'>"
    "Fetched Events / Total"
    "</div>"

    "<div class='editable-field-wrapper' style='text-align:center;'>"
    "{message}"
    "</div>"
)


def main():
    try:
        incident = demisto.incident()
        custom_fields = incident.get('CustomFields', {})
        fetched = custom_fields.get('numberoffetchedevents', 0)  # define which incident field to use
        total = custom_fields.get('numberofeventsinoffense', 0)  # define which incident field to use

        if fetched == 0:
            message = 'The offense contains Events but non were fetched. ' \
                      'Event fetching can be configured in the integration instance settings.'
        else:
            message = 'Events details on this page are based on the fetched events.'

        html = HTML_TEMPLATE.format(fetched=fetched, total=total, message=message)

        return {
            'ContentsFormat': 'html',
            'Type': entryTypes['note'],
            'Contents': html
        }

    except Exception as exp:
        return_error('could not parse QRadar offense', error=exp)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    return_results(main())
