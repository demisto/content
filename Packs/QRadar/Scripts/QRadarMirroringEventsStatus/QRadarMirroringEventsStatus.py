import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

HTML_TEMPLATE = (
    "</br>"
    "<div style='color:#404142; text-align:center; font-size:17px;'>"
    "{status}"
    "</div>"

    "<div class='editable-field-wrapper' style='text-align:center;'>"
    "{message}"
    "</div>"
    "<div draggable='false' class='section-item-content' style='width: 220px; min-height: 22px; padding-top:10px;'>"
    "<div class='field-wrapper row'>"
    "<div class='header-wrapper'>"
    "<span class='header-value label-text opacity-description ellipsis' title='LastMirroredInTime'>"
    "LastMirroredInTime"
    "</span>"
    "</div>"
    "<div class='value-wrapper'>"
    "<span class=''>"
    "<div class='date-field-wrapper small'>"
    "<div class='date-display-value-wrapper'>"
    "<div class='date-display-value'>"
    "{last_mirror_in_time}"
    "</div>"
    "</div>"
    "</div>"
    "</span>"
    "</div>"
    "</div>"
    "</div>"
)


def main():
    try:
        incident = demisto.incident()
        custom_fields = incident.get('CustomFields', {})
        last_mirror_in_time = custom_fields.get('lastmirroredintime', None)
        message = custom_fields.get('incomingmirrorerror', '')

        if message == '':
            status = 'Not Started'
        elif message == 'Mirroring events has reached events limit in this incident.':
            status = 'Completed and Stopped'
        elif message == 'All available events in the offense were mirrored.':
            status = 'Completed'
        elif message == 'In queue.':
            status = 'In Progress'
        else:
            status = 'Failure'

        html = HTML_TEMPLATE.format(status=status, message=message, last_mirror_in_time=last_mirror_in_time)

        return {
            'ContentsFormat': 'html',
            'Type': entryTypes['note'],
            'Contents': html
        }

    except Exception as exp:
        return_error('could not parse QRadar offense', error=exp)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    return_results(main())
