import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

incident = demisto.incidents()
fetched = incident[0].get('CustomFields', {}).get('numberoffetchedevents', 0)  # define which incident field to use
total = incident[0].get('CustomFields', {}).get('numberofeventsinoffense', 0)  # define which incident field to use

if fetched == 0:
    total = str(total)
    fetched = str(fetched)
    html = "<div style='line-height:36px;color: #404142;text-align: center;font-size: 20px;line-height: 36px;'>" + "<br>" + fetched + "/" + total + "</div>" + "<div class='editable-field-wrapper' style='text-align:center;padding-top: 10px;'>" + \
        "Fetched Events / Total" "<br>" + "<div class='editable-field-wrapper' style='text-align:center;'>" + \
        "The offense contains Events but non were fetched. Event fetching can be configured in the integration instance settings." "</div>"


else:
    total = str(total)
    fetched = str(fetched)
    html = "<div style='line-height: 36px;color: #404142;text-align: center;font-size: 20px;line-height: 36px;'>" + "<br>" + fetched + "/" + total + "</div>" + "<div class='editable-field-wrapper' style='text-align:center;padding-top: 10px;'>" + \
        "Fetched Events / Total" "<br>" + "<div class='editable-field-wrapper' style='text-align:center;'>" + \
        "Events details on this page are based on the fetched events." + "</div>""</div>"

demisto.results({
    'ContentsFormat': 'html',
    'Type': entryTypes['note'],
    'Contents': html
})
