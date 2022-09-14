import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

incident = demisto.incidents()
salesforcestatus = (incident[0].get('CustomFields', {}).get('salesforcestatus'))
picklistValues = execute_command("salesforce-describe-sobject-field",
                                 {"sobject": "Case", "field": "Status"})[0]['Contents'].get('picklistValues', [])
text_color = '#000000'
text_content = 'Pending Update'
try:
    for value in picklistValues:
        label = value.get('label') or ''
        if salesforcestatus == label:
            if 'New' in label:
                text_color = '#00CD33'

            elif 'Hold' in label:
                text_color = '#FF9000'

            elif 'Close' in label:
                text_color = '#9AA0A3'

            elif 'Progress' in label:
                text_color = '#7995D4'

            elif 'Pending' in label:
                text_color = '#FF9000'

            else:
                text_color = '#51414F'

            text_content = salesforcestatus

except Exception as e:
    demisto.debug(f'SalesforceCaseStatus debug - state is: {salesforcestatus}\n{e}')


html = f"<div style='color:{text_color};text-align:center;'><h2>{text_content}</h2></div>"
demisto.results({
    'ContentsFormat': formats['html'],
    'Type': entryTypes['note'],
    'Contents': html
})
