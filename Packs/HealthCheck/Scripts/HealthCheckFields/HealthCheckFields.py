import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def find_indexed_longText_fields(fields):
    found = []
    for field in fields:
        if field['type'] in RIKEY_TYPES and field['unsearchable'] is False:
            if field['packID'] == "":
                if field['system'] is False:
                    if field['name'] != 'description':
                        found.append({'fieldname': field['name'], 'fieldtype': field['type']})
    return found

# def find_indexed_longText_fields(fields):
#     found = []
#     for field in fields:
#         if (field['type'] in RIKEY_TYPES and field['unsearchable'] is False):
#             if field['packID'] == "" and field['system'] is False and field['name'] != 'description':
#                 found.append({'fieldname':field['name'],'fieldtype':field['type']})
#     return found


DESCRIPTION = ['Custom with LongText fields were configured to be indexed consider not to index it']

RESOLUTION = ['Navigate to incident field page (Settings > Advanced > Fields), select Field > Edit, '
              'and turn off Make data available for search under the Attributes tab its determines if '
              'the values in these fields are available when searching.']

RIKEY_TYPES = ['grid', 'html', 'longText', 'markdown', 'url']
res = demisto.executeCommand('demisto-api-get', {'uri': '/incidentfields'})
if is_error(res):
    return_error(res[0]['Contents'])
fields = res[0]['Contents']['response']
found = find_indexed_longText_fields(fields)

demisto.executeCommand("setIncident", {"healthcheckriskyindexedfields": found})

action_items = []
if found:
    action_items.append({
        'category': 'Content',
        'severity': 'Medium',
        'description': DESCRIPTION[0],
        'resolution': '{}'.format(RESOLUTION[0]),
    })


results = CommandResults(
    outputs_prefix="HealthCheck.ActionableItems",
    outputs=action_items,
)

return_results(results)

# for recomendations:
# if fields exist with data in incidents make it higher severity with explanations
