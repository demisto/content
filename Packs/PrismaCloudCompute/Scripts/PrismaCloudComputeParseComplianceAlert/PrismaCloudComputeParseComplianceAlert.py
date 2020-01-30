import demistomock as demisto
from CommonServerPython import *
import json


def parse_compliance(raw_json):
    data = json.loads(raw_json)
    if 'kind' not in data or data['kind'] != 'compliance':
        raise ValueError(f'Input should be a raw JSON compliance Alert, received: {raw_json}')

    outputs = {'PrismaCloudCompute.ComplianceAlert': data}
    readable_outputs = tableToMarkdown('Compliance Information',
                                       data,
                                       headers=['time', 'type'])
    # add another table for compliance issues
    readable_outputs += tableToMarkdown('Compliance', data['compliance'])

    return (
        readable_outputs,
        outputs,
        raw_json
    )


def main():
    try:
        return_outputs(*parse_compliance(demisto.args().get('alert_raw_json', '')))
    except Exception as ex:
        return_error(f'Failed to execute PrismaCloudComputeParseComplianceAlert. Error: {str(ex)}')


if __name__ in ('__builtin__', 'builtins'):
    main()
