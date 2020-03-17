import demistomock as demisto
from CommonServerPython import *
import json


def parse_compliance(raw_json):
    data = json.loads(raw_json)

    if data.get('kind') != 'compliance':
        raise ValueError(f'Input should be a raw JSON compliance alert, received: {raw_json}')

    outputs = {'PrismaCloudCompute.ComplianceAlert': data}

    # remove unneeded fields from human readable results
    headers: list = []
    for field in data.keys():
        if field not in ['_id', 'kind', 'compliance']:
            headers.append(field)
    headers.sort()

    readable_outputs = tableToMarkdown('Compliance Information',
                                       data,
                                       headers=headers)

    # add another table for compliance issues
    readable_outputs += tableToMarkdown('Compliance', data.get('compliance'))

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
