import demistomock as demisto
from CommonServerPython import *
import json


def parse_audit(raw_json):
    data = json.loads(raw_json)

    if data.get('kind') != 'audit':
        raise ValueError(f'Input should be a raw JSON audit alert, received: {raw_json}')

    outputs = {'PrismaCloudCompute.AuditAlert': data}
    readable_outputs = tableToMarkdown('Audit Information', data)

    return (
        readable_outputs,
        outputs,
        raw_json
    )


def main():
    try:
        return_outputs(*parse_audit(demisto.args().get('alert_raw_json', '')))
    except Exception as ex:
        return_error(f'Failed to execute PrismaCloudComputeParseAuditAlert. Error: {str(ex)}')


if __name__ in ('__builtin__', 'builtins'):
    main()
