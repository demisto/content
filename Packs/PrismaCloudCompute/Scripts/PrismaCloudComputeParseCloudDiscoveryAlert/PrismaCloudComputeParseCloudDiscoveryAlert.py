import demistomock as demisto
from CommonServerPython import *
import json


def parse_cloud_discovery(raw_json):
    data = json.loads(raw_json)

    if data.get('kind') != 'cloudDiscovery':
        raise ValueError(f'Input should be a raw JSON cloud discovery alert, received: {raw_json}')

    outputs = {'PrismaCloudCompute.CloudDiscoveryAlert': data}

    data_fields: list = []
    entities_fields: list = []
    for field in data.keys():
        if field not in ['entities', '_id', 'kind']:
            data_fields.append(field)
    for entity in data.get('entities'):
        for field in entity.keys():
            if field not in entities_fields:
                entities_fields.append(field)

    data_fields.sort()
    entities_fields.sort()

    readable_outputs = tableToMarkdown('Cloud Discovery Information',
                                       data, headers=data_fields)
    # add another table for entities
    readable_outputs += tableToMarkdown('Discovered Entities', data.get('entities'), headers=entities_fields)

    return (
        readable_outputs,
        outputs,
        raw_json
    )


def main():
    try:
        return_outputs(*parse_cloud_discovery(demisto.args().get('alert_raw_json', '')))
    except Exception as ex:
        return_error(f'Failed to execute PrismaCloudComputeParseCloudDiscoveryAlert. Error: {str(ex)}')


if __name__ in ('__builtin__', 'builtins'):
    main()
