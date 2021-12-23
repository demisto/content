import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json


def get_tir_id(args):
    return args['tir_id']


def get_tir_data(tir_id):
    res = execute_command('getThreatIntelReport', {"id": tir_id})
    return res


def get_tir_relationships(tir_id, tir_type):
    results = execute_command('SearchIndicatorRelationships', {"entities": tir_id, "entities_types": tir_type})
    if results:
        relationships = [{"value": res.get('EntityB'), "type": res.get(
            'EntityBType'), "name": res.get('Relationship')} for res in results]
        return relationships
    return None


def main():
    try:
        args = demisto.args()
        tir_id = get_tir_id(args)

        tir_data = get_tir_data(tir_id)
        tir_type = tir_data['type']
        tir_data['relationships'] = get_tir_relationships(tir_id, tir_type)

        tir_data_str = json.dumps(tir_data)

        return_results(tir_data_str)

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
