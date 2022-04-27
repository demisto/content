import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""
Creates a TIR
"""
import json

from typing import Dict
import traceback

''' STANDALONE FUNCTION '''

FIELDS_FOR_CREATETHREATINTELREPORT = {'aliases', 'appendMultiSelect', 'appendTags', 'bodycampaign',
                                      'bodyexecutivebrief', 'bodymalware', 'bodythreatactor',
                                      'bodyvulnerability', 'creator', 'cve', 'cvss', 'description',
                                      'firstseen', 'firstseenbysource', 'fuzzyhash', 'goals', 'indicatortype',
                                      'lastseen', 'logo', 'malwaretype', 'modified', 'name', 'objective',
                                      'operatingsystem', 'primarymotivation', 'published', 'reportstatus',
                                      'roles', 'secondarymotivations', 'sophistication', 'source',
                                      'tags', 'targeting', 'threatactor', 'threatactortypes',
                                      'trafficlightprotocol', 'type', 'value', 'vulnerabilitytype',
                                      'xsoarReadOnlyRoles', 'mispdistributionid', 'mispeventuuid', 'mispthreatlevelid',
                                      'mispeventid',
                                      }


def create_tir_data(args: dict):
    tir_data = args.get('tir_data', '')
    tir_data: dict = json.loads(tir_data)
    relationships_to_create = tir_data.get('relationships')

    create_tir_args = {}
    for key, value in tir_data.items():
        if key in FIELDS_FOR_CREATETHREATINTELREPORT:
            create_tir_args[key] = value

    if 'tirsourceid' in tir_data.keys() and tir_data['tirsourceid']:
        # create a new TIR from an exising TIR
        create_tir_args['tirsourceid'] = tir_data['tirsourceid']
    elif 'id' in tir_data.keys():
        # create a new TIR
        create_tir_args['tirsourceid'] = tir_data['id']

    results = execute_command('createThreatIntelReport', create_tir_args)
    if results:
        if 'Failed to execute' in results:
            raise DemistoException(f"createThreatIntelReport failed")
    tir_id = results.get('id')
    tir_type = results.get('type')

    if not tir_id or not tir_type:
        raise DemistoException('could not create relationship due to empty values')

    outputs = {'tir_id': tir_id, 'tir_type': tir_type}
    if relationships_to_create:
        re_list = create_relations_list(relationships_to_create, tir_id, tir_type)
        return CommandResults(relationships=re_list, readable_output=f'TIR {tir_id} with relationships created successfully.',
                              outputs=outputs, outputs_prefix="CreateTIRFromPubSub")
    else:
        return CommandResults(readable_output=f'TIR {tir_id} created successfully.', outputs=outputs, outputs_prefix="CreateTIRFromPubSub")


def create_relations_list(relationships_to_create, tir_id, tir_type):
    re_list = []
    for related_object in relationships_to_create:
        create_tir_relationship_args = create_relationships_for_tir(tir_id=tir_id,
                                                                    tir_type=tir_type,
                                                                    related_object=related_object)
        result = execute_command('CreateTIRRelationship', create_tir_relationship_args, False)
        if result:
            if 'Failed to execute' in result:
                raise DemistoException(f"CreateTIRRelationship failed. relaionship wasn't created.")
            else:
                relationships = result[0]['Metadata']['Relationships']
                r = relationships[0]
                en = EntityRelationship(
                    entity_a_family='ThreatIntelReport',
                    entity_b_family='Indicator',
                    name=r.get('name'),
                    entity_a=r.get('entityA'),
                    entity_a_type=r.get('entityAType'),
                    entity_b=r.get('entityB'),
                    entity_b_type=r.get("entityBType"),
                    brand=r.get("brand"),
                    fields={
                        "description": r.get('description')
                    }
                )
                re_list.append(en)
    return re_list


def create_relationships_for_tir(tir_id: str, tir_type: str, related_object: Dict[str, str]):
    related_object_value = related_object.get('value')
    related_object_type = related_object.get('type')
    relationship_name = related_object.get('name')
    return {
        'entity_a': tir_id,
        'entity_a_type': tir_type,
        'entity_b': related_object_value,
        'entity_b_type': related_object_type,
        'relationship': relationship_name
    }


def main():
    try:
        return_results(create_tir_data(demisto.args()))

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute SetTIRData. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
