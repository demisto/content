
from CommonServerPython import *

from typing import Dict, Any
import traceback

''' STANDALONE FUNCTION '''


def create_relation():
    return EntityRelation(name="Relation A -> B - Name",
                          reverse_name="Relation B -> A - Name",
                          relation_type="uses",
                          entity_a="STIX Attack Pattern",
                          entity_a_family="Bootstrap attack",
                          object_type_a="Indicator",
                          entity_b="10.140.50.9",
                          entity_b_family="IP",
                          object_type_b="Indicator",
                          source_reliability="A+",
                          fields={})


''' COMMAND FUNCTION '''


def create_relation_command(args: Dict[str, Any]) -> CommandResults:
    return CommandResults(relations=[create_relation()])


''' MAIN FUNCTION '''


def main():
    try:
        return_results(create_relation_command(demisto.args()))
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute create-relation automation. Error: {str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
