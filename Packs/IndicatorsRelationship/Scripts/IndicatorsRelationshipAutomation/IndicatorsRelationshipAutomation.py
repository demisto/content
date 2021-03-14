
from CommonServerPython import *
import traceback

''' STANDALONE FUNCTION '''


def create_relation():
    return EntityRelation(name=demisto.getArg("name"),
                          reverse_name=demisto.getArg("reverse_name"),
                          relation_type=demisto.getArg("relation_type"),
                          entity_a=demisto.getArg("entity_a"),
                          entity_a_family=demisto.getArg("entity_a_family"),
                          object_type_a=demisto.getArg("object_type_a"),
                          entity_b=demisto.getArg("entity_b"),
                          entity_b_family=demisto.getArg("entity_b_family"),
                          object_type_b=demisto.getArg("object_type_b"),
                          source_reliability=demisto.getArg("source_reliability"),
                          fields={
                              "revoked": demisto.getArg("revoked")
                          },
                          brand=demisto.getArg("brand"))


''' COMMAND FUNCTION '''


def create_relation_command() -> CommandResults:
    return CommandResults(readable_output=f"Relation {demisto.getArg('name')} updated.", relations=[create_relation()])


''' MAIN FUNCTION '''


def main():
    try:
        return_results(create_relation_command())
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute create-relation automation. Error: {str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
