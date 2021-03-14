from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' HELPER FUNCTIONS '''


def create_relation() -> EntityRelation:
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


''' COMMAND FUNCTIONS '''


def test_module() -> str:
    return 'ok'


def create_relation_command() -> CommandResults:
    return CommandResults(readable_output=f"Relation {demisto.getArg('name')} updated.", relations=[create_relation()])


''' MAIN FUNCTION '''


def main() -> None:
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        if demisto.command() == 'test-module':
            return_results(test_module())

        elif demisto.command() == 'create-relation-integration':
            return_results(create_relation_command())

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
