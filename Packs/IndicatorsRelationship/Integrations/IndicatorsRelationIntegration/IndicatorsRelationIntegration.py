from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' HELPER FUNCTIONS '''


def create_relation() -> EntityRelation:
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


''' COMMAND FUNCTIONS '''


def test_module() -> str:
    return 'ok'


def fetch_indicators_command():
    relation = create_relation()
    indicators = [{
            'Value': "10.140.50.9",
            'Type': 'IP',
            'rawJSON': {},
            'fields': {},
            'Relationships': relation.to_context()
        }]
    return indicators


def create_relation_command(args: Dict[str, Any]) -> CommandResults:

    return CommandResults(
        relations=[create_relation()],
        readable_output="Relation-created"
    )


''' MAIN FUNCTION '''


def main() -> None:
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        if demisto.command() == 'fetch-indicators':
            indicators = fetch_indicators_command()
            # we submit the indicators in batches
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)
        if demisto.command() == 'test-module':
            return_results(test_module())

        elif demisto.command() == 'create-relation-integration':
            return_results(create_relation_command(demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
