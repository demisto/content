"""ExpanseAggregateAttributionUser

"""

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

from typing import Dict, List, Any, Tuple
import traceback


''' STANDALONE FUNCTION '''


def deconstruct_entry(entry: Dict[str, str],
                      username_fields: List[str],
                      sightings_fields: List[str]) -> Tuple[Optional[str],
                                                            Optional[str],
                                                            Optional[int]]:
    username = next((entry[field] for field in username_fields if field in entry), None)
    sightings = next((int(entry[field]) for field in sightings_fields if field in entry), 1)

    domain = None
    if username is not None and "\\" in username:
        domain, username = username.split("\\", 1)

    return username, domain, sightings


''' COMMAND FUNCTION '''


def aggregate_command(args: Dict[str, Any]) -> CommandResults:
    input_list = argToList(args.get('input', []))
    current_list = argToList(args.get('current', []))

    username_fields = argToList(args.get('username_fields', "source_user,srcuser,user"))
    sightings_fields = argToList(args.get('sightings_fields', "count"))

    current_users = {
        f"{d['username']}::{d['domain']}": d
        for d in current_list if d is not None
    }

    for entry in input_list:
        if not isinstance(entry, dict):
            continue

        username, domain, sightings = deconstruct_entry(
            entry,
            username_fields=username_fields,
            sightings_fields=sightings_fields
        )

        if username is None:
            continue
        if domain is None:
            domain = ""

        user_key = f"{username}::{domain}"
        current_state = current_users.get(user_key, None)
        if current_state is None:
            current_state = {
                'username': username,
                'domain': domain,
                'sightings': 0,
                'groups': [],
                'description': None,
            }
            current_users[user_key] = current_state

        if sightings is not None:
            current_state['sightings'] += sightings

    markdown = '## ExpanseAggregateAttributionUser'
    outputs = list(current_users.values())

    return CommandResults(
        readable_output=markdown,
        outputs=outputs if len(outputs) > 0 else None,
        outputs_prefix="Expanse.AttributionUser",
        outputs_key_field=["username", "domain"]
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(aggregate_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute ExpanseAggregateAttributionUser. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
