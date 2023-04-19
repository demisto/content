import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""Script for identifying and recommending the most likely owners of a discovered service
from those surfaced by Cortex ASM Enrichment.
"""


from typing import Dict, List, Any
import traceback
from itertools import groupby
from collections.abc import Iterable, Mapping


def score(owners: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Owner score is the number of observations on that owner divided by the max number of observations
    for any owner in the list

    Expects `Count` key and replaces it with `Confidence Score`; this function should be run after
    `deduplicate` and before `rank`
    """
    if len(owners):
        max_count = max(x['Count'] for x in owners)
        for i in range(len(owners)):
            count = owners[i].pop('Count')
            owners[i]['Confidence Score'] = count / max_count
    return owners


def rank(owners: List[Dict[str, Any]], k: int = 5) -> List[Dict[str, Any]]:
    """
    Sort by confidence and return top k
    """
    return sorted(owners, key=lambda x: x['Confidence Score'])[:k]


def justify(owners: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """
    For now, `Justification` is the same as `Source`; in the future, will sophisticate
    """
    for i in range(len(owners)):
        owners[i]['Justification'] = owners[i]['Source']
    return owners


def deduplicate(owners: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    """
    Deduplicate by white-stripped email address; if none provided, deduplicate by name.
    Take max timestamp for each deduplicated owner and take a union over their sources.
    """
    deduped = []
    for email, group in groupby(sorted(owners, key=lambda x: x["Email"]), key=lambda x: x["Email"].strip()):
        if email == '':
            # deduplicate by name if no email is found
            for name, subgroup in groupby(sorted(group, key=lambda x: x["Name"]), key=lambda x: x['Name']):
                sg = list(subgroup)
                source = ' | '.join(sorted(set([x['Source'] for x in sg])))
                timestamp = sorted([x['Timestamp'] for x in sg], reverse=True)[0]
                owner = {
                    'Name': name,
                    'Email': email,
                    'Source': source,
                    'Timestamp': timestamp,
                    'Count': len(sg)
                }
                deduped.append(owner)

        else:
            # deduplicate by email
            g = list(group)
            source = ' | '.join(sorted(set([x['Source'] for x in g])))
            name = sorted([x['Name'] for x in g], key=lambda x: len(x), reverse=True)[0]
            timestamp = sorted([x['Timestamp'] for x in g], reverse=True)[0]
            owner = {
                'Name': name,
                'Email': email.strip(),
                'Source': source,
                'Timestamp': timestamp,
                'Count': len(g)
            }
            deduped.append(owner)
    return deduped


def validate_input(owners: Any) -> List[Dict[str, str]]:
    """
    Drop inputs of invalid type and ensure required dictionary keys are present
    """
    if not isinstance(owners, Iterable):
        return []

    # drop non-dictionary inputs
    owners = [dict(owner) for owner in owners if isinstance(owner, Mapping)]

    # ensure required keys are present and replace invalidly-typed values with empty strings
    for i in range(len(owners)):
        for key in ('Name', 'Source', 'Email', 'Timestamp'):
            if key not in owners[i] or owners[i][key] is None:
                owners[i][key] = ''

            # cast values to strings if not already
            owners[i][key] = str(owners[i][key])

    return owners


def main():
    try:
        owners = validate_input(demisto.args()["owners"])
        top_k = justify(rank(score(deduplicate(owners))))
        demisto.executeCommand("setAlert", {"asmserviceowner": top_k})
        return_results(CommandResults(readable_output='top 5 service owners written to asmserviceowner'))

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
