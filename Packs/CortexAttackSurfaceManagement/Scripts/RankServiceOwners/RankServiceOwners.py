import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""Script for identifying and recommending the most likely owners of a discovered service
from those surfaced by Cortex ASM Enrichment.
"""


from typing import Dict, List, Any
import traceback
from itertools import groupby


def score(owners: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Owner score is the number of observations on that owner divided by the max number of observations
    for any owner in the list

    Expects `Count` key and replaces it with `Ranking Score`
    """
    if owners:
        max_count = max(owner.get('Count', 1) for owner in owners)
        for owner in owners:
            count = owner.pop('Count', 1)
            owner['Ranking Score'] = count / max_count
    return owners


def rank(owners: List[Dict[str, Any]], k: int = 5) -> List[Dict[str, Any]]:
    """
    Return up to k owners with the highest ranking scores
    """
    if k <= 0:
        raise ValueError(f'Number of owners k={k} must be greater than zero')
    return sorted(owners, key=lambda x: x['Ranking Score'])[:k]


def justify(owners: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """
    For now, `Justification` is the same as `Source`; in the future, will sophisticate
    """
    for owner in owners:
        owner['Justification'] = owner.get('Source', '')
    return owners


def _canonicalize(owner: Dict[str, Any]) -> Dict[str, Any]:
    """
    Canonicalizes an owner dictionary and adds a deduplication key
    `Canonicalization` whose value is either:
        1. whitespace-stripped and lower-cased email, if email exists
        2. whitespace-stripped and lower-cased name
        3. empty string if neither exists
    """
    if owner.get('Email', ''):
        owner['Canonicalization'] = owner['Email'].strip().lower()
        owner['Email'] = owner['Canonicalization']
    elif owner.get('Name', ''):
        owner['Canonicalization'] = owner['Name'].strip().lower()
        owner['Name'] = owner['Canonicalization']
    else:
        owner['Canonicalization'] = ''
    return owner


def canonicalize(owners: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    """
    Calls _canonicalize on each well-formatted owner; drops and logs malformated inputs
    """
    canonicalized = []
    try:
        for owner in owners:
            try:
                canonicalized.append(_canonicalize(owner))
            except Exception as e:
                demisto.error(f"Unable to canonicalize {owner}: {e}")
    except Exception as e:
        demisto.error(f"`owners` must be iterable: {e}")
    return canonicalized


def aggregate(owners: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    """
    Aggregate owners by their canonicalization.

    If canonicalized form is email, preserve longest name.
    Preserve max timestamp and union over sources.

    Aggregate remaining keys by type: union over strings, and max over numerical types.
    If type is neither of the above, all values of that key will be dropped from the aggregated owner.
    """
    deduped = []
    sorted_owners = sorted(owners, key=lambda owner: owner['Canonicalization'])
    for key, group in groupby(sorted_owners, key=lambda owner: owner['Canonicalization']):
        duplicates = list(group)
        email = duplicates[0].get('Email', '')
        # the if condition in the list comprehension below defends against owners whose Name value is None (not sortable)
        names = sorted(
            [owner.get('Name', '') for owner in duplicates if owner.get('Name')],
            key=lambda x: len(x), reverse=True
        )
        name = names[0] if names else ''
        # aggregate Source by union
        source = ' | '.join(sorted(
            set(owner.get('Source', '') for owner in duplicates if owner.get('Source', ''))
        ))
        # take max Timestamp if there's at least one; else empty string
        timestamps = sorted(
            [owner.get('Timestamp', '') for owner in duplicates if owner.get('Timestamp', '')], reverse=True
        )
        timestamp = timestamps[0] if timestamps else ''
        owner = {
            'Name': name,
            'Email': email,
            'Source': source,
            'Timestamp': timestamp,
            'Count': len(duplicates)
        }

        # aggregate remaining keys according to type
        all_keys = set(k for owner in duplicates for k in owner.keys())
        keys_to_types = {k: type(owner[k]) for owner in duplicates for k in owner.keys()}
        other_keys = all_keys - {'Name', 'Email', 'Source', 'Timestamp', 'Canonicalization'}
        for other in other_keys:
            if keys_to_types[other] == str:
                # union over strings
                owner[other] = ' | ' .join(sorted(
                    set(owner.get(other, '') for owner in duplicates if owner.get(other, ''))
                ))
            elif keys_to_types[other] in (int, float):
                # max over numerical types
                owner[other] = max(owner.get(other, 0) for owner in duplicates)
            else:
                demisto.info(f'Cannot aggregate owner detail {other} -- removing from service owner')
                continue
        deduped.append(owner)
    return deduped


def main():
    try:
        owners = demisto.args().get("owners", [])
        top_k = justify(rank(score(aggregate(canonicalize(owners)))))
        demisto.executeCommand("setAlert", {"asmserviceowner": top_k})
        return_results(CommandResults(readable_output='top 5 service owners written to asmserviceowner'))

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute IdentifyServiceOwners. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
