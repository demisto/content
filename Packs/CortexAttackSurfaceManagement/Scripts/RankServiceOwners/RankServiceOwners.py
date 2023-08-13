import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""Script for identifying and recommending the most likely owners of a discovered service
from those surfaced by Cortex ASM Enrichment.
"""


from typing import Any
from collections.abc import Iterable
import traceback
from itertools import groupby
import math

STRING_DELIMITER = ' | '  # delimiter used for joining source fields and any additional fields of type string


def score(owners: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Owner score is the number of observations on that owner divided by the max number of observations
    for any owner in the list

    Expects `Count` key and replaces it with `ranking_score`
    """
    if owners:
        max_count = max(owner.get('Count', 1) for owner in owners)
        for owner in owners:
            count = owner.pop('Count', 1)
            owner['ranking_score'] = count / max_count
    return owners


def rank(owners: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Sort owners by ranking score and use data-driven algorithm to return the top k,
    where k is a dynamic value based on the relative scores

    See _get_k for hyperparameters that can be used to adjust the target value of k
    """
    k = _get_k(scores=(owner['ranking_score'] for owner in owners))
    return sorted(owners, key=lambda x: x['ranking_score'], reverse=True)[:k]


def justify(owners: list[dict[str, str]]) -> list[dict[str, str]]:
    """
    For now, `justification` is the same as `source`; in the future, will sophisticate
    """
    for owner in owners:
        owner['justification'] = owner.get('source', '')
    return owners


def _canonicalize(owner: dict[str, Any]) -> dict[str, Any]:
    """
    Canonicalizes an owner dictionary and adds a deduplication key
    `Canonicalization` whose value is either:
        1. whitespace-stripped and lower-cased email, if email exists
        2. whitespace-stripped and lower-cased name
        3. empty string if neither exists
    """
    if owner.get('email', ''):
        owner['Canonicalization'] = owner['email'].strip().lower()
        owner['email'] = owner['Canonicalization']
    elif owner.get('name', ''):
        owner['Canonicalization'] = owner['name'].strip().lower()
        owner['name'] = owner['Canonicalization']
    else:
        owner['Canonicalization'] = ''
    return owner


def canonicalize(owners: list[dict[str, str]]) -> list[dict[str, Any]]:
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


def aggregate(owners: list[dict[str, str]]) -> list[dict[str, Any]]:
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
        email = duplicates[0].get('email', '')
        # the if condition in the list comprehension below defends against owners whose name value is None (not sortable)
        names = sorted(
            [owner.get('name', '') for owner in duplicates if owner.get('name')],
            key=lambda x: len(x), reverse=True
        )
        name = names[0] if names else ''
        # aggregate source by union
        source = STRING_DELIMITER.join(sorted(
            {owner.get('source', '') for owner in duplicates if owner.get('source', '')}
        ))
        # take max timestamp if there's at least one; else empty string
        timestamps = sorted(
            [owner.get('timestamp', '') for owner in duplicates if owner.get('timestamp', '')], reverse=True
        )
        timestamp = timestamps[0] if timestamps else ''
        owner = {
            'name': name,
            'email': email,
            'source': source,
            'timestamp': timestamp,
            'Count': len(duplicates)
        }

        # aggregate remaining keys according to type
        all_keys = {k for owner in duplicates for k in owner}
        keys_to_types = {k: type(owner[k]) for owner in duplicates for k in owner}
        other_keys = []
        for key in all_keys:
            if key.lower() not in {'name', 'email', 'source', 'timestamp', 'canonicalization'}:
                other_keys.append(key)
        for other in other_keys:
            if keys_to_types[other] == str:
                # union over strings
                owner[other] = STRING_DELIMITER.join(sorted(
                    {owner.get(other, '') for owner in duplicates if owner.get(other, '')}
                ))
            elif keys_to_types[other] in (int, float):
                # max over numerical types
                owner[other] = max(owner.get(other, 0) for owner in duplicates)
            else:
                demisto.info(f'Cannot aggregate owner detail {other} -- removing from service owner')
                continue
        deduped.append(owner)
    return deduped


def _get_k(
    scores: Iterable[float],
    target_k: int = 5,
    k_tol: int = 2,
    a_tol: float = 1.0,
    min_score_proportion: float = 0.75
) -> int:
    """
    Return a value of k such that:
    - target_k >= k <= target_k + k_tol
    - the top k scores comprise minimum specified proportion of the total score mass

    See unit tests in RankServiceOwners_test.py for a more detailed specification of the
    expected behavior.

    Notable hyperparameters (which are tuned to target_k=5) and where they come from:

    :param target_k: the value of k we are roughly targeting (set by discussion with PM)
    :param k_tol: our tolerance for k, or how many additional owners above `target_k` we are willing to show
        (set by intuition/discussion with PM)
    :param a_tol: max expected absolute different between two scores in the same "tier"
        (set by intuition; see unit tests)
    :param min_score_proportion: the targeted min proportion of the score mass
        (identified using a gridsearch over values to find best outcome on unit tests)
    """
    if target_k < 0:
        raise ValueError("target_k must be non-negative")
    if k_tol < 0:
        raise ValueError("k_tol must be non-negative")
    if a_tol < 0:
        raise ValueError("a_tol must be non-negative")
    if min_score_proportion < 0 or min_score_proportion > 1:
        raise ValueError("min_score_proportion must be a value between 0 and 1")

    # get up to target_k scores that comprise the desired score proportion
    scores_desc = sorted(scores, reverse=True)
    min_score_proportion = sum(scores_desc) * min_score_proportion
    k = 0
    cumulative_score = 0.0
    while cumulative_score < min_score_proportion and k < target_k:
        cumulative_score += scores_desc[k]
        k += 1

    # score values are likely groupable into "tiers"; try to find a cutoff between tiers
    # look for the end of the next element's tier (may be the current or next tier),
    # where a tier is (arbitrarily) defined by an absolute difference of `a_tol`
    tier_index = k
    while tier_index < len(scores_desc) and math.isclose(scores_desc[tier_index], scores_desc[tier_index - 1], abs_tol=a_tol):
        tier_index += 1

    # add additional score(s) if within tolerance for k
    if math.isclose(target_k, tier_index, abs_tol=k_tol):
        k = tier_index

    return k


def main():
    try:
        unranked = demisto.args().get("owners", [])
        ranked = justify(rank(score(aggregate(canonicalize(unranked)))))
        demisto.executeCommand("setAlert", {"asmserviceowner": ranked})
        return_results(CommandResults(readable_output='Service owners ranked and written to asmserviceowner'))

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute IdentifyServiceOwners. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
