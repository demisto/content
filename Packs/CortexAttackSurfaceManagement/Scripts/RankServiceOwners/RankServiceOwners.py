from collections.abc import Iterable, Callable
from typing import Any
import google.cloud.storage
import numpy as np
import posixpath
import dill as pickle
import os
import itertools
import string
import re
import math
from itertools import groupby
import traceback
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
demisto.debug('pack name = Cortex Attack Surface Management, pack version = 1.7.65')


"""Script for identifying and recommending the most likely owners of a discovered service
from those surfaced by Cortex ASM Enrichment.
"""


STRING_DELIMITER = ' | '  # delimiter used for joining source fields and any additional fields of type string

# Normalize owner scores to be within the following bounds.
# We want to use a standard scale (e.g. between 0 and 1) for interpretability.
# However, we expect that normalizing to greater-than-half "probabilities" is
# likely more accurate, # given that there are stringent conditions on initial detection
# such that any name should be considered well-attested and likely to be an owner.
SCORE_LOWER_BOUND = 0.5
SCORE_UPPER_BOUND = 1.0


def load_pickled_xpanse_object(file_name: str, cache_path: str = "/tmp/xpanse-ml") -> Any:
    """
    Returns the pickled object at `file_name` as a Python object,
    either using the local cache or retrieving from the
    remote bucket as needed.

    The default cache is a subdirectory of /tmp directory will cache persistently across interactions.
    Data saved to /var/lib/demisto will be lost betwen interactions (not cached).
    """
    remote_gcs_bucket = "xpanse-service-ownership-ml-models"
    remote_gcs_path = ""  # ok for this to be empty string

    os.makedirs(cache_path, exist_ok=True)
    cached_file_path = os.path.join(cache_path, file_name)

    # check that file is not empty; if authorization fails it will
    # create the cache_path but the file will be empty
    if not (os.path.exists(cached_file_path) and os.path.getsize(cached_file_path)):
        # The relevant infrastructure-related service account needs to be granted
        # read access to the GCS bucket, or at least the resource at `remote_path`
        remote_path = posixpath.join(remote_gcs_path, file_name)

        demisto.info(f"Starting download of '{file_name}' from gs://{remote_gcs_bucket}/{remote_path}")
        client = google.cloud.storage.client.Client()
        bucket = client.bucket(remote_gcs_bucket)
        blob = bucket.blob(remote_path)
        blob.download_to_filename(cached_file_path)
        demisto.info(f"Downloaded '{file_name}' from gs://{remote_gcs_bucket}/{remote_path}")

    else:
        demisto.info(f"Found '{file_name}' locally")

    with open(cached_file_path, "rb") as f:
        return pickle.load(f)


def featurize(asm_system_ids: list[str], owners: list[dict[str, Any]]) -> np.ndarray:
    """
    Convert owners information into numerical array for model inference
    """
    pipeline = OwnerFeaturizationPipeline()
    feats = pipeline.featurize(asm_system_ids, owners)
    return feats


def normalize_scores(
    scores: list[float],
    lower_bound: float = SCORE_LOWER_BOUND,
    upper_bound: float = SCORE_UPPER_BOUND,
) -> list[float]:
    """
    Normalizes a list of non-negative reals to values in range specified by `lower_bound`
    and `upper_bound`
    """
    if lower_bound < 0 or upper_bound < 0:
        raise ValueError("Lower and upper bounds must be non-negative")
    if lower_bound > upper_bound:
        raise ValueError("Lower bound must be greater than or equal to upper bound")

    if not len(scores):
        return scores
    max_val = max(scores)
    min_val = min(scores)
    if max_val == min_val:
        return [upper_bound] * len(scores)
    return [
        round(((score - min_val) / (max_val - min_val) * (upper_bound - lower_bound) + lower_bound), ndigits=2)
        for score in scores
    ]


def score(owners: list[dict[str, Any]], asm_system_ids: list[str]) -> list[dict[str, Any]]:
    """
    Load the model, featurize inputs, score owners, normalize scores, and update the owners dicts

    If we fail to load or run inference with the model, return uniform scores of SCORE_LOWER_BOUND
    """
    def scoring_fallback(owners: list[dict[str, Any]]):
        for owner in owners:
            owner['ranking_score'] = SCORE_LOWER_BOUND
        return owners

    try:
        model = load_pickled_xpanse_object("service_owner_model.pkl")
    except Exception as ex:
        demisto.info(f"Error loading the model: {ex}. Using fallback scores")
        return scoring_fallback(owners)

    try:
        featurized = featurize(asm_system_ids=asm_system_ids, owners=owners)
        scores = model.predict(featurized)
    except Exception as ex:
        demisto.info(f"Error scoring the owners: {ex}. Using fallback scores")
        return scoring_fallback(owners)

    normalized = normalize_scores(scores)
    for owner, score in zip(owners, normalized):
        owner['ranking_score'] = score
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

    Strip "Chain: " from both `source` and `justification` fields as post-processing step.

    The "Chain: " prefix in the source indicates that the attribution of this owner
    is multi-step: e.g. first we recovered the service account, then we recovered the
    project owner for that service account.

    Future work may further unroll this chain, for instance: recover the manager
    of the project owner of the service account, which we would denote using a `source` value of:
    "Chain: Chain: Manager of GCP project owner of service account".

    The model takes the length of the chain into the account, with longer chains carrying less weight
    """
    for owner in owners:
        normalized_source = owner.get('source', '').replace('Chain: ', '')
        owner['source'] = normalized_source
        owner['justification'] = normalized_source
    return owners


def _canonicalize(owner: dict[str, Any]) -> dict[str, Any]:
    """
    Canonicalizes an owner dictionary and adds a deduplication key
    `canonicalization` whose value is either:
        1. whitespace-stripped and lower-cased email, if email exists
        2. whitespace-stripped and lower-cased name
        3. empty string if neither exists
    """
    if owner.get('email', ''):
        owner['canonicalization'] = owner['email'].strip().lower()
        owner['email'] = owner['canonicalization']
    elif owner.get('name', ''):
        owner['canonicalization'] = owner['name'].strip().lower()
        owner['name'] = owner['canonicalization']
    else:
        owner['canonicalization'] = ''
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
    sorted_owners = sorted(owners, key=lambda owner: owner['canonicalization'])
    for key, group in groupby(sorted_owners, key=lambda owner: owner['canonicalization']):
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
            'timestamp': timestamp
        }

        # aggregate remaining keys according to type
        all_keys = {k for owner in duplicates for k in owner}
        keys_to_types = {k: type(owner[k]) for owner in duplicates for k in owner}
        other_keys = []
        for key in all_keys:
            if key.lower() not in {'name', 'email', 'source', 'timestamp', 'canonicalization'}:
                other_keys.append(key)
        for other in other_keys:
            if keys_to_types[other] is str:
                # union over strings
                owner[other] = STRING_DELIMITER.join(sorted(
                    {owner.get(other, '') for owner in duplicates if owner.get(other, '')}
                ))
            elif keys_to_types[other] in (int, float):
                # max over numerical types
                owner[other] = max(owner.get(other, 0) for owner in duplicates)  # type: ignore
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


# Begin: Model Featurization Code
def generate_all_spaceless_monikers(personal_monikers: Iterable[str]) -> set[str]:
    """
    Return all the spaceless ways that `personal_monikers` (such as a name or
    email address) might manifest.

    Guaranteed lower case. Removes hyphens and quotes, and anything that
    looks like a domain of an email address.

    Example:
        personal_monikers = ["mike@example.com", "Michael Jordan"]
        returns: {"mike", "michael", "jordan", "mj", "mjordan"}
    """
    result_set = set()
    for moniker in personal_monikers:
        moniker = moniker.lower()
        if "@" in moniker:
            moniker = moniker[:moniker.index("@")]

        split_full_moniker: list[str] = [
            t.replace("-", "").replace("'", "") for t in moniker.split()
        ]
        result_set |= set(split_full_moniker)

        if len(split_full_moniker) >= 2:
            canonical_first_name: str = split_full_moniker[0]
            all_possible_first_names: list[str] = [canonical_first_name]
            last_name: str = split_full_moniker[-1]
            middle_names: list[str] = split_full_moniker[1:-1]

            # each name as a separate word
            result_set |= set(all_possible_first_names)
            # firstmiddlelast
            result_set.add(f"{canonical_first_name}{''.join(middle_names)}{last_name}")
            # firstlast
            for fname in all_possible_first_names:
                result_set.add(f"{fname}{last_name}")
            # fm+l
            for fname in all_possible_first_names:
                result_set.add(
                    f"{fname[0]}{''.join([m[0] for m in middle_names])}{last_name[0]}"
                )
            # fl
            for fname in all_possible_first_names:
                result_set.add(f"{fname[0]}{last_name[0]}")
            # flast
            for fname in all_possible_first_names:
                result_set.add(f"{fname[0]}{last_name}")
            # fm*last
            for fname in all_possible_first_names:
                result_set.add(
                    f"{fname[0]}{''.join([m[0] for m in middle_names])}{last_name}"
                )

    return result_set


def split_phrase(phrase: str) -> set[str]:
    """
    Return the human-readable subcomponents of `phrase`.
    Keep both sides of :-delimited pairs (kv pairs).

    This object allows us to run `in` commands correctly for `asset_name`.

    If asset_name has internal string structure, make it foremost.
    If it has no structure, run on the raw string.
    """
    SPLITTER = re.compile(r"[:\*_\.-]")

    all_components = set()
    if ":" in phrase:
        all_components |= {t.strip() for t in phrase.split(":")}
    all_components |= set(re.split(SPLITTER, phrase))

    for w in all_components.copy():
        all_components |= set(
            itertools.chain.from_iterable(re.findall(r"(\d*)([a-zA-Z]*)(\d*)", w))
        )

    all_components = {c.strip() for c in all_components if c}
    all_components -= {"", None}
    return all_components


def get_possible_3initials(personal_monikers: Iterable[str]) -> set[str]:
    """
    Tries to generate 3 initials from `personal_monikers`. If there
    is a middle name in `personal_monikers`, returns those results.
    Otherwise generates all possible middle initials for first/last.
    """
    result_set = set()
    for moniker in personal_monikers:
        moniker = moniker.lower()
        split_full_moniker: list[str] = moniker.split()

        if len(split_full_moniker) < 2:
            continue

        canonical_first_initial: str = split_full_moniker[0][0]
        last_initial: str = split_full_moniker[-1][0]
        middle_names: list[str] = split_full_moniker[1:-1]

        if middle_names:
            # abort early
            return {
                f"{canonical_first_initial}{''.join([m[0] for m in middle_names])}{last_initial}"
            }
        else:
            for hypothesized_letter in string.ascii_lowercase:
                result_set.add(
                    f"{canonical_first_initial}{hypothesized_letter}{last_initial}"
                )

    return result_set


def get_name_similarity_index(
    personal_monikers: Iterable[str],
    constant_name: str,
) -> float:
    """
    Returns an index into name similarity between `personal_monikers` and `constant_name`.

    Returns >=1 if there is a blatant match.
    Returns 0 if there is no match at all.
    Returns 0 to 1 if there is a potential match.

    Example:
        personal_monikers = ["mike@example.com", "Michael Jordan"]
        constant_name = "mj-test"
        returns: 1.0

        personal_monikers = ["mike@example.com", "Michael Jordan"]
        constant_name = "mbj-test"
        returns: .1
    """
    total_indicators = 0.0

    all_monikers: set[str] = map(  # type: ignore
        str.lower,
        generate_all_spaceless_monikers(personal_monikers),
    )
    all_monikers = {m for m in all_monikers if len(m) > 1}
    all_names = split_phrase(constant_name.lower())
    all_names = {n for n in all_names if len(n) > 1}

    for moniker in all_monikers:
        if moniker in all_names:
            demisto.info(f"Name similarity match: {constant_name} and {moniker}")
            total_indicators += 1
        else:
            for n in all_names:
                if moniker in n:
                    demisto.info(f"Name substring match: {constant_name} and {moniker}")
                    total_indicators += 0.01

    # check for a hypothesized-middle-initial match
    # for example, this may help us attest a dev server named mjj-test
    # (or mbj-test, or mij-test) to Michael Jordan
    hypothesized_initials = get_possible_3initials(personal_monikers) - all_monikers
    for hypothesized_initial in hypothesized_initials:
        if hypothesized_initial in all_names:
            demisto.info(f"Hypothesized initial match: {constant_name} and {moniker}")
            total_indicators += 0.1

    return total_indicators


class OwnerFeaturizationPipeline():
    def __init__(self, sources: list | None = None):
        """
        Initialize a featurization pipeline.
        """
        if sources is None:
            self.SOURCES = ["Azure", "GCP", "AWS", "Tenable", "Rapid7", "Qualys", "SNOW-CMDB", "Splunk", "PrismaCloud"]
        else:
            self.SOURCES = sources.copy()

        # features which only require contents of asmserviceowner as input
        self.OWNER_FEATURES: list[tuple[str, Callable]] = [
            ("num_reasons", self.get_num_reasons),
            ("num_distinct_sources", self.get_num_distinct_sources),
            ("min_path_length", self.get_min_path_length),
            ("is_attested_in_cmdb", self.get_in_cmdb),
            ("is_attested_in_recent_logs", self.get_in_logs)
        ]

        # features that require asmsystemid as an additional input
        self.SYSTEM_ID_FEATURES: list[tuple[str, Callable]] = [
            ("name_similarity_person_asset", self.get_name_similarity_person_asset),
        ]

        self.NUM_FEATURES = len(self.SYSTEM_ID_FEATURES) + len(self.OWNER_FEATURES)

    @staticmethod
    def _get_sources(owner: dict[str, Any]) -> list[str]:
        """
        Return a list of sources.
        """
        return owner.get("source", "").split(STRING_DELIMITER)

    def get_num_reasons(self, owner: dict[str, Any]) -> int:
        """
        Returns the number of reasons on `owner`.
        """
        return len(self._get_sources(owner))

    def get_num_distinct_sources(self, owner: dict[str, Any]) -> int:
        """
        Returns the number of distinct sources on `owner`.
        """
        distinct_sources = set()
        for src in self.SOURCES:
            if src.lower() in owner.get("source", "").lower():
                distinct_sources.add(src.lower())
        return len(distinct_sources)

    def get_min_path_length(self, owner: dict[str, Any]) -> Union[float, int]:
        """
        Returns the minimum path length to reach this owner.
        """
        min_path_length = float('inf')
        for src in self._get_sources(owner):
            src_path_length = 1
            while src.startswith("Chain: "):
                src_path_length += 1
                src = src[len("Chain: "):]
            if min_path_length is None or src_path_length < min_path_length:
                min_path_length = src_path_length
        return min_path_length

    def get_name_similarity_person_asset(self,
                                         service_identifiers: Iterable[str],
                                         owner: dict[str, Any]) -> float:
        """
        Returns >=1 if there is a blatant match between any `service_identifiers` and `owner`.
        Returns 0 if there is no match at all.
        Returns 0 to 1 if there is a potential match.
        """
        personal_monikers = [owner.get("email", ""), owner.get("name", "")]
        best_similarity = 0.0
        for service_id in service_identifiers:
            similarity = get_name_similarity_index(personal_monikers, service_id)
            if similarity > best_similarity:
                best_similarity = similarity
        return best_similarity

    def get_in_cmdb(self, owner: dict[str, Any]) -> int:
        """
        Return 1 if any `owner` is attested in any CMDB; 0 otherwise.
        """
        for src in self._get_sources(owner):
            if "CMDB" in src:
                return 1
        return 0

    def get_in_logs(self, owner: dict[str, Any]) -> int:
        """
        Return 1 if any `owner` is attested in any logs; 0 otherwise.
        """
        for src in self._get_sources(owner):
            if "Splunk" in src or "log" in src.lower():
                return 1
        return 0

    def featurize(self, service_identifiers: Iterable[str], owners: list[dict[str, Any]]) -> np.ndarray:
        """
        Generate a featurized numpy array from `service_identifiers` and `owners`.
        """
        X = np.zeros((len(owners), self.NUM_FEATURES))
        for sample_idx, owner in enumerate(owners):
            # Iterate over features which require both system ID and owner as inputs
            feature_idx = 0
            for (method_name, method) in self.SYSTEM_ID_FEATURES:
                try:
                    X[sample_idx, feature_idx] = method(service_identifiers, owner)
                except Exception as e:
                    demisto.info(f"Setting 0 for {method_name} because of processing exception: {e}")
                    X[sample_idx, feature_idx] = 0
                finally:
                    feature_idx += 1

            # Iterate over features which only require the owner as input
            for (method_name, method) in self.OWNER_FEATURES:
                try:
                    X[sample_idx, feature_idx] = method(owner)
                except Exception as e:
                    demisto.info(f"Setting 0 for {method_name} because of processing exception: {e}")
                    X[sample_idx, feature_idx] = 0
                finally:
                    feature_idx += 1
        return X


def write_output_to_context_key(final_owners: list[dict[str, str]], owner_related_field: str, platform_tenant: str):
    stringify_platform_tenant = str(platform_tenant)
    set_alert_issue_map = {"True": "setIssue", "False": "setAlert"}
    if final_owners and owner_related_field:
        res = demisto.executeCommand(set_alert_issue_map[stringify_platform_tenant], {owner_related_field: final_owners})
        if isError(res):
            raise ValueError('Unable to update field')
        return_results(CommandResults(readable_output=f"Owners ranked and written to {owner_related_field}"))
    else:
        return_results(CommandResults(readable_output='No owners found'))


def main():
    try:
        # parse inputs
        unranked = demisto.args().get("owners", [])
        if isinstance(unranked, dict):
            unranked = [unranked]
        asm_system_ids = demisto.args().get("asmsystemids", [])
        owner_related_field = demisto.args().get("ownerrelatedfield", "asmserviceowner")
        platform_tenant_usage = demisto.args().get("tenantcommand", "False")
        # deduplicate/normalize, score, and rank owners
        normalized = aggregate(canonicalize(unranked))
        final_owners = justify(rank(score(owners=normalized, asm_system_ids=asm_system_ids)))

        write_output_to_context_key(final_owners=final_owners,
                                    owner_related_field=owner_related_field,
                                    platform_tenant=platform_tenant_usage)

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute RankServiceOwners. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
