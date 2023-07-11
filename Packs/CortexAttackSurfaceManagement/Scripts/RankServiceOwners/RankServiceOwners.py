import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""Script for identifying and recommending the most likely owners of a discovered service
from those surfaced by Cortex ASM Enrichment.
"""

import traceback
from itertools import groupby
import math

import re
import string
import itertools
import os
import dill as pickle
import posixpath
import numpy as np
import google.cloud.storage

from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.linear_model import LinearRegression
from sklearn.preprocessing import FunctionTransformer

from typing import Iterable, List, Dict, Any, Optional, Set, Callable, Tuple
from nicknames import NickNamer


STRING_DELIMITER = ' | '  # delimiter used for joining Source fields and any additional fields of type string

# The /tmp directory will cache persistently across interactions.
# Data saved to /var/lib/demisto will be lost betwen interactions (not cached).
LOCAL_MODEL_CACHE_PATH = "/tmp/xpanse-ml"

# GCP_PROJECT = "qa2-test-9996075903380"
# GCP_PROJECT = "engine-qa2-test-9996075903380" # default, converted to explicit arg
REMOTE_GCS_BUCKET = "qadium-datascience-plantains-dev"
REMOTE_GCS_PATH = "2023/afr-service-ownership/public"  # ok for this to be empty string

MODEL_FILE_NAME = "service_owner_model.pkl"


def get_heuristic_regression(reason_weight=1,
                             src_weight=(1 / 1000),
                             similarity_weight=10,
                             cmdb_weight=30,
                             log_weight=3) -> LinearRegression:
    """
    Returns a fitted linear model that is parameterized using the provided weights.
    """

    coefficients = np.array([reason_weight, src_weight, similarity_weight, cmdb_weight, log_weight])

    X_train = np.random.rand(len(coefficients), len(coefficients))
    y_train = X_train.dot(coefficients)

    model = LinearRegression(fit_intercept=False)
    model.fit(X_train, y_train)

    assert np.allclose(coefficients, model.coef_)
    return model


def get_elementwise_inversion() -> Pipeline:
    """
    Returns a fitted transformer that inverts vectors x elementwise to 1/x.
    """
    return Pipeline([
        ("squeeze", FunctionTransformer(np.squeeze, kw_args={"axis": 1})),
        ("create square matrix", FunctionTransformer(np.diag)),
        ("invert square matrix", FunctionTransformer(np.linalg.inv)),
        ("retrieve vector", FunctionTransformer(np.diag)),
    ])


def get_base_score_fields() -> ColumnTransformer:
    """
    Returns a fitted ColumnTransformer that retrieves the appropriate fields.
    """
    idx_num_reasons = 0
    idx_num_distinct_sources = 1
    idx_name_similarity_person_asset = 3
    idx_is_attested_in_cmdb = 4
    idx_is_attested_in_recent_logs = 5

    X_train = np.random.rand(5, 6)
    y_train = np.random.rand(5, 1)
    ct = ColumnTransformer(
        transformers=[
            (
                "retain (# reasons, # srcs, similarity, in cmdb, in logs)",
                "passthrough",
                [
                    idx_num_reasons,
                    idx_num_distinct_sources,
                    idx_name_similarity_person_asset,
                    idx_is_attested_in_cmdb,
                    idx_is_attested_in_recent_logs
                ]
            )
        ]
    )
    ct.fit(X_train, y_train)
    return ct


def get_path_length_field() -> ColumnTransformer:
    """
    Returns a fitted ColumnTransformer that retrieves the appropriate field.
    """
    idx_min_path_length = 2

    X_train = np.random.rand(5, 6)
    y_train = np.random.rand(5, 1)
    ct = ColumnTransformer([
        ("retain (min path length)", "passthrough", [idx_min_path_length])
    ])
    ct.fit(X_train, y_train)
    return ct


def get_model():
    """
    Returns a fitted overall model for [num_samples, 6]-shaped inputs.

    Columns are:
    0: num_reasons (1 or larger)
    1: num_distinct_sources (1 or larger)
    2: min_path_length (1 or larger)
    3: name_similarity_person_asset (float >=0: 0 is 'no similarity', >1 is 'very similar', and 0-1 is 'some similarity)
    4: is_attested_in_cmdb (0 or 1)
    5: is_attested_in_recent_logs (0 or 1)
    """
    invert_for_path_length = Pipeline([
        ("select path column", get_path_length_field()),
        ("invert elementwise to 1/x", get_elementwise_inversion()),
        ("turn vector into an array",
         FunctionTransformer(np.expand_dims, kw_args={"axis": 1})),
    ])

    score_the_owners = Pipeline([
        ("select relevant columns", get_base_score_fields()),
        ("get unscaled base predicted score", get_heuristic_regression()),
    ])

    overall_pipeline = Pipeline([
        ('scale inputs for path length',
         FunctionTransformer(lambda X: np.multiply(invert_for_path_length.transform(X),
                                                   X))),
        ('predict', score_the_owners)
    ])

    return overall_pipeline


def load_pickled_xpanse_object(file_name: str) -> Any:
    """
    Returns the pickled object at `file_name` as a Python object,
    either using the local cache or retrieving from the
    remote bucket as needed.
    """
    os.makedirs(LOCAL_MODEL_CACHE_PATH, exist_ok=True)
    cache_path = os.path.join(LOCAL_MODEL_CACHE_PATH, file_name)

    if not os.path.exists(cache_path):
        remote_path = posixpath.join(REMOTE_GCS_PATH, file_name)

        demisto.info(f"Starting download of '{file_name}' from gs://{REMOTE_GCS_BUCKET}/{remote_path}")
        client = google.cloud.storage.client.Client()
        bucket = client.bucket(REMOTE_GCS_BUCKET)
        blob = bucket.blob(remote_path)
        blob.download_to_filename(cache_path)
        demisto.info(f"Downloaded '{file_name}' from gs://{REMOTE_GCS_BUCKET}/{remote_path}")
    else:
        demisto.info(f"Found '{file_name}' locally")

    with open(cache_path, "rb") as f:
        return pickle.load(f)


def featurize(asm_system_ids: List[str], owners: List[Dict[str, Any]]) -> np.ndarray:
    """
    Featurize owners
    """
    pipeline = OwnerFeaturizationPipeline()
    feats = pipeline.featurize(asm_system_ids, owners)
    return feats

def normalize(scores: List[float]) -> List[float]:
    """
    Normalizes a score with respect to total and maps it to a value between 0.5 and 1
    """
    total = sum(scores)
    return [score / total / 2 + 0.5 for score in scores]


def normalize_scores(owners: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Normalizes a list of non-negative reals to values between 0.5 and 1

    We want to show greater-than-half probabilities to the end user
    for the sake of confidence/psychological comfort
    """
    normalized = normalize(owner['Ranking Score'] for owner in owners)
    for owner, score in zip(owners, normalized):
        owner['Ranking Score'] = score
    return owners


def score(owners: List[Dict[str, Any]], asm_system_ids: List[str]) -> List[Dict[str, Any]]:
    """
    Loads the model from cache or downloads from GCS and scores owners
    """
    model = load_pickled_xpanse_object(MODEL_FILE_NAME)
    featurized = featurize(asm_system_ids=asm_system_ids, owners=owners)
    scores = model.predict(featurized)
    for owner, score in zip(owners, scores):
        owner['Ranking Score'] = score
    return owners


def rank(owners: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Sort owners by ranking score and use data-driven algorithm to return the top k,
    where k is a dynamic value based on the relative scores

    See _get_k for hyperparameters that can be used to adjust the target value of k
    """
    k = _get_k(scores=(owner['Ranking Score'] for owner in owners))
    return sorted(owners, key=lambda x: x['Ranking Score'], reverse=True)[:k]


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
    if owner.get('email', ''):
        owner['Canonicalization'] = owner['email'].strip().lower()
        owner['email'] = owner['Canonicalization']
    elif owner.get('name', ''):
        owner['Canonicalization'] = owner['name'].strip().lower()
        owner['name'] = owner['Canonicalization']
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
        email = duplicates[0].get('email', '')
        # the if condition in the list comprehension below defends against owners whose Name value is None (not sortable)
        names = sorted(
            [owner.get('name', '') for owner in duplicates if owner.get('name')],
            key=lambda x: len(x), reverse=True
        )
        name = names[0] if names else ''
        # aggregate Source by union
        source = STRING_DELIMITER.join(sorted(
            {owner.get('source', '') for owner in duplicates if owner.get('source', '')}
        ))
        # take max Timestamp if there's at least one; else empty string
        timestamps = sorted(
            [owner.get('timestamp', '') for owner in duplicates if owner.get('timestamp', '')], reverse=True
        )
        timestamp = timestamps[0] if timestamps else ''
        owner = {
            'Name': name,
            'Email': email,
            'Source': source,
            'Timestamp': timestamp,
            # 'Count': len(duplicates)
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


# Model Featurization Code
def generate_all_spaceless_monikers(
    personal_monikers: Iterable[str], nicknamer: Optional[NickNamer] = None
) -> Set[str]:
    """
    Return all the spaceless ways that `personal_monikers` might manifest.
    Guaranteed lower case. Removes hyphens and quotes, and anything that
    looks like a domain of an email address.

    Includes nicknames if `nicknamer` is passed.
    """
    result_set = set()
    for moniker in personal_monikers:
        moniker = moniker.lower()
        if "@" in moniker:
            moniker = moniker[:moniker.index("@")]

        split_full_moniker: List[str] = [
            t.replace("-", "").replace("'", "") for t in moniker.split()
        ]
        result_set |= set(split_full_moniker)

        if len(split_full_moniker) >= 2:
            canonical_first_name: str = split_full_moniker[0]
            all_possible_first_names: List[str] = [canonical_first_name]
            last_name: str = split_full_moniker[-1]
            middle_names: List[str] = split_full_moniker[1:-1]

            # add nicknames
            if nicknamer:
                for nick in nicknamer.nicknames_of(canonical_first_name):
                    all_possible_first_names.append(nick)
            else:
                demisto.info(
                    f"Need a nicknamer to include possible nicknames for {canonical_first_name}"
                )

            # each name as a separate word
            result_set |= set(all_possible_first_names)
            # firstmiddlelast
            # (we don't include nicknames because use of middle is very formal)
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


def split_phrase(phrase: str) -> Set[str]:
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
        all_components |= set(t.strip() for t in phrase.split(":"))
    all_components |= set(re.split(SPLITTER, phrase))

    for w in all_components.copy():
        all_components |= set(
            itertools.chain.from_iterable(re.findall(r"(\d*)([a-zA-Z]*)(\d*)", w))
        )

    all_components = set([c.strip() for c in all_components if c])
    all_components -= set(["", None])
    return all_components


def get_possible_3initials(personal_monikers: Iterable[str]) -> Set[str]:
    """
    Tries to generate 3 initials from `personal_monikers`. If there
    is a middle name in `personal_monikers`, returns those results.
    Otherwise generates all possible middle initials for first/last.
    """
    result_set = set()
    for moniker in personal_monikers:
        moniker = moniker.lower()
        split_full_moniker: List[str] = moniker.split()

        if len(split_full_moniker) < 2:
            continue

        canonical_first_initial: str = split_full_moniker[0][0]
        last_initial: str = split_full_moniker[-1][0]
        middle_names: List[str] = split_full_moniker[1:-1]

        if middle_names:
            # abort early
            return set(
                [
                    f"{canonical_first_initial}{''.join([m[0] for m in middle_names])}{last_initial}"
                ]
            )
        else:
            for hypothesized_letter in string.ascii_lowercase:
                result_set.add(
                    f"{canonical_first_initial}{hypothesized_letter}{last_initial}"
                )

    return result_set


def get_name_similarity_index(
    personal_monikers: Iterable[str],
    constant_name: str,
    nicknamer: Optional[NickNamer] = None,
) -> float:
    """
    Returns an index into name similarity between `personal_monikers` and `constant_name`.
    Set `nicknamer` if you want to resolve cases with nicknames (like ["Daniel"] to
    `dan-test`).

    Returns >=1 if there is a blatant match.
    Returns 0 if there is no match at all.
    Returns 0 to 1 if there is a potential match.

    Note:
    We can't use word embeddings for nicknames. For instance, cosine similarities:
        dan, daniel -> 0.736
        daniel, jason -> 0.747
    Instead we hand-curated nicknames via a (small) package.
    """
    total_indicators = 0.0

    all_monikers: Set[str] = map(  # type: ignore
        str.lower,
        generate_all_spaceless_monikers(personal_monikers, nicknamer=nicknamer),
    )
    all_monikers = set([m for m in all_monikers if len(m) > 1])
    all_names = split_phrase(constant_name.lower())
    all_names = set([n for n in all_names if len(n) > 1])

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
    # we want this because gmj-test --> George Jones (gejones)
    hypothesized_initials = get_possible_3initials(personal_monikers) - all_monikers
    for hypothesized_initial in hypothesized_initials:
        if hypothesized_initial in all_names:
            demisto.info(f"Hypothesized initial match: {constant_name} and {moniker}")
            total_indicators += 0.1

    return total_indicators


class OwnerFeaturizationPipeline():
    def __init__(self, sources: Optional[List] = None):
        """
        Initialize a featurization pipeline.

        As of May 2023, we use `sources` to parse out which sources are included in the
        RC-provided owner data. The "parse the sources for a parallel list of known
        sources" approach is quite fragile (it requires us to release a new model every
        time RC adds a new source if the model wants to use that new source as a new source);
        we should work with RC to change the data format so that this approach is less
        fragile.
        """
        if sources is None:
            # Hardcoding is true as of May 2023.
            # To get the fields available as Sources, within the `content` repo, search the path
            # `/Users/ptoman/Documents/Projects/content/Packs/CortexAttackSurfaceManagement`
            # for `Name,Email,Source,Timestamp`.

            # FIXME (plt 2023.06): work with RC to retain Source System directly from the `owners` metadata
            # (rather than trying to maintain truth for who the owners can be separately here and in the
            # playbooks, and then trying to parse it out of `owners` metadata)
            self.SOURCES = ["Azure", "GCP", "AWS", "Tenable", "Rapid7", "Qualys", "SNOW-CMDB", "Splunk", "PrismaCloud"]
        else:
            self.SOURCES = sources.copy()

        self.FEATURES: List[Tuple[str, Callable]] = [
            ("num_reasons", self.get_num_reasons),
            ("num_distinct_sources", self.get_num_distinct_sources),
            ("min_path_length", self.get_min_path_length),
            ("name_similarity_person_asset", self.get_name_similarity_person_asset),
            ("is_attested_in_cmdb", self.get_in_cmdb),
            ("is_attested_in_recent_logs", self.get_in_logs)
        ]

    @staticmethod
    def _get_sources(owner: Dict[str, Any]) -> List[str]:
        """
        Return a list of Sources.
        """
        return owner.get("Source", "").split(" | ")

    def get_num_reasons(self, owner: Dict[str, Any]) -> int:
        """
        Returns the number of reasons on `owner`.
        """
        return len(self._get_sources(owner))

    def get_num_distinct_sources(self, owner: Dict[str, Any]) -> int:
        """
        Returns the number of distinct sources on `owner`.
        """
        # FIXME: current implementation is vulnerable to false string matches
        # solution is for RC to provide a field specifically for "Remote System Sources" that we can count
        distinct_sources = set([])
        for src in self.SOURCES:
            if src.lower() in owner.get("Source", "").lower():
                distinct_sources.add(src.lower())
        return len(distinct_sources)

    def get_min_path_length(self, owner: Dict[str, Any]) -> Union[float, int]:
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
                                         owner: Dict[str, Any]) -> float:
        """
        Returns >=1 if there is a blatant match between any `service_identifiers` and `owner`.
        Returns 0 if there is no match at all.
        Returns 0 to 1 if there is a potential match.
        """
        personal_monikers = [owner.get("Email", ""), owner.get("Name", "")]
        best_similarity = 0.0
        for service_id in service_identifiers:
            similarity = get_name_similarity_index(personal_monikers, service_id)
            if similarity > best_similarity:
                best_similarity = similarity
        return best_similarity

    def get_in_cmdb(self, owner: Dict[str, Any]) -> int:
        """
        Return 1 if any `owner` is attested in any CMDB; 0 otherwise.
        """
        for src in self._get_sources(owner):
            if "CMDB" in src:
                return 1
        return 0

    def get_in_logs(self, owner: Dict[str, Any]) -> int:
        """
        Return 1 if any `owner` is attested in any logs; 0 otherwise.
        """
        for src in self._get_sources(owner):
            if "Splunk" in src or "log" in src.lower():
                return 1
        return 0

    def featurize(self, service_identifiers: Iterable[str], owners: List[Dict[str, Any]]) -> np.ndarray:
        """
        Generate a featurized numpy array from `service_identifiers` and `owners`.
        """
        X = np.zeros((len(owners), len(self.FEATURES)))
        for sample_idx, owner in enumerate(owners):
            for feature_idx, (method_name, method) in enumerate(self.FEATURES):
                try:
                    if "similarity" in method_name and "person" in method_name and "asset" in method_name:
                        X[sample_idx, feature_idx] = method(service_identifiers, owner)
                    else:
                        X[sample_idx, feature_idx] = method(owner)
                except Exception as e:
                    demisto.error(f"Setting 0 for {method_name} because of processing exception: {e}")
                    X[sample_idx, feature_idx] = 0
        return X


def main():
    try:
        # parse inputs
        unranked = demisto.args().get("owners", [])
        asm_system_ids = demisto.args().get("asmsystemids", [])

        # score and rank owners
        normalized = aggregate(canonicalize(unranked))
        top_k = rank(score(owners=normalized, asm_system_ids=asm_system_ids))
        final_owners = justify(normalize_scores(top_k))

        # write output to context
        demisto.executeCommand("setAlert", {"asmserviceowner": final_owners})
        return_results(CommandResults(readable_output='Service owners ranked and written to asmserviceowner'))

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute IdentifyServiceOwners. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
