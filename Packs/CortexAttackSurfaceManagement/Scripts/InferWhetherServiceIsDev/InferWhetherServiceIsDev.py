import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


import traceback
from collections.abc import Mapping
from typing import Any
from collections.abc import Callable


DEV_ENV_CLASSIFICATION = "DevelopmentEnvironment"
EXACT_DEV_MATCH = ["dv", "noprod", "np", "ppe"]
PARTIAL_DEV_MATCH = ["stg", "stag", "qa", "quality", "test", "tst", "exp", "non_prod",
                     "non-prod", "nonprod", "nprd", "n-prd", "npe", "npd", "pre_prod",
                     "pre-prod", "preprod", "pprd", "pov", "proof of value", "poc",
                     "sbx", "sandbox", "internal", "validation", "lab"]
EXACT_PROD_MATCH = ["pr"]
PARTIAL_PROD_MATCH = ["prod", "prd", "release", "live"]


def _canonicalize_string(in_str: str) -> str:
    """
    Converts `in_str` to a canonical-for-dev-evaluation version of itself through:
    * lowercasing
    * stripping whitespace (space and tab)
    * stripping quotation marks (" and ')
    """
    return in_str.lower().strip(' \t"\'')


def get_indicators_from_key_value_pairs(observed_key_value_pairs: list, is_indicator_match: Callable) -> list:
    """
    Returns list of matches based on criteria.

    Args:
        observed_key_value_pairs (List[str]): list of tags to process.
        is_indicator_match (callable): what function to call depending on dev or prod checking.

    Returns:
        list: list of matches based on exact/partial dev criteria.
    """
    indicators = []
    for kv_pair in observed_key_value_pairs:
        if not isinstance(kv_pair, Mapping):
            demisto.info(f"Ignoring item because it is not a mapping: {kv_pair}")
        else:
            if "key" not in kv_pair or "value" not in kv_pair:
                demisto.info(f"Ignoring item because it lacks the keys 'key' and/or 'value': {sorted(kv_pair.keys())}")
            else:
                key = _canonicalize_string(kv_pair.get("key", ""))
                value = _canonicalize_string(kv_pair.get("value", ""))

                if (("env" in key) or (key in ("stage", "function", "lifecycle", "usage", "tier"))) and is_indicator_match(value):
                    indicators.append(kv_pair)

    return indicators


def is_dev_indicator(value: str) -> bool:
    """
     Returns boolean based on match on exact/partial dev criteria.

     Args:
         value (str): value of the kv pair of tag.

     Returns:
         bool: whether there was a match based on exact/partial dev criteria.
     """
    return (("dev" in value and "devops" not in value)
            or ("uat" in value and "prod" not in value)
            or any(m == value for m in EXACT_DEV_MATCH)
            or any(m in value for m in PARTIAL_DEV_MATCH))


def is_prod_indicator(value: str) -> bool:
    """
    Returns boolean based on match on exact/partial prod criteria.

    Args:
        value (str): value of the kv pair of tag.

    Returns:
        bool: whether there was a match based on exact/partial prod criteria.
    """
    # Check if matches dev first for values like "non-production"
    if is_dev_indicator(value):
        return False
    else:
        return (any(m == value for m in EXACT_PROD_MATCH)
                or any(m in value for m in PARTIAL_PROD_MATCH))


def get_indicators_from_external_classification(classifications: list[str]) -> list:
    """
    Returns whether any of the classification strings indicate that this service is
    a development environment. The Xpanse ASM classification strings are a defined
    vocabulary of facts that are derivable from the publicly observed service without
    joining on any additional data.

    Args:
        classifications (List[str]): list of Xpanse ASM classification terms
            (a defined vocabulary)
            Example value for `classifications`:
                ["RdpServer", "SelfSignedCertificate"]

    Returns:
        List: whether there is an indication within `classifications` that
            the described system is used for development.  Empty list means
            no matches.
    """
    ext_classification_match = [DEV_ENV_CLASSIFICATION] if DEV_ENV_CLASSIFICATION in classifications else []
    return ext_classification_match


def determine_reason(external_indicators: list, matches: list) -> str:
    """
    Craft the 'reason' for the final verdict of "development" server or not.

    Args:
        external_indicators (list): to determine there is an external service classification match.
            Empty list means no matches.
        matches (list): list of matches of tags with DEV or PROD characteristics.

    Returns:
        str: complete `reason` string to be added to the gridfield.
    """
    reason_parts = []
    if len(external_indicators) == 1:
        reason_parts.append("external classification of " + DEV_ENV_CLASSIFICATION)
    for match in matches:
        reason_parts.append("tag {" + f"{match.get('key')}: {match.get('value')}" + "} from " + match.get('source'))
    reason_final = "match on "
    for reason in reason_parts:
        reason_final += reason + ", "
    # Strip last ','
    reason_final = reason_final[:-2]
    # Replace last ','' with ' and '
    reason_final = " and ".join(reason_final.rsplit(", ", 1))
    return reason_final


def final_decision(external_indicators: list, dev_matches: list, prod_matches: list) -> dict:
    """
    Final decision to be set in gridfield.

    Args:
        external_indicators (list): list of matches of external service classification match.
        dev_matches (list): list of matches of tags with DEV characteristics.
        prod_matches (list): list of matches of tags with PROD characteristics.

    Returns:
        dict: dictionary to be added to gridfield.
    """
    final_dict: dict[str, Any] = {}
    if (len(external_indicators) == 1 or len(dev_matches) > 0) and len(prod_matches) == 0:
        final_dict["result"] = True
        final_dict["confidence"] = "Likely Development"
        reason_final = determine_reason(external_indicators, dev_matches)
        final_dict["reason"] = reason_final
    elif (len(external_indicators) == 1 or len(dev_matches) > 0) and len(prod_matches) > 0:
        final_dict["result"] = False
        final_dict["confidence"] = "Conflicting Information"
        reason_final = determine_reason(external_indicators, dev_matches + prod_matches)
        final_dict["reason"] = reason_final
    elif (len(external_indicators) == 0 and len(dev_matches) == 0) and len(prod_matches) > 0:
        final_dict["result"] = False
        final_dict["confidence"] = "Likely Production"
        reason_final = determine_reason(external_indicators, prod_matches)
        final_dict["reason"] = reason_final
    else:
        final_dict["result"] = False
        final_dict["confidence"] = "Not Enough Information"
        final_dict["reason"] = "Neither dev nor prod indicators found"
    # Create a more human readable table for war room.
    if final_dict.get("result", False):
        final_dict["result_readable"] = "The service is development"
    else:
        final_dict["result_readable"] = "The service is not development"
    return final_dict


""" MAIN FUNCTION """


def main():
    """
    Identifies whether the service is a "development" server. Development servers
    have no external users and run no production workflows. These servers might be
    named "dev", but they might also be named "qa", "pre-production", "user
    acceptance testing", or use other non-production terms. This automation uses
    both public data visible to anyone (`active_classifications` as derived by
    Xpanse ASM) as well as checking internal data for AI-learned indicators of
    development systems (`asm_tags` as derived from integrations with non-public
    systems).

    Args:
        asm_tags (List[Dict[str, Any]]): list of key-value dictionaries;
            each dictionary within the list must contain the keys "key" and "value";
            the values are arbitrary
            Example value for `observed_key_value_pairs`:
                [{"key": "env", "source": "AWS", "value": "dev"},
                 {"key": "Name", "source": "AWS", "value": "ssh-ec2-machine-name"}]
        active_classifications (List[str]): list of Xpanse ASM classification terms
            (a defined vocabulary)
            Example value for `classifications`:
                ["RdpServer", "SelfSignedCertificate"]
    Returns:
        No return value.
        Two side effects:
        1. Update the "alert" context with a values for `asmdevcheckdetails` gridfield.
           The `result` key is set as True if there is a consistent indicator of dev-ness
           in the arguments,and is False otherwise.  `confidence` and `reason` explain
           more about why the `result` key was marked as it is
        2. Update the warroom with a statement of whether the service is dev
    """
    try:
        args = demisto.args()

        internal_tags: list[dict[str, Any]] = argToList(args.get("asm_tags", [{}]))
        dev_kv_indicators = get_indicators_from_key_value_pairs(internal_tags, is_dev_indicator)
        prod_kv_indicators = get_indicators_from_key_value_pairs(internal_tags, is_prod_indicator)

        external_active_classifications: list[str] = argToList(args.get("active_classifications", []))
        external_indicators = get_indicators_from_external_classification(external_active_classifications)

        decision_dict = final_decision(external_indicators, dev_kv_indicators, prod_kv_indicators)
        demisto.executeCommand("setAlert", {"asmdevcheckdetails": [decision_dict]})

        output = tableToMarkdown("Dev Check Results", decision_dict, ['result_readable', 'confidence', 'reason'])
        return_results(CommandResults(readable_output=output))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute InferWhetherServiceIsDev. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
