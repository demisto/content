import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback
from collections.abc import Mapping
from typing import Any, Dict, List


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


def is_dev_according_to_key_value_pairs(observed_key_value_pairs: List[Dict[str, Any]]) -> bool:
    """
    Returns whether the key-value pairs in `observed_key_value_pairs` explicitly & solely contain
    an indication of "dev"ness. Indicators of "dev"ness were learned by AI from a large
    corpus of canonically tagged infrastructure, designed to capture many ways in which
    "dev" infrastructure might manifest within different operating environments.

    If `observed_key_value_pairs` has indicators of both prod AND dev, returns False;
    `observed_key_value_pairs` does not describe a definitively "development" role server.

    Args:
        observed_key_value_pairs (List[Dict[str, Any]]): list of key-value dictionaries;
            each dictionary within the list must contain the keys "Key" and "Value";
            the values are arbitrary
            Example value for `observed_key_value_pairs`:
                [{"Key": "env", "Source": "AWS", "Value": "dev"},
                 {"Key": "Name", "Source": "AWS", "Value": "ssh-ec2-machine-name"}]

    Returns:
        bool: whether `observed_key_value_pairs` indicates that the described system is
            used solely for development (has development indicators and lacks any
            production indicators)
    """

    has_dev_indicator = False
    has_prod_indicator = False
    for kv_pair in observed_key_value_pairs:
        if not isinstance(kv_pair, Mapping):
            demisto.info(f"Ignoring item because it is not a mapping: {kv_pair}")
        else:
            if "Key" not in kv_pair or "Value" not in kv_pair:
                demisto.info(f"Ignoring item because it lacks the keys 'Key' and/or 'Value': {sorted(kv_pair.keys())}")
            else:
                key = _canonicalize_string(kv_pair.get("Key", ""))
                value = _canonicalize_string(kv_pair.get("Value", ""))

                if ("env" in key) or (key in ("stage", "function", "lifecycle", "usage", "tier")):
                    if (("dev" in value and "devops" not in value)
                            or ("uat" in value and "prod" not in value)
                            or any([m == value for m in EXACT_DEV_MATCH])
                            or any([m in value for m in PARTIAL_DEV_MATCH])):
                        has_dev_indicator = True
                    elif (any([m == value for m in EXACT_PROD_MATCH])
                          or any([m in value for m in PARTIAL_PROD_MATCH])):
                        has_prod_indicator = True

    if has_dev_indicator and not has_prod_indicator:
        return True
    else:
        return False


def is_dev_according_to_classifications(classifications: List[str]) -> bool:
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
        bool: whether there is an indication within `classifications` that
            the described system is used for development
    """
    is_dev = (DEV_ENV_CLASSIFICATION in classifications)
    return is_dev


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
            each dictionary within the list must contain the keys "Key" and "Value";
            the values are arbitrary
            Example value for `observed_key_value_pairs`:
                [{"Key": "env", "Source": "AWS", "Value": "dev"},
                 {"Key": "Name", "Source": "AWS", "Value": "ssh-ec2-machine-name"}]
        active_classifications (List[str]): list of Xpanse ASM classification terms
            (a defined vocabulary)
            Example value for `classifications`:
                ["RdpServer", "SelfSignedCertificate"]

    Returns:
        No return value.
        Two side effects:
        1. Update the "alert" context with a boolean value named `asmdevcheck`
           that is True if there is a consistent indicator of dev-ness in the arguments,
           and is False otherwise
        2. Update the warroom with a statement of whether the service is dev
    """
    try:
        args = demisto.args()

        internal_tags: List[Dict[str, Any]] = argToList(args.get("asm_tags", [{}]))
        is_dev_internal = is_dev_according_to_key_value_pairs(internal_tags)

        external_active_classifications: List[str] = argToList(args.get("active_classifications", []))
        is_dev_external = is_dev_according_to_classifications(external_active_classifications)

        dev_or_not = is_dev_internal or is_dev_external
        demisto.executeCommand("setAlert", {"asmdevcheck": dev_or_not})
        if dev_or_not:
            return_results(CommandResults(readable_output='the service is development'))
        else:
            return_results(CommandResults(readable_output='the service is not development'))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute InferWhetherServiceIsDev. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
