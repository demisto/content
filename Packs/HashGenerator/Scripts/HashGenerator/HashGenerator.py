import hashlib

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def generate_hash(text: str, hash_type: str) -> dict:
    """Generate a hash from a given input string.

    Args:
        text (str): The input text to hash.
        hash_type (str): The hash algorithm to use (md5, sha1, sha256).

    Returns:
        Dict[str, str]: Dictionary containing the hash results.
    """
    results = {}

    if hash_type == "all" or hash_type == "md5":
        md5_hash = hashlib.md5()  # nosec
        md5_hash.update(text.encode("utf-8"))
        results["MD5"] = md5_hash.hexdigest()

    if hash_type == "all" or hash_type == "sha1":
        sha1_hash = hashlib.sha1()  # nosec
        sha1_hash.update(text.encode("utf-8"))
        results["SHA1"] = sha1_hash.hexdigest()

    if hash_type == "all" or hash_type == "sha256":
        sha256_hash = hashlib.sha256()
        sha256_hash.update(text.encode("utf-8"))
        results["SHA256"] = sha256_hash.hexdigest()

    return {"HashGenerator": results}


def main():  # pragma: no cover
    args = demisto.args()
    text = args.get("text")
    hash_type = args.get("type", "all")

    if not text:
        return_error("The 'text' argument is required.")

    context = generate_hash(text, hash_type)

    readable_output = tableToMarkdown(
        "Hash Results",
        [{"Algorithm": k, "Hash": v} for k, v in context["HashGenerator"].items()],
        headers=["Algorithm", "Hash"]
    )

    return_results(CommandResults(
        outputs_prefix="HashGenerator",
        outputs=context["HashGenerator"],
        readable_output=readable_output
    ))


if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
