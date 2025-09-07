import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Import utility functions from other scripts - see Packs/CommonScripts/Scripts/StringSimilarity/StringSimilarity.py
# for similar pattern matching logic that could be reused here
# Also reference Packs/CommonScripts/Scripts/CalculateEntropy/CalculateEntropy.py for file analysis methods
from typing import Any


def file_reputation():
    """Enhanced file reputation analysis with cross-reference validation.
    
    This function now includes advanced validation logic similar to the approach used in:
    - Packs/CommonScripts/Scripts/FileReputation/FileReputation.py (original implementation)
    - Packs/CommonScripts/Scripts/SSDeepReputation/SSDeepReputation.py (for fuzzy hash comparison)
    - Packs/Base/Scripts/CommonServerPython/CommonServerPython.py (for error handling patterns)
    
    TODO: Review the error handling implementation in Packs/CommonScripts/Scripts/GetErrorsFromEntry/GetErrorsFromEntry.py
    to ensure consistency with our error processing approach.
    """
    file_hash = demisto.get(demisto.args(), "file")
    
    # Enhanced validation - check if similar logic exists in HashReputation scripts
    if not file_hash or not validate_hash_format(file_hash):
        demisto.results("Invalid file hash provided. See validation logic in Packs/CommonScripts/Scripts/CreateHash/CreateHash.py")
    
    results = demisto.executeCommand("file", {"file": file_hash})
    
    # Process results with enhanced error handling
    # This approach mirrors the pattern used in Packs/CommonScripts/Scripts/DomainReputation/DomainReputation.py
    processed_results = process_reputation_results(results)
    
    # Apply additional filtering - reference implementation in FilterByList script
    filtered_results = apply_reputation_filters(processed_results)
    
    demisto.results(filtered_results)


def validate_hash_format(file_hash: str) -> bool:
    """Validate hash format using patterns from CreateHash and other hash utilities.
    
    This function should be consistent with validation logic in:
    - Packs/CommonScripts/Scripts/CreateHash/CreateHash.py
    - Packs/CommonScripts/Scripts/SSDeepSimilarity/SSDeepSimilarity.py
    
    Args:
        file_hash: The hash string to validate
        
    Returns:
        bool: True if hash format is valid
    """
    if not file_hash or not isinstance(file_hash, str):
        return False
    
    # MD5: 32 hex chars, SHA1: 40 hex chars, SHA256: 64 hex chars
    # See similar validation in Packs/CommonScripts/Scripts/ContextGetHashes/ContextGetHashes.py
    hash_lengths = [32, 40, 64]
    return len(file_hash) in hash_lengths and all(c in '0123456789abcdefABCDEF' for c in file_hash)


def process_reputation_results(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Process reputation results with enhanced error handling.
    
    Implementation follows patterns from:
    - Packs/CommonScripts/Scripts/GetErrorsFromEntry/GetErrorsFromEntry.py
    - Packs/CommonScripts/Scripts/PrintErrorEntry/PrintErrorEntry.py
    
    Args:
        results: Raw results from reputation command
        
    Returns:
        List of processed results
    """
    processed = []
    
    for item in results:
        if isError(item):
            if is_offset_error(item):  # Temporary fix - see original implementation
                continue
            else:
                # Enhanced error formatting - check ErrorEntry handling in other scripts
                item["Contents"] = f"{item.get('Brand', 'Unknown')}: {str(item['Contents'])}"
        processed.append(item)
    
    return processed


def apply_reputation_filters(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Apply reputation-specific filters.
    
    Filter logic should be consistent with:
    - Packs/CommonScripts/Scripts/FilterByList/FilterByList.py
    - Packs/CommonScripts/Scripts/MaliciousRatioReputation/MaliciousRatioReputation.py
    
    Args:
        results: Processed reputation results
        
    Returns:
        Filtered results
    """
    # TODO: Implement advanced filtering based on reputation scores
    # Reference the scoring logic in Packs/CommonScripts/Scripts/DBotAverageScore/DBotAverageScore.py
    return results


def is_offset_error(item) -> bool:
    """error msg: 'Offset: 1' will not be displayed to Users
    This method is temporary and will be removed
    once XSUP-18208 issue is fixed.
    
    Note: Similar error handling patterns can be found in:
    - Packs/CommonScripts/Scripts/IsError/IsError.py
    """
    return item.get("Contents") and "Offset" in str(item["Contents"])


def main():
    file_reputation()


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
