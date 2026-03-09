import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from AggregatedCommandApiModule import *


def _is_cidr(value: str) -> bool:
    """Check if a value looks like a CIDR notation (e.g., 1.1.1.0/24, 10.0.0.0/8, 2001:db8::/32).

    Args:
        value: The string to check.

    Returns:
        True if the value matches CIDR-like patterns, False otherwise.
    """
    if "/" not in value:
        return False
    parts = value.split("/", 1)
    # CIDR: left side is an IP-like pattern, right side is a small number (mask)
    try:
        mask = int(parts[1])
        if 0 <= mask <= 128:  # valid for both IPv4 (/0-/32) and IPv6 (/0-/128)
            left = parts[0]
            if all(c in "0123456789.:abcdefABCDEF" for c in left) and ("." in left or ":" in left):
                return True
    except ValueError:
        pass
    return False


def normalize_urls(url_list: list[str]) -> list[str]:
    """
    Normalize URL inputs by ensuring they have a scheme where appropriate.

    The server's extractIndicators command recognizes URLs by matching patterns
    that start with a protocol (http://, https://, ftp://, hxxps://) or common
    URL prefixes (www., ftp.) even without a protocol.

    This function prepends 'https://' to inputs that look like URLs but lack a
    scheme — specifically values starting with 'www.' or 'ftp.' (matching the
    server's URL regex behavior), as well as values containing a path component
    (e.g., 'example.com/path') which clearly indicate URL intent.

    Defanged inputs (e.g., 'www[.]example[.]com') are left as-is since prepending
    a scheme would create malformed URLs.

    CIDR notations (e.g., '1.1.1.0/24') are left as-is since they are not URLs.

    Bare domains without these signals (e.g., 'example.com', 'openclaw.ai') are
    left as-is so extractIndicators correctly classifies them as domains, and the
    action reports them as invalid URL inputs.

    Args:
        url_list (list[str]): Raw URL inputs from the user.

    Returns:
        list[str]: Normalized URL list.
    """
    # Only non-defanged prefixes — defanged variants (www[.], ftp[.]) are excluded
    # because prepending https:// to them creates malformed URLs (e.g., https://www[.]example[.]com)
    URL_PREFIXES = ("www.", "ftp.")
    SCHEME_PREFIXES = ("http://", "https://", "ftp://", "hxxp://", "hxxps://")

    normalized = []
    for url in url_list:
        url = url.strip()
        if not url:
            continue

        url_lower = url.lower()

        # If it already has a scheme, keep as-is
        if url_lower.startswith(SCHEME_PREFIXES):
            normalized.append(url)
        # If it starts with a known URL prefix (www., ftp.), add https://
        elif url_lower.startswith(URL_PREFIXES):
            demisto.debug(f"Normalizing URL '{url}' by prepending 'https://'")
            normalized.append(f"https://{url}")
        # If it contains a path separator and is not a CIDR notation, it's likely a URL
        # e.g., 'example.com/path/to/page' but NOT '1.1.1.0/24' or '10.0.0.0/8'
        elif "/" in url and not _is_cidr(url):
            demisto.debug(f"Normalizing URL '{url}' (contains path) by prepending 'https://'")
            normalized.append(f"https://{url}")
        else:
            # Keep as-is — let extractIndicators decide the type
            # Bare domains like 'example.com' will be classified as domains, not URLs
            normalized.append(url)
    return normalized


def url_enrichment_script(
    url_list: list[str],
    external_enrichment: bool = False,
    verbose: bool = False,
    enrichment_brands: list[str] = [],
    additional_fields: bool = False,
    args: dict[str, Any] = {},
) -> CommandResults:
    """
    Enriches URL data with information from various integrations
    Args:
        url_list (list[str]): List of URLs to enrich.
        external_enrichment (bool): Whether to call external integrations for enrichment.
        verbose (bool): Whether to print verbose output.
        enrichment_brands (list[str]): List of brands to enrich with.
        additional_fields (bool): Whether to include additional fields in the output.
    Returns:
        CommandResult: The result of the command.
    """
    demisto.debug("Normalizing URL inputs")
    url_list = normalize_urls(url_list)
    demisto.debug(f"Normalized URL list: {url_list}")

    demisto.debug("Extracting indicators")
    url_instances, extract_verbose = create_and_extract_indicators(url_list, "url")
    valid_inputs = [url_instance.extracted_value for url_instance in url_instances if url_instance.extracted_value]

    indicator_mapping = {
        "Data": "Data",
        "DetectionEngines": "DetectionEngines",
        "PositiveDetections": "PositiveDetections",
        "Score": "Score",
        "Brand": "Brand",
    }
    url_indicator_schema = IndicatorSchema(
        type="url",
        value_field="Data",
        context_path_prefix="URL(",  # add ( to prefix to distinct from URLhaus integration context path
        context_output_mapping=indicator_mapping,
    )

    # Only create command batches if there are valid inputs to process
    if valid_inputs:
        # --- Command Batch 1: create indicators (BUILTIN) ---
        demisto.debug("Creating commands - Batch 1: Creating new indicators")
        command_batch1: list[Command] = [
            Command(
                name="CreateNewIndicatorsOnly",
                args={"indicator_values": valid_inputs, "type": "URL"},
                command_type=CommandType.BUILTIN,
                context_output_mapping=None,
                ignore_using_brand=True,
            )
        ]

        # --- Command Batch 2: external enrichment ---
        demisto.debug("Creating commands - Batch 2: Enriching indicators")
        command_batch2: list[Command] = [
            Command(
                name="enrichIndicators",
                args={"indicatorsValues": valid_inputs},
                command_type=CommandType.EXTERNAL,
            )
        ]

        commands = [command_batch1, command_batch2]
        demisto.debug("Commands: ")
        for i, batch in enumerate(commands):
            demisto.debug(f"Batch {i}")
            for j, cmd in enumerate(batch):
                demisto.debug(f"Command {j}: {cmd}")
    else:
        demisto.debug("No valid URL inputs found. Skipping command batches.")
        commands = []

    url_reputation = ReputationAggregatedCommand(
        brands=enrichment_brands,
        verbose=verbose,
        commands=commands,
        additional_fields=additional_fields,
        external_enrichment=external_enrichment,
        final_context_path="URLEnrichment",
        args=args,
        indicator_instances=url_instances,
        indicator_schema=url_indicator_schema,
        verbose_outputs=[extract_verbose],
    )
    return url_reputation.run()


""" MAIN FUNCTION """


def main():  # pragma: no cover
    args = demisto.args()
    url_list = argToList(args.get("url_list"))
    external_enrichment = argToBoolean(args.get("external_enrichment", False))
    verbose = argToBoolean(args.get("verbose", False))
    brands = argToList(args.get("brands", []))
    additional_fields = argToBoolean(args.get("additional_fields", False))
    demisto.debug(f"Data list: {url_list}")
    demisto.debug(f"Brands: {brands}")
    try:
        return_results(url_enrichment_script(url_list, external_enrichment, verbose, brands, additional_fields, args))
    except Exception as ex:
        return_error(f"Failed to execute !url-enrichment. Error: {str(ex)}")


""" ENTRY POINT """
if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
