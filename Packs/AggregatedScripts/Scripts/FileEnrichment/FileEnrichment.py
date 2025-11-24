import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from AggregatedCommandApiModule import *

INTERNAL_ENRICHMENT_BRANDS = ["WildFire-v2"]

FILE_HASH_TYPES = [
    "MD5",
    "SHA1",
    "SHA256",
    "SHA512",
    "CRC32",
    "CTPH",
    "SSDeep",
    "ImpHash",
]

# Used as well for determining Main keys
# What not under this list will go to AdditionalFields
INDICATOR_MAPPING = {
    "MD5": "MD5",
    "SHA1": "SHA1",
    "SHA256": "SHA256",
    "SHA512": "SHA512",
    "CRC32": "CRC32",
    "CTPH": "CTPH",
    "SSDeep": "SSDeep",
    "ImpHash": "ImpHash",
    "SourceTimeStamp": "SourceTimeStamp",
    "Modified": "Modified",
    "Path": "Path",
    "Size": "Size",
    "FileExtension": "FileExtension",
    "AssociatedFileNames": "AssociatedFileNames",
    "Brand": "Brand",
    "Score": "Score",
}


def file_enrichment_script(
    file_list: list[str],
    external_enrichment: bool = False,
    verbose: bool = False,
    enrichment_brands: list[str] = [],
    additional_fields: bool = False,
    args: dict[str, Any] = {},
) -> CommandResults:
    """
    Enriches File data with information from various integrations
    Args:
        file_list (list[str]): List of Files to enrich.
        external_enrichment (bool): Whether to call external integrations for enrichment.
        verbose (bool): Whether to print verbose output.
        enrichment_brands (list[str]): List of brands to enrich with.
        additional_fields (bool): Whether to include additional fields in the output.
    Returns:
        CommandResults: The result of the command.
    """
    demisto.debug("Extracting indicators")
    file_list = extract_indicators(file_list, "file")

    file_indicator = Indicator(
        type="file",
        value_field=FILE_HASH_TYPES,
        context_path_prefix="File",
        context_output_mapping=INDICATOR_MAPPING,
    )

    # --- Command Batch 1: create indicators (BUILTIN) ---
    command_batch1: list[Command] = [
        Command(
            name="CreateNewIndicatorsOnly",
            args={"indicator_values": file_list, "type": "File"},
            command_type=CommandType.BUILTIN,
            context_output_mapping=None,
            ignore_using_brand=True,
        )
    ]

    # --- Command Batch 2: external enrichment + Core IR---
    command_batch2: list[Command] = [
        Command(
            name="enrichIndicators",
            args={"indicatorsValues": file_list},
            command_type=CommandType.EXTERNAL,
        ),
    ] + [
        Command(
            name="core-get-hash-analytics-prevalence",
            args={"sha256": file},
            brand="Cortex Core - IR",
            command_type=CommandType.INTERNAL,
            context_output_mapping={},
        )
        for file in file_list
        if get_hash_type(file) == "sha256"
    ]

    commands = [command_batch1, command_batch2]
    demisto.debug("Commands Batches")
    for i, batch in enumerate(commands):
        demisto.debug(f"Batch {i}")
        for j, cmd in enumerate(batch):
            demisto.debug(f"Command {j}: {cmd}")

    file_reputation = ReputationAggregatedCommand(
        brands=enrichment_brands,
        verbose=verbose,
        commands=commands,
        additional_fields=additional_fields,
        internal_enrichment_brands=INTERNAL_ENRICHMENT_BRANDS,
        external_enrichment=external_enrichment,
        final_context_path="FileEnrichment",
        args=args,
        data=file_list,
        indicator=file_indicator,
    )
    return file_reputation.run()



""" MAIN FUNCTION """


def main():  # pragma: no cover
    args = demisto.args()
    file_list = argToList(args.get("file_hash"))
    external_enrichment = argToBoolean(args.get("external_enrichment", False))
    verbose = argToBoolean(args.get("verbose", False))
    brands = argToList(args.get("brands", []))
    additional_fields = argToBoolean(args.get("additional_fields", False))
    demisto.debug(f"Data list: {file_list}")
    demisto.debug(f"Brands: {brands}")
    try:
        return_results(file_enrichment_script(file_list, external_enrichment, verbose, brands, additional_fields, args))
    except Exception as ex:
        return_error(f"Failed to execute !file-enrichment. Error: {str(ex)}")


""" ENTRY POINT """
if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
