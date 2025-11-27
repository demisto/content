import json
import pytest
from pytest_mock import MockerFixture
from FileEnrichment import Brands, Command, CommandResults, ContextPaths, EntryType, Any


""" TEST CONSTANTS """

MD5_HASH = "md5md5md5md5md5md5md5md5md5md5md"
SHA_1_HASH = "sha1sha1sha1sha1sha1sha1sha1sha1sha1sha1"
SHA_256_HASH = "sha256sha256sha256sha256sha256sha256sha256sha256sha256sha256sha2"


def util_load_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.mark.parametrize(
    "command, enabled_brands, expected_has_enabled_instance",
    [
        pytest.param(
            Command("wildfire-get-verdict", {"file_hash": SHA_256_HASH}, Brands.WILDFIRE_V2),
            [Brands.WILDFIRE_V2.value],
            True,
            id="Command brand active, other brand disabled",
        ),
        pytest.param(
            Command("core-get-hash-analytics-prevalence", {"sha256": SHA_256_HASH}, Brands.CORE_IR),
            [Brands.WILDFIRE_V2.value],
            False,
            id="Command brand disabled, other brand active",
        ),
        pytest.param(
            Command("core-get-endpoints", {"limit": 10}, Brands.CORE_IR),
            [Brands.WILDFIRE_V2.value, Brands.CORE_IR.value],
            True,
            id="All brands active",
        ),
        pytest.param(
            Command("wildfire-get-sample", {"sha256": SHA_256_HASH}, Brands.WILDFIRE_V2),
            [],
            False,
            id="All brands disabled",
        ),
    ],
)
def test_command_has_enabled_instance(command: Command, enabled_brands: list[str], expected_has_enabled_instance: bool):
    """
    Given:
        - Command objects with source brand and arguments dictionaries and modules context from `demisto.getModules()`.

    When:
        - Calling `Command.has_enabled_instance`.

    Assert:
        - Ensure value is True if an integration instance of the brand is active. Otherwise, False.
    """
    assert command.has_enabled_instance(enabled_brands) == expected_has_enabled_instance


@pytest.mark.parametrize(
    "original_human_readable, is_error, expected_readable_output",
    [
        pytest.param(
            "This is a regular message",
            False,
            '#### Result for !wildfire-upload-url upload="http://www.example.com"\nThis is a regular message',
            id="Note Entry",
        ),
        pytest.param(
            "This is an error message",
            True,
            '#### Error for !wildfire-upload-url upload="http://www.example.com"\nThis is an error message',
            id="Error Entry",
        ),
    ],
)
def test_command_prepare_human_readable(original_human_readable: str, is_error: bool, expected_readable_output: str):
    """
    Given:
        - Command objects with source brand and arguments dictionaries.

    When:
        - Calling `Command.prepare_human_readable`.

    Assert:
        - Ensure correct human readable value with the appropriate title and message.
    """
    command = Command("wildfire-upload-url", {"upload": "http://www.example.com"}, Brands.WILDFIRE_V2)

    human_readable_command_results = command.prepare_human_readable(original_human_readable, is_error)

    assert human_readable_command_results.readable_output == expected_readable_output


def test_command_execute(mocker: MockerFixture):
    """
    Given:
        - A Command object with source brand and an arguments dictionary.

    When:
        - Calling `Command.execute`.

    Assert:
        - Ensure correctly parsed entry context and human-readable CommandResults from the execution response.
    """
    command = Command("file", {"file": SHA_256_HASH})

    demisto_execute_response = util_load_json("test_data/file_reputation_command_response.json")
    mock_demisto_execute = mocker.patch("FileEnrichment.demisto.executeCommand", return_value=demisto_execute_response)

    entry_context, readable_command_results = command.execute()

    assert mock_demisto_execute.call_count == 1
    assert entry_context[0] == demisto_execute_response[0]["EntryContext"]
    assert readable_command_results[0].readable_output == (
        f"#### Result for {command}\n{demisto_execute_response[0]['HumanReadable']}"
    )


def test_get_file_from_ioc_custom_fields():
    """
    Given:
        - A File indicator with `CustomFields`.

    When:
        - Calling `get_file_from_ioc_custom_fields`.

    Assert:
        - Ensure correct `File` context that removes empty values and extracts `Name` and `Signature`.
    """
    from FileEnrichment import get_file_from_ioc_custom_fields

    ioc_custom_fields = {
        "fileextension": "ZIP",
        "filetype": "application/zip",
        "md5": "md5md5md5md5md5md5md5md5md5md5md5md5md5m",
        "sha1": "sha1sha1sha1sha1sha1sha1sha1sha1sha1sha1",
        "sha256": "sha256sha256sha256sha256sha256sha256sha256sha256sha256sha256sha2",
        "size": 262291,
        "ssdeep": "6144:aAaAaAaAaAaA/B/:CCeeffgghhiijj/kkllmm",
        "tags": ["checks-cpu-name", "checks-hostname"],
        "stixid": None,  # expect to be removed (empty value)
        "name": "Test Application.zip",
        "associatedfilenames": ["Test Application.zip", "test_installer_x64.zip"],
        "signatureauthentihash": "sha256sha256sha256sha256sha256sha256sha256sha256sha256sha256sha2",
    }
    file_indicator_context = get_file_from_ioc_custom_fields(ioc_custom_fields)

    assert "stixid" not in file_indicator_context
    assert file_indicator_context == {
        "Extension": ioc_custom_fields["fileextension"],
        "Type": ioc_custom_fields["filetype"],
        "MD5": ioc_custom_fields["md5"],
        "SHA1": ioc_custom_fields["sha1"],
        "SHA256": ioc_custom_fields["sha256"],
        "Size": ioc_custom_fields["size"],
        "SSDeep": ioc_custom_fields["ssdeep"],
        "Tags": ioc_custom_fields["tags"],
        "AssociatedFileNames": ioc_custom_fields["associatedfilenames"],
        "Name": ioc_custom_fields["name"],
        "Signature": {
            "Authentihash": ioc_custom_fields["signatureauthentihash"],
        },
    }


def test_classify_hashes_by_type():
    """
    Given:
        - A list of file hashes of different types.

    When:
        - Calling `classify_hashes_by_type`

    Assert:
        - Classified hashes dictionary is as expected.
    """
    from FileEnrichment import classify_hashes_by_type

    hashes = [MD5_HASH, SHA_1_HASH, SHA_256_HASH]
    assert classify_hashes_by_type(hashes) == {"MD5": [MD5_HASH], "SHA1": [SHA_1_HASH], "SHA256": [SHA_256_HASH]}


def test_flatten_list():
    """
    Given:
        - A list of numbers that contains a nested list of numbers.

    When:
        - Calling `flatten_list`.

    Assert:
        - Ensure a flattened (non-nested) list of the same numbers.
    """
    from FileEnrichment import flatten_list

    nested_list = [1, 2, 3, [4, 5], 4, 6, [7, [8]]]

    assert flatten_list(nested_list) == [1, 2, 3, 4, 5, 4, 6, 7, 8]


def test_merge_context_outputs():
    """
    Given:
        - The per-command entry context from 5 commands.

    When:
        - Calling `merge_context_outputs`.

    Assert:
        - Ensure merged correct context output.
    """
    from FileEnrichment import merge_context_outputs

    per_command_context = {
        "findIndicators": util_load_json("test_data/search_file_indicator_expected.json")["Context"],
        "file": util_load_json("test_data/file_reputation_command_expected.json")["Context"],
        "wildfire-get-verdict": util_load_json("test_data/wildfire_verdict_command_expected.json")["Context"],
        "core-get-hash-analytics-prevalence": util_load_json("test_data/ir_hash_analytics_command_expected.json")["Context"],
    }

    expected_merged_context = util_load_json("test_data/merged_context_expected.json")

    assert merge_context_outputs(per_command_context, include_additional_fields=True) == expected_merged_context


@pytest.mark.parametrize(
    "dbot_scores, file_context, expected_result",
    [
        # A standard case with a valid match.
        (
            [{"Indicator": MD5_HASH, "Vendor": "TestVendor"}],
            {"MD5": MD5_HASH, "SHA256": "abc"},
            {"Indicator": MD5_HASH, "Vendor": "TestVendor"},
        ),
        # No matching hash found.
        ([{"Indicator": "no_match_here", "Vendor": "TestVendor"}], {"MD5": MD5_HASH}, {}),
        # The function should correctly find the SHA256 match and ignore the None MD5.
        (
            [{"Indicator": SHA_256_HASH, "Vendor": "VirusTotal"}],
            {"MD5": None, "SHA256": SHA_256_HASH, "Verdict": "-102"},
            {"Indicator": SHA_256_HASH, "Vendor": "VirusTotal"},
        ),
        # The indicator value in `dbot_scores` is None or an empty string.
        ([{"Indicator": None, "Vendor": "TestVendor"}], {"MD5": MD5_HASH}, {}),
    ],
)
def test_find_matching_dbot_score(dbot_scores: list[dict], file_context: dict[str, Any], expected_result: dict):
    """
    Given:
        - dbot_scores: List of "DBotScore" objects.
        - file_context: Context output from a single war room result entry.

    When:
        - Calling `find_matching_dbot_score`.

    Assert:
        - Ensure correct output from "find_matching_dbot_score" is returned.
    """

    from FileEnrichment import find_matching_dbot_score

    assert find_matching_dbot_score(dbot_scores, file_context) == expected_result


def test_execute_file_reputation(mocker: MockerFixture):
    """
    Given:
        - The '!file' command with a SHA256 file hash.

    When:
        - Calling `execute_file_reputation`.

    Assert:
        - Ensure correct context output and human-readable output.
    """
    from FileEnrichment import execute_file_reputation

    command = Command("file", {"file": SHA_256_HASH})

    demisto_execute_response = util_load_json("test_data/file_reputation_command_response.json")
    mocker.patch("FileEnrichment.demisto.executeCommand", return_value=demisto_execute_response)

    context_output, readable_command_results = execute_file_reputation(command)

    expected_output = util_load_json("test_data/file_reputation_command_expected.json")
    assert context_output == expected_output["Context"]
    assert readable_command_results[0].readable_output == expected_output["HumanReadable"]


def test_execute_wildfire_verdict(mocker: MockerFixture):
    """
    Given:
        - The '!wildfire-get-verdict' command with a SHA256 file hash.

    When:
        - Calling `execute_wildfire_verdict`.

    Assert:
        - Ensure correct context output and human-readable output.
    """
    from FileEnrichment import execute_wildfire_verdict

    command = Command("wildfire-get-verdict", {"hash": SHA_256_HASH}, Brands.WILDFIRE_V2)

    demisto_execute_response = util_load_json("test_data/wildfire_verdict_command_response.json")
    mocker.patch("FileEnrichment.demisto.executeCommand", return_value=demisto_execute_response)

    context_output, readable_command_results = execute_wildfire_verdict(command)

    expected_output = util_load_json("test_data/wildfire_verdict_command_expected.json")
    assert context_output == expected_output["Context"]
    assert readable_command_results[0].readable_output == expected_output["HumanReadable"]


def test_execute_ir_hash_analytics(mocker: MockerFixture):
    """
    Given:
        - The '!core-get-hash-analytics-prevalence' command with a SHA256 file hash.

    When:
        - Calling `execute_ir_hash_analytics`.

    Assert:
        - Ensure correct context output and human-readable output.
    """
    from FileEnrichment import execute_ir_hash_analytics

    command = Command("core-get-hash-analytics-prevalence", {"sha256": SHA_256_HASH}, Brands.CORE_IR)

    demisto_execute_response = util_load_json("test_data/ir_hash_analytics_command_response.json")
    mocker.patch("FileEnrichment.demisto.executeCommand", return_value=demisto_execute_response)

    context_output, readable_command_results = execute_ir_hash_analytics(command)

    expected_output = util_load_json("test_data/ir_hash_analytics_command_expected.json")
    assert context_output == expected_output["Context"]
    assert readable_command_results[0].readable_output == expected_output["HumanReadable"]


def test_enrich_with_command_known_command(mocker: MockerFixture):
    """
    Given:
        - The known '!core-get-hash-analytics-prevalence' command with a SHA256 hash and an active instance of the source brand.

    When:
        - Calling `enrich_with_command`.

    Assert:
        - Ensure the known file enrichment command is executed.
    """
    from FileEnrichment import enrich_with_command

    mock_execution_function = mocker.patch("FileEnrichment.execute_ir_hash_analytics", return_value=("", ""))

    command = Command("core-get-hash-analytics-prevalence", {"sha256": SHA_256_HASH}, Brands.CORE_IR)

    enrich_with_command(
        command=command,
        enabled_brands=[Brands.CORE_IR.value],
        enrichment_brands=[],
        per_command_context={},
        verbose_command_results=[],
    )

    assert mock_execution_function.call_count == 1


def test_enrich_with_command_unknown_command():
    """
    Given:
        - The unknown '!core-get-endpoints' command with a limit and an active instance of the source brand.

    When:
        - Calling `enrich_with_command`.

    Assert:
        - Ensure a `ValueError` is raised with the appropriate error message.
    """
    from FileEnrichment import enrich_with_command

    command = Command("core-get-endpoints", {"limit": "10"}, Brands.CORE_IR)
    enabled_brands = [Brands.CORE_IR.value]

    with pytest.raises(ValueError, match="Unknown command: core-get-endpoints"):
        enrich_with_command(
            command=command,
            enabled_brands=enabled_brands,
            enrichment_brands=[],
            per_command_context={},
            verbose_command_results=[],
        )


def test_enrich_with_command_with_no_enabled_instance(mocker: MockerFixture):
    """
    Given:
        - The known '!core-get-hash-analytics-prevalence' command with a SHA256 hash and a disabled instance of the source brand.

    When:
        - Calling `enrich_with_command`.

    Assert:
        - Ensure the command is not executed since there is no active instance of the source brand.
    """
    from FileEnrichment import enrich_with_command

    mock_execution_function = mocker.patch("FileEnrichment.execute_file_reputation")

    command = Command("core-get-hash-analytics-prevalence", {"sha256": SHA_256_HASH}, Brands.CORE_IR)
    enabled_brands = [Brands.CORE_IR.value]
    enrichment_brands = [Brands.WILDFIRE_V2.value]

    enrich_with_command(
        command=command,
        enabled_brands=enabled_brands,
        enrichment_brands=enrichment_brands,
        per_command_context={},
        verbose_command_results=[],
    )

    assert mock_execution_function.call_count == 0


def test_enrich_with_command_not_in_enrichment_brands(mocker: MockerFixture):
    """
    Given:
        - The known '!wildfire-report' command with a SHA256 hash and an enabled instance of the source brand.

    When:
        - Calling `enrich_with_command`.

    Assert:
        - Ensure the command is not executed since there is no active instance of the source brand.
    """
    from FileEnrichment import enrich_with_command

    mock_execution_function = mocker.patch("FileEnrichment.execute_file_reputation")

    command = Command("core-get-hash-analytics-prevalence", {"sha256": SHA_256_HASH}, Brands.CORE_IR)

    enrich_with_command(
        command=command,
        enabled_brands=[Brands.CORE_IR.value],
        enrichment_brands=["VirusTotal (API v3)"],
        per_command_context={},
        verbose_command_results=[],
    )

    assert mock_execution_function.call_count == 0


def test_search_file_indicator(mocker: MockerFixture):
    """
    Given:
        - A file indicator in the Threat Intelligence Module (TIM).

    When:
        - Calling `search_file_indicator`.

    Assert:
        - Ensure correct context output and human-readable output.
    """
    from FileEnrichment import search_file_indicator

    indicator_search_results = util_load_json("test_data/search_file_indicator_response.json")
    mocker.patch("FileEnrichment.IndicatorsSearcher.__iter__", return_value=iter(indicator_search_results))

    per_command_context, verbose_command_results = {}, []
    search_file_indicator(SHA_256_HASH, per_command_context, verbose_command_results)

    expected_output = util_load_json("test_data/search_file_indicator_expected.json")
    assert per_command_context["findIndicators"] == expected_output["Context"]
    assert verbose_command_results[0].readable_output == expected_output["HumanReadable"]


def test_run_external_enrichment(mocker: MockerFixture):
    """
    Given:
        - A SHA256 file hash and enabled instances of all source brands.

    When:
        - Calling `run_external_enrichment`.

    Assert:
        - Ensure all the commands from all the source brands run with the correct arguments.
    """
    from FileEnrichment import run_external_enrichment

    enabled_brands = [Brands.WILDFIRE_V2.value, Brands.CORE_IR.value]
    enrichment_brands = [Brands.WILDFIRE_V2.value]

    mock_enrich_with_command = mocker.patch("FileEnrichment.enrich_with_command")

    run_external_enrichment(
        hashes_by_type={"SHA256": [SHA_256_HASH]},
        enabled_brands=enabled_brands,
        enrichment_brands=enrichment_brands,
        per_command_context={},
        verbose_command_results=[],
    )

    assert mock_enrich_with_command.call_count == 1

    # Run file reputation command
    file_reputation_command = mock_enrich_with_command.call_args_list[0].kwargs["command"]

    assert file_reputation_command.name == "file"
    assert file_reputation_command.args == {"file": SHA_256_HASH, "using-brand": ",".join(enrichment_brands)}


def test_run_internal_enrichment(mocker: MockerFixture):
    """
    Given:
        - A SHA256 file hash and enabled instances of all source brands.

    When:
        - Calling `run_internal_enrichment`.

    Assert:
        - Ensure all the commands from all the source brands run with the correct arguments.
    """
    from FileEnrichment import run_internal_enrichment

    enabled_brands = [Brands.WILDFIRE_V2.value, Brands.CORE_IR.value]
    mock_enrich_with_command = mocker.patch("FileEnrichment.enrich_with_command")

    run_internal_enrichment(
        hashes_by_type={"SHA256": [SHA_256_HASH]},
        enabled_brands=enabled_brands,
        enrichment_brands=[],
        per_command_context={},
        verbose_command_results=[],
    )

    assert mock_enrich_with_command.call_count == 2

    # B. Run Wildfire Verdict command
    wildfire_verdict_command = mock_enrich_with_command.call_args_list[0].kwargs["command"]

    assert wildfire_verdict_command.name == "wildfire-get-verdict"
    assert wildfire_verdict_command.args == {"hash": SHA_256_HASH}

    # C. Run Core IR Hash Analytics command
    hash_analytics_command = mock_enrich_with_command.call_args_list[1].kwargs["command"]

    assert hash_analytics_command.name == "core-get-hash-analytics-prevalence"
    assert hash_analytics_command.args == {"sha256": SHA_256_HASH}


@pytest.mark.parametrize(
    "enrichment_brands, expected_results",
    [
        # No enrichment brands: only internal enrichment brands should run.
        pytest.param([], {"internal_enrichment_should_run": [True, True]}, id="No Enrichment Brands"),
        # Only WildFire in enrichment brands: only Wildfire should run
        pytest.param(
            [Brands.WILDFIRE_V2.value], {"internal_enrichment_should_run": [True, False]}, id="Enrichment Brands Include Wildfire"
        ),
        # Enrichment brands is not empty and does not include internal: no internal enrichment brands should run.
        pytest.param(
            [Brands.TIM.value],
            {"internal_enrichment_should_run": [False, False]},
            id="Enrichment Brands Does NotInclude Wildfire",
        ),
    ],
)
def test_run_internal_enrichment_with_specified_enrichment_brand(
    mocker: MockerFixture, enrichment_brands: list[str], expected_results: dict
):
    """
    Given:
        - A SHA256 file hash and enabled instances of all source brands.
        - A list of enrichment brands
        - A list of expected results

    When:
        - Calling `run_internal_enrichment`.

    Assert:
        - Ensure that the correct commands run according to the specified enrichment brand
    """
    from FileEnrichment import run_internal_enrichment

    enabled_brands = [Brands.WILDFIRE_V2.value, Brands.CORE_IR.value]
    mock_ir = mocker.patch("FileEnrichment.execute_ir_hash_analytics", return_value=({}, []))
    mock_wildfire = mocker.patch("FileEnrichment.execute_wildfire_verdict", return_value=({}, []))

    run_internal_enrichment(
        hashes_by_type={"SHA256": [SHA_256_HASH]},
        enabled_brands=enabled_brands,
        enrichment_brands=enrichment_brands,
        per_command_context={},
        verbose_command_results=[],
    )

    assert mock_wildfire.call_count == int(expected_results["internal_enrichment_should_run"][0])
    assert mock_ir.call_count == int(expected_results["internal_enrichment_should_run"][1])


def test_summarize_command_results_successful_commands(mocker: MockerFixture):
    """
    Given:
        - Per-command entry context and verbose command results with "NOTE" entry type.

    When:
        - Calling `summarize_command_results`.

    Assert:
        - Ensure summarized human-readable output has correct values of "Status", "Result", and "Message".
        - Ensure final (aggregated) context output has correct "File" indicator "DBotScore" context.
    """
    from FileEnrichment import summarize_command_results

    mock_table_to_markdown = mocker.patch("FileEnrichment.tableToMarkdown")

    file_reputation_context = {"SHA256": SHA_256_HASH, "VTVendors": [], "Brand": "VirusTotal (API v3)"}
    wildfire_report_context = {"SHA256": SHA_256_HASH, "WFReport": "Success", "Brand": str(Brands.WILDFIRE_V2)}

    per_command_context = {
        "file": {"FileEnrichment": [file_reputation_context]},
        "wildfire-report": {"FileEnrichment": [wildfire_report_context]},
    }

    summary_command_results = summarize_command_results(
        hashes_by_type={"SHA256": [SHA_256_HASH]},
        per_command_context=per_command_context,
        verbose_command_results=[CommandResults(readable_output="This is hash scan result", entry_type=EntryType.NOTE)],
        external_enrichment=True,
        include_additional_fields=True,
    )

    table_to_markdown_kwargs = mock_table_to_markdown.call_args.kwargs
    assert table_to_markdown_kwargs["name"] == f"File Enrichment result for {SHA_256_HASH}"
    assert table_to_markdown_kwargs["t"] == [
        {
            "File": SHA_256_HASH,
            "Status": "Done",  # Got "File" context from two commands
            "Result": "Success",  # No error entries in command results
            "Message": "Found data on file from 2 brands.",
            "Brands": f"VirusTotal (API v3), {Brands.WILDFIRE_V2}",
            "TIM Verdict": "Unknown",
        }
    ]

    assert summary_command_results.outputs == {
        ContextPaths.FILE_ENRICHMENT.value: [file_reputation_context, wildfire_report_context]
    }


def test_summarize_command_results_failed_commands(mocker: MockerFixture):
    """
    Given:
        - Empty per-command entry context and verbose command results with "ERROR" entry type.

    When:
        - Calling `summarize_command_results` with `external_enrichment set` to False.

    Assert:
        - Ensure summarized human-readable output has correct values of "Status", "Result", and "Message".
        - Ensure final (aggregated) context output is empty - consistent with the per-command context.
    """
    from FileEnrichment import summarize_command_results

    mock_table_to_markdown = mocker.patch("FileEnrichment.tableToMarkdown")

    summary_command_results = summarize_command_results(
        hashes_by_type={"SHA256": [SHA_256_HASH]},
        per_command_context={},
        verbose_command_results=[CommandResults(readable_output="This is an error message!", entry_type=EntryType.ERROR)],
        external_enrichment=False,
        include_additional_fields=False,
    )

    table_to_markdown_kwargs = mock_table_to_markdown.call_args.kwargs
    assert table_to_markdown_kwargs["name"] == f"File Enrichment result for {SHA_256_HASH}"
    assert table_to_markdown_kwargs["t"] == [
        {
            "File": SHA_256_HASH,
            "Status": "Not Found",  # No "File" context from any command
            "Result": "Failed",  # Error entry in command results
            "Message": "Could not find data on file. Consider setting external_enrichment=true.",
            "TIM Verdict": "Unknown",
        }
    ]

    assert summary_command_results.outputs == {}


def test_main_invalid_hashes(mocker: MockerFixture):
    """
    Given:
        - Invalid file hashes.

    When:
        - Calling `main`

    Assert:
        - Ensure an error is returned with the appropriate error message.
    """
    from FileEnrichment import main

    mocker.patch("FileEnrichment.demisto.args", return_value={"file_hash": "123,345"})
    mocker.patch("FileEnrichment.demisto.error")  # mocked to avoid logging to STDERR when running unit test
    mock_return_error = mocker.patch("FileEnrichment.return_error")

    expected_error_message = (
        "Failed to execute file-enrichment script. "
        "Error: None of the file hashes are valid. Supported types are: MD5, SHA1, SHA256, and SHA512."
    )

    main()

    assert mock_return_error.call_args[0][0] == expected_error_message


@pytest.mark.parametrize(
    "external_enrichment",
    [
        pytest.param(True, id="Enabled external enrichment"),
        pytest.param(False, id="Disabled external enrichment"),
    ],
)
def test_main_valid_hash(mocker: MockerFixture, external_enrichment: bool):
    """
    Given:
        - A valid SHA256 file hash and external_enrichment boolean flag.

    When:
        - Calling `file_enrichment_script`

    Assert:
        - Ensure the correct functions are called, depending on the value of external_enrichment.
    """
    from FileEnrichment import file_enrichment_script

    mock_search_file_indicator = mocker.patch("FileEnrichment.search_file_indicator")
    mock_demisto_get_modules = mocker.patch("FileEnrichment.demisto.getModules")
    mock_run_internal_enrichment = mocker.patch("FileEnrichment.run_internal_enrichment")
    mock_run_external_enrichment = mocker.patch("FileEnrichment.run_external_enrichment")
    mock_summarize_command_results = mocker.patch("FileEnrichment.summarize_command_results")

    args = {"file_hash": SHA_256_HASH, "external_enrichment": external_enrichment}
    file_enrichment_script(args)

    assert mock_search_file_indicator.call_count == 1

    # Should not run if external_enrichment is False
    assert mock_demisto_get_modules.call_count == 1
    assert mock_run_internal_enrichment.call_count == 1
    assert mock_run_external_enrichment.call_count == int(external_enrichment)

    assert mock_summarize_command_results.call_count == 1
