import json
import pytest
from pytest_mock import MockerFixture
from FileEnrichment import Brands, Command, CommandResults, ContextPaths, EntryType


""" TEST CONSTANTS """

SHA_256_HASH = "7aa15bd505a240a8bf62735a5389a530322945eec6ce9d7b6ad299ca33b2b1b0"


COMMAND_HAS_REQUIRED_ARGS_PARAMS = [  # command, expected_has_required_args
    pytest.param(
        Command(Brands.WILDFIRE_V2, "wildfire-report", {"sha256": SHA_256_HASH}),
        True,
        id="Has all args",
    ),
    pytest.param(
        Command(Brands.VIRUS_TOTAL_V3, "file", {"file": None}),
        False,
        id="Is missing args",
    ),
    pytest.param(
        Command(Brands.CORE_IR, "get-endpoints", {}),
        True,
        id="Has no args",
    ),
]

COMMAND_SHOULD_BRAND_RUN_PARAMS = [  # command, expected_should_brand_run
    pytest.param(
        Command(Brands.WILDFIRE_V2, "wildfire-get-verdict", {"file_hash": SHA_256_HASH}),
        True,
        id="Brand active",
    ),
    pytest.param(
        Command(Brands.VIRUS_TOTAL_V3, "vt-file-sandbox-report", {"file": SHA_256_HASH}),
        False,
        id="Brand disabled",
    ),
]

COMMAND_PREPARE_HUMAN_READABLE_PARAMS = [   # original_human_readable, is_error, expected_readable_output
    pytest.param(
        "This is a regular message",
        False,
        "#### Result for !wildfire-upload-url upload=\"http://www.example.com\"\nThis is a regular message",
        id="Note entry",
    ),
    pytest.param(
        "This is an error message",
        True,
        "#### Error for !wildfire-upload-url upload=\"http://www.example.com\"\nThis is an error message",
        id="Error Entry",
    ),
]

MAIN_VALID_HASH_PARAMS = [
    pytest.param(True, id="Enabled external enrichment"),
    pytest.param(False, id="Disabled external enrichment"),
]


""" TEST HELPER FUNCTIONS """


def util_load_json(path: str):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


""" UNIT TESTS FUNCTIONS """


@pytest.mark.parametrize("command, expected_has_required_args", COMMAND_HAS_REQUIRED_ARGS_PARAMS)
def test_command_has_required_args(command: Command, expected_has_required_args: bool):
    """
    Given:
        - Command objects with source brand and arguments dictionaries.

    When:
        - Calling `Command._has_required_args`.

    Assert:
        - Ensure value is True if all arguments have values or if command has no arguments. Otherwise, False.
    """
    assert command._has_required_args == expected_has_required_args


@pytest.mark.parametrize("command, expected_should_brand_run", COMMAND_SHOULD_BRAND_RUN_PARAMS)
def test_command_should_brand_run(command: Command, expected_should_brand_run: bool):
    """
    Given:
        - Command objects with source brand and arguments dictionaries.

    When:
        - Calling `Command._should_brand_run`.

    Assert:
        - Ensure value is True if an integration instance of the brand is active. Otherwise, False.
    """
    modules = {
        "instance_wf": {"brand": Brands.WILDFIRE_V2.value, "state": "active"},
        "instance_ir": {"brand": Brands.CORE_IR.value, "state": "active"},
        "instance_vt": {"brand": Brands.VIRUS_TOTAL_V3.value, "state": "disabled"},
    }
    brands_to_run = Brands.values()  # all brands

    assert command._should_brand_run(modules, brands_to_run) == expected_should_brand_run


@pytest.mark.parametrize("original_human_readable, is_error, expected_readable_output", COMMAND_PREPARE_HUMAN_READABLE_PARAMS)
def test_command_prepare_human_readable(original_human_readable: str, is_error: bool, expected_readable_output: str):
    """
    Given:
        - Command objects with source brand and arguments dictionaries.

    When:
        - Calling `Command.prepare_human_readable`.

    Assert:
        - Ensure correct human readable value with the appropriate title and message.
    """
    command = Command(Brands.WILDFIRE_V2, "wildfire-upload-url", {"upload": "http://www.example.com"})

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
    command = Command(Brands.VIRUS_TOTAL_V3, "file", {"file": SHA_256_HASH})

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
        "md5": "4E76823C05048E92A4C0122D61000EDF",
        "sha1": "D8B426700C3C10413ABB8ACDCFECCAAEC8F06CD9",
        "sha256": "7AA15BD505A240A8BF62735A5389A530322945EEC6CE9D7B6AD299CA33B2B1B0",
        "size": 262291,
        "ssdeep": "6144:WWEH6PCEYPX3DNGG+KFXLLRNR8M+FHAD2HNRG/U/:WWS6PCVLHT+KDR8/AD23Z",
        "tags": ["checks-cpu-name", "checks-hostname"],
        "stixid": None,  # expect to be removed (empty value)
        "associatedfilenames": ["VS Code", "Visual Studio Code Setup (x64)"],
        "signatureauthentihash": "7AA15BD505A240A8BF62735A5389A530322945EEC6CE9D7B6AD299CA33B2B1B0",
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
        "Name": ioc_custom_fields["associatedfilenames"][0],
        "Signature": {
            "Authentihash": ioc_custom_fields["signatureauthentihash"],
        }
    }


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

    nested_list = ["1", "2", ["3", "4"], "5"]

    assert sorted(flatten_list(nested_list)) == ["1", "2", "3", "4", "5"]


def test_add_source_brand_to_values():
    """
    Given:
        - A dictionary of string keys and values of different data types.

    When:
        - Calling `add_source_brand_to_values`.

    Assert:
        - Ensure the dictionary is transformed with the correct nested dictionaries.
    """
    from FileEnrichment import add_source_brand_to_values

    original_context = {
        "Key0": ["ValA"],
        "Key1": ["ValB", "ValC"],
        "Key2": "ValD",
        "Key3": 4,
        "Key4": {"KeyE": "InnerValE"},
        "Key5": "ValF",
    }
    brand = Brands.CORE_IR
    updated_context = add_source_brand_to_values(original_context, brand, excluded_keys=["Key5"])

    assert "Key5" not in updated_context
    assert updated_context == {
        "Key0": {"Value": original_context["Key0"][0], "Source": brand.value},
        "Key1": {"Value": original_context["Key1"], "Source": brand.value},
        "Key2": {"Value": original_context["Key2"], "Source": brand.value},
        "Key3": {"Value": original_context["Key3"], "Source": brand.value},
        "Key4": {"KeyE": {"Value": original_context["Key4"]["KeyE"], "Source": brand.value}},
    }


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

    command = Command(Brands.VIRUS_TOTAL_V3, "file", {"file": SHA_256_HASH})

    demisto_execute_response = util_load_json("test_data/file_reputation_command_response.json")
    mocker.patch("FileEnrichment.demisto.executeCommand", return_value=demisto_execute_response)

    context_output, readable_command_results = execute_file_reputation(command)

    expected_output = util_load_json("test_data/file_reputation_command_expected.json")
    assert context_output["_DBotScore"] == expected_output["DBotScore"]
    assert context_output["_File"] == expected_output["File"]
    assert readable_command_results[0].readable_output == expected_output["HumanReadable"]


def test_execute_wildfire_report(mocker: MockerFixture):
    """
    Given:
        - The '!wildfire-report' command with a SHA256 file hash.

    When:
        - Calling `execute_wildfire_report`.

    Assert:
        - Ensure correct context output and human-readable output.
    """
    from FileEnrichment import execute_wildfire_report

    command = Command(Brands.WILDFIRE_V2, "wildfire-report", {"sha256": SHA_256_HASH})

    demisto_execute_response = util_load_json("test_data/wildfire_report_command_response.json")
    mocker.patch("FileEnrichment.demisto.executeCommand", return_value=demisto_execute_response)

    context_output, readable_command_results = execute_wildfire_report(command)

    expected_output = util_load_json("test_data/wildfire_report_command_expected.json")
    assert context_output["_DBotScore"] == expected_output["DBotScore"]
    assert context_output["_File"] == expected_output["File"]
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

    command = Command(Brands.WILDFIRE_V2, "wildfire-get-verdict", {"hash": SHA_256_HASH})

    demisto_execute_response = util_load_json("test_data/wildfire_verdict_command_response.json")
    mocker.patch("FileEnrichment.demisto.executeCommand", return_value=demisto_execute_response)

    context_output, readable_command_results = execute_wildfire_verdict(command)

    expected_output = util_load_json("test_data/wildfire_verdict_command_expected.json")
    assert context_output["_DBotScore"] == expected_output["DBotScore"]
    assert context_output["_File"] == expected_output["File"]
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

    command = Command(Brands.CORE_IR, "core-get-hash-analytics-prevalence", {"sha256": SHA_256_HASH})

    demisto_execute_response = util_load_json("test_data/ir_hash_analytics_command_response.json")
    mocker.patch("FileEnrichment.demisto.executeCommand", return_value=demisto_execute_response)

    context_output, readable_command_results = execute_ir_hash_analytics(command)

    expected_output = util_load_json("test_data/ir_hash_analytics_command_expected.json")
    assert context_output["_File"] == expected_output["File"]
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

    command = Command(Brands.CORE_IR, "core-get-hash-analytics-prevalence", {"sha256": SHA_256_HASH})
    modules = {"instance_ir": {"brand": Brands.CORE_IR.value, "state": "active"}}
    brands_to_run = Brands.values()

    enrich_with_command(
        command=command,
        modules=modules,
        brands_to_run=brands_to_run,
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

    command = Command(Brands.CORE_IR, "core-get-endpoints", {"limit": "10"})
    modules = {"instance_ir": {"brand": Brands.CORE_IR.value, "state": "active"}}
    brands_to_run = Brands.values()

    with pytest.raises(ValueError, match="Unknown command: core-get-endpoints"):
        enrich_with_command(
            command=command,
            modules=modules,
            brands_to_run=brands_to_run,
            per_command_context={},
            verbose_command_results=[],
        )


def test_enrich_with_command_cannot_run(mocker: MockerFixture):
    """
    Given:
        - The known '!file' command with a SHA256 hash and a disabled instance of the source brand.

    When:
        - Calling `enrich_with_command`.

    Assert:
        - Ensure the command is not executed since there is no active instance of the source brand.
    """
    from FileEnrichment import enrich_with_command

    mock_execution_function = mocker.patch("FileEnrichment.execute_file_reputation")

    command = Command(Brands.VIRUS_TOTAL_V3, "file", {"file": SHA_256_HASH})
    modules = {"instance_vt": {"brand": Brands.VIRUS_TOTAL_V3.value, "state": "disabled"}}
    brands_to_run = Brands.values()

    enrich_with_command(
        command=command,
        modules=modules,
        brands_to_run=brands_to_run,
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
    assert per_command_context["findIndicators"]["_File"] == expected_output["File"]
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

    modules = {
        "instance_wf": {"brand": Brands.WILDFIRE_V2.value, "state": "active"},
        "instance_ir": {"brand": Brands.CORE_IR.value, "state": "active"},
        "instance_vt": {"brand": Brands.VIRUS_TOTAL_V3.value, "state": "active"},
    }
    brands_to_run = Brands.values()

    mock_enrich_with_command = mocker.patch("FileEnrichment.enrich_with_command")

    run_external_enrichment(
        file_hash=SHA_256_HASH,
        hash_type="sha256",
        modules=modules,
        brands_to_run=brands_to_run,
        per_command_context={},
        verbose_command_results=[],
    )

    assert mock_enrich_with_command.call_count == 4

    # A. Run file reputation command
    file_reputation_command = mock_enrich_with_command.call_args_list[0][0][0]

    assert file_reputation_command.name == "file"
    assert file_reputation_command.args == {"file": SHA_256_HASH, "using-brand": ",".join(brands_to_run)}

    # B. Run Wildfire Report command
    wildfire_report_command = mock_enrich_with_command.call_args_list[1][0][0]

    assert wildfire_report_command.name == "wildfire-report"
    assert wildfire_report_command.args == {"sha256": SHA_256_HASH}

    # C. Run Wildfire Verdict command
    wildfire_verdict_command = mock_enrich_with_command.call_args_list[2][0][0]

    assert wildfire_verdict_command.name == "wildfire-get-verdict"
    assert wildfire_verdict_command.args == {"hash": SHA_256_HASH}

    # D. Run Core IR Hash Analytics command
    hash_analytics_command = mock_enrich_with_command.call_args_list[3][0][0]

    assert hash_analytics_command.name == "core-get-hash-analytics-prevalence"
    assert hash_analytics_command.args == {"sha256": SHA_256_HASH}


def test_summarize_command_results_successful_commands(mocker: MockerFixture):
    """
    Given:
        - Per-command entry context with "_File" and "_DBotScores" keys and verbose command results with "NOTE" entry type.

    When:
        - Calling `summarize_command_results`.

    Assert:
        - Ensure summarized human-readable output has correct values of "Status", "Result", and "Message".
        - Ensure final (aggregated) context output has correct "File" indicator "DBotScore" context.
    """
    from FileEnrichment import summarize_command_results

    mock_table_to_markdown = mocker.patch("FileEnrichment.tableToMarkdown")

    vt_score = {"Indicator": SHA_256_HASH, "Score": 1, "Reliability": "B - Reliable", "Vendor": Brands.VIRUS_TOTAL_V3.value}
    wf_score = {"Indicator": SHA_256_HASH, "Score": 3, "Reliability": "B - Reliable", "Vendor": Brands.WILDFIRE_V2.value}

    per_command_context = {
        "file": {
            "_File": {"SHA256": SHA_256_HASH, "VTVerdict": "Benign"},
            "_DBotScore": [vt_score]
        },
        "wildfire-report": {
            "_File": {"SHA256": SHA_256_HASH, "WFReport": "Success"},
            "_DBotScore": [wf_score]
        }
    }

    summary_command_results = summarize_command_results(
        file_hash=SHA_256_HASH,
        per_command_context=per_command_context,
        verbose_command_results=[
            CommandResults(readable_output="This is hash scan result", entry_type=EntryType.NOTE)
        ],
        external_enrichment=True,
    )

    table_to_markdown_kwargs = mock_table_to_markdown.call_args.kwargs
    assert table_to_markdown_kwargs["name"] == f"File Enrichment result for {SHA_256_HASH}"
    assert table_to_markdown_kwargs["t"] == {
        "File": SHA_256_HASH,
        "Status": "Done",  # Got "File" context from two commands
        "Result": "Success",  # No error entries in command results
        "Message": "Found data on file from 2 sources.",
    }

    assert summary_command_results.outputs == {
        ContextPaths.FILE.value: {"SHA256": SHA_256_HASH, "VTVerdict": "Benign", "WFReport": "Success"},
        ContextPaths.DBOT_SCORE.value: [vt_score, wf_score]
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
        file_hash=SHA_256_HASH,
        per_command_context={},
        verbose_command_results=[
            CommandResults(readable_output="This is an error message!", entry_type=EntryType.ERROR)
        ],
        external_enrichment=False,
    )

    table_to_markdown_kwargs = mock_table_to_markdown.call_args.kwargs
    assert table_to_markdown_kwargs["name"] == f"File Enrichment result for {SHA_256_HASH}"
    assert table_to_markdown_kwargs["t"] == {
        "File": SHA_256_HASH,
        "Status": "Not Found",  # No "File" context from any command
        "Result": "Failed",  # Error entry in command results
        "Message": "Could not find data on file. Consider setting external_enrichment=true.",
    }

    assert summary_command_results.outputs == {}


def test_main_invalid_hash(mocker: MockerFixture):
    """
    Given:
        - An invalid file hash.

    When:
        - Calling `main`

    Assert:
        - Ensure an error is returned with the appropriate error message.
    """
    from FileEnrichment import main

    mocker.patch("FileEnrichment.demisto.args", return_value={"file_hash": "123"})
    mock_return_error = mocker.patch("FileEnrichment.return_error")

    expected_error_message = (
        "Failed to execute file-enrichment command. "
        "Error: A valid file hash must be provided. Supported types are: MD5, SHA1, SHA256, and SHA512."
    )

    main()

    assert mock_return_error.call_args[0][0] == expected_error_message


@pytest.mark.parametrize("external_enrichment", MAIN_VALID_HASH_PARAMS)
def test_main_valid_hash(mocker: MockerFixture, external_enrichment: bool):
    """
    Given:
        - A valid SHA256 file hash and external_enrichment boolean flag.

    When:
        - Calling `main`

    Assert:
        - Ensure the correct functions are called, depending on the value of external_enrichment.
    """
    from FileEnrichment import main

    args = {"file_hash": SHA_256_HASH, "external_enrichment": external_enrichment}
    mocker.patch("FileEnrichment.demisto.args", return_value=args)

    mock_search_file_indicator = mocker.patch("FileEnrichment.search_file_indicator")
    mock_demisto_get_modules = mocker.patch("FileEnrichment.demisto.getModules")
    mock_run_external_enrichment = mocker.patch("FileEnrichment.run_external_enrichment")
    mock_summarize_command_results = mocker.patch("FileEnrichment.summarize_command_results")
    mock_return_results = mocker.patch("FileEnrichment.return_results")

    main()

    assert mock_search_file_indicator.call_count == 1

    # Should not run if external_enrichment is False
    assert mock_demisto_get_modules.call_count == int(external_enrichment)
    assert mock_run_external_enrichment.call_count == int(external_enrichment)

    assert mock_summarize_command_results.call_count == 1
    assert mock_return_results.call_count == 1
