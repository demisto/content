import json
import pytest
from pytest_mock import MockerFixture
from FileEnrichment import Command, Brands


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

COMMAND_PREPARE_HUMAN_READABLE_PARAMS = [
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
        "instance_1": {"brand": Brands.WILDFIRE_V2.value, "state": "active"},
        "instance_2": {"brand": Brands.CORE_IR.value, "state": "disabled"},
        "instance_3": {"brand": Brands.VIRUS_TOTAL_V3.value, "state": "disabled"},
    }
    brands_to_run = Brands.values()  # all brands

    assert command._should_brand_run(modules, brands_to_run) == expected_should_brand_run


@pytest.mark.parametrize("inputted_human_readable, is_error, expected_readable_output", COMMAND_PREPARE_HUMAN_READABLE_PARAMS)
def test_command_prepare_human_readable(inputted_human_readable: str, is_error: bool, expected_readable_output: str):
    """
    Given:
        - Command objects with source brand and arguments dictionaries.

    When:
        - Calling `Command.prepare_human_readable`.

    Assert:
        - Ensure correct human readable value with the appropriate title and message.
    """
    command = Command(Brands.WILDFIRE_V2, "wildfire-upload-url", {"upload": "http://www.example.com"})

    human_readable_command_results = command.prepare_human_readable(inputted_human_readable, is_error)

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
        - Ensure the dictionary is transformed with the correct key prefix and the values nested in dictionaries that also
          contain the source brand field.
    """
    from FileEnrichment import add_source_brand_to_values

    original_context = {
        "Key1": ["ValA", "ValB"],
        "Key2": "ValC",
        "Key3": 4,
        "Key4": {"KeyD": "InnerValE"},
        "Key5": "ValF",
    }

    updated_context = add_source_brand_to_values(original_context, Brands.TIM, key_prefix="Source", excluded_keys=["Key5"])

    assert "Key5" not in updated_context
    assert updated_context == {
        "SourceKey1": {"value": original_context["Key1"], "source": Brands.TIM.value},
        "SourceKey2": {"value": original_context["Key2"], "source": Brands.TIM.value},
        "SourceKey3": {"value": original_context["Key3"], "source": Brands.TIM.value},
        "SourceKey4": {"value": original_context["Key4"], "source": Brands.TIM.value},
    }


def test_execute_file_reputation(mocker: MockerFixture):
    """
    Given:
        - ...

    When:
        - Calling `execute_file_reputation`.

    Assert:
        - ...
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


def test_execute_execute_wildfire_report(mocker: MockerFixture):
    """
    Given:
        - ...

    When:
        - Calling `execute_wildfire_report`.

    Assert:
        - ...
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


def test_execute_ir_hash_analytics(mocker: MockerFixture):
    """
    Given:
        - ...

    When:
        - Calling `execute_ir_hash_analytics`.

    Assert:
        - ...
    """
    from FileEnrichment import execute_ir_hash_analytics

    command = Command(Brands.CORE_IR, "core-get-hash-analytics-prevalence", {"sha256": SHA_256_HASH})

    demisto_execute_response = util_load_json("test_data/ir_hash_analytics_command_response.json")
    mocker.patch("FileEnrichment.demisto.executeCommand", return_value=demisto_execute_response)

    context_output, readable_command_results = execute_ir_hash_analytics(command)

    expected_output = util_load_json("test_data/ir_hash_analytics_command_expected.json")
    assert context_output["_File"] == expected_output["File"]
    assert readable_command_results[0].readable_output == expected_output["HumanReadable"]
