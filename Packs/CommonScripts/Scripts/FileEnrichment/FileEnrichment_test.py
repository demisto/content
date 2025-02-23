import pytest
from FileEnrichment import Command, Brands


SHA_256_HASH = "1234567890abcdefghiklmnopqrstuvwxyz1234567890abcdefghiklmnopqrst"


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

COMMAND_PRERPARE_HUMAN_READABLE_PARAMS = [
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


@pytest.mark.parametrize("inputted_human_readable, is_error, expected_readable_output", COMMAND_PRERPARE_HUMAN_READABLE_PARAMS)
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
