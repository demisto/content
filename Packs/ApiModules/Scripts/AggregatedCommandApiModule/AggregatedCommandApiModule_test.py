import pytest
import demistomock as demisto
from AggregatedCommandApiModule import *


# ─────── Tests for Command class ────────────────────────────────────────────────
@pytest.mark.parametrize(
    "brands_to_run,expected_result",
    [
        (["brand1", "brand2"], {"test-command": {"arg1": "value1", "using-brand": "brand1,brand2"}}),
        ([], {"test-command": {"arg1": "value1"}}),
    ],
)
def test_to_batch_item_with_brands(brands_to_run, expected_result):
    """
    Given:
        - A Command instance with name and args
        - A list of brands to run (may be empty)
    When:
        - Calling to_batch_item method with brands
    Then:
        - Returns a dictionary with the command name as key and args as value
        - The using-brand parameter is added only when brands are provided
    """
    cmd = Command(name="test-command", args={"arg1": "value1"})
    batch_item = cmd.to_batch_item(brands_to_run)
    
    assert batch_item == expected_result
