import pytest
from AzureFindAvailableNSGPriorities import find_available_priorities

TEST_LIST = list(range(1, 1110))

TEST_INPUTS = [
    (106, 2, [100, 101, 103, 106, 107], [105, 104]),
    (2998, 2, [100, 101, 103, 106, 110, 111, 2996, 2998, 3000], [2997, 2995]),
]

ERROR_MESSAGE_TEST_INPUTS = [
    ("", 2, [100, 101, 103, 106, 107], "target_rule_priority not specified."),
    (90, 2, [100, 101, 103, 106, 107], "target_rule_priority must not be 100 or less."),
    (
        5000,
        2,
        [100, 101, 103, 106, 110, 111, 2996, 2998, 3000],
        "target_rule_priority must not be 4096 or more.",
    ),
    (
        107,
        "",
        [100, 101, 103, 106, 107],
        "number_of_available_priorities_to_retrieve not specified.",
    ),
    (
        107,
        -1,
        [100, 101, 103, 106, 107],
        "number_of_available_priorities_to_retrieve cannot be 0 or less, or more than 5. Please use a lower number.",
    ),
    (
        107,
        6,
        [100, 101, 103, 106, 107],
        "number_of_available_priorities_to_retrieve cannot be 0 or less, or more than 5. Please use a lower number.",
    ),
    (107, 2, [], "list_of_priorities_from_rules not specified."),
    (107, 2, "test string", "list_of_priorities_from_rules must be a list."),
    (
        300,
        2,
        TEST_LIST,
        "list_of_priorities_from_rules does not support list over 999 entries, please reduce the list.",
    ),
    (101, 2, [100, 101], "No available priorities found."),
]


@pytest.mark.parametrize(
    "target_rule_priority, number_of_available_priorities_to_retrieve, list_of_priorities_from_rules, expected_result",
    TEST_INPUTS,
)
def test_find_available_priorities(
    target_rule_priority,
    number_of_available_priorities_to_retrieve,
    list_of_priorities_from_rules,
    expected_result,
):
    assert (
        find_available_priorities(
            target_rule_priority,
            number_of_available_priorities_to_retrieve,
            list_of_priorities_from_rules,
        )
        == expected_result
    )


@pytest.mark.parametrize(
    "target_rule_priority, number_of_available_priorities_to_retrieve, list_of_priorities_from_rules, expected_error_message",
    ERROR_MESSAGE_TEST_INPUTS,
)
def test_input_value_errors(
    target_rule_priority,
    number_of_available_priorities_to_retrieve,
    list_of_priorities_from_rules,
    expected_error_message,
):
    with pytest.raises(ValueError) as error_message:
        # function call with invalid parameters
        find_available_priorities(
            target_rule_priority,
            number_of_available_priorities_to_retrieve,
            list_of_priorities_from_rules,
        )
    assert expected_error_message in str(error_message.value)
