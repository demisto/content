import pytest
import demistomock as demisto
from unittest.mock import patch
import SetIndicatorGridField
from SetIndicatorGridField import parse_rows, main, get_existing_grid_records

VALID_ROWS_STR = '[[192.168.1.1,"example.com"], [192.168.1.2, ""], ["", "example.net"]]'
INVALID_ROWS_STR = '[[192.168.1.1, "example.com"],[192.168.1.2],[""]]}'
INDICATOR_RESPONSE = [
    {
        "Type": 1,
        "Contents": [
            {
                "id": "indicator-id-123",
                "type": "indicator-type",
                "value": "example.com",
                "CustomFields": {
                    "gridField": [
                        {"IP": "192.168.1.1", "Hostname": "example.com"},
                        {"IP": "192.168.1.2", "Hostname": "example.org"}
                    ]
                },
                "lastSeen": "2023-10-05T12:34:56Z",
                "score": 1
            }
        ],
        "ContentsFormat": "json"
    }
]


@pytest.mark.parametrize(
    "rows_str, expected_result, expect_exception",
    [
        (VALID_ROWS_STR, [['192.168.1.1', 'example.com'], ['192.168.1.2', ''], ['', 'example.net']], False),
        (INVALID_ROWS_STR, [], True)
    ]
)
def test_parse_rows(rows_str, expected_result, expect_exception):
    if expect_exception:
        with pytest.raises(Exception):
            parse_rows(rows_str)
    else:
        assert parse_rows(rows_str) == expected_result


@pytest.mark.parametrize(
    "indicator_value, grid_field, mock_response, expected_records, expect_exception",
    [
        (
            'example.com', 'gridField',
            INDICATOR_RESPONSE,
            [
                {"IP": "192.168.1.1", "Hostname": "example.com"},
                {"IP": "192.168.1.2", "Hostname": "example.org"}
            ],
            False
        ),
        (
            'example.com', 'gridField', [{'Type': 4, 'Contents': 'Error'}],
            'Failed to find indicator example.com. Error: Error',
            True
        )
    ]
)
@patch.object(SetIndicatorGridField, 'return_error')
@patch.object(demisto, 'executeCommand')
def test_get_existing_grid_records(mock_executeCommand, mock_return_error, indicator_value,
                                   grid_field, mock_response, expected_records, expect_exception):
    # Mocking the response for 'findIndicators' command
    mock_executeCommand.return_value = mock_response

    if expect_exception:
        mock_return_error.side_effect = Exception(expected_records)
        with pytest.raises(Exception, match=expected_records):
            get_existing_grid_records(indicator_value, grid_field)
        mock_return_error.assert_called_with(expected_records)
    else:
        records = get_existing_grid_records(indicator_value, grid_field)
        assert records == expected_records


@pytest.mark.parametrize(
    "args, append, indicator_response, expected_results, expect_exception",
    [
        (
            # Test Case 1: Valid context input, no append
            {
                "input": [{"ip_addr": "192.168.1.2", "hostname": "example.net"},
                          {"ip_addr": "192.168.1.3", "hostname": "example.com"}],
                "headers": "IP,Hostname",
                "indicator": "example.com",
                "grid_field": "gridField",
                "keys_from_context": "ip_addr,hostname",
                "append": "false"
            },
            False,
            INDICATOR_RESPONSE,
            [
                {"IP": "192.168.1.2", "Hostname": "example.net"},
                {"IP": "192.168.1.3", "Hostname": "example.com"}
            ],
            False
        ),
        (
            # Test Case 2: Valid context input, append
            {
                "input": [{"ip_addr": "192.168.1.3", "hostname": "example.net"}],
                "headers": "IP,Hostname",
                "indicator": "example.com",
                "grid_field": "gridField",
                "keys_from_context": "ip_addr,hostname",
                "append": "true"
            },
            True,
            INDICATOR_RESPONSE,
            [
                {"IP": "192.168.1.1", "Hostname": "example.com"},
                {"IP": "192.168.1.2", "Hostname": "example.org"},
                {"IP": "192.168.1.3", "Hostname": "example.net"}
            ],
            False
        ),
        (
            # Test Case 3: Valid manual input, append
            {
                "input": '["192.168.1.3", "example.net"]',
                "headers": "IP,Hostname",
                "indicator": "example.com",
                "grid_field": "gridField",
                "keys_from_context": "ip_addr,hostname",
                "append": "true"
            },
            True,
            INDICATOR_RESPONSE,
            [
                {"IP": "192.168.1.1", "Hostname": "example.com"},
                {"IP": "192.168.1.2", "Hostname": "example.org"},
                {"IP": "192.168.1.3", "Hostname": "example.net"}
            ],
            False
        ),
        (
            # Test Case 4: No input provided
            {
                "input": '',
                "headers": "IP,Hostname",
                "indicator": "example.com",
                "grid_field": "gridField",
                "keys_from_context": "ip_addr,hostname",
                "append": "false"
            },
            False,
            INDICATOR_RESPONSE,
            'You must provide the "input" argument.',
            True
        ),
        (
            # Test Case 5: Single row
            {
                "input": '["192.168.1.3", "example.com"]',
                "headers": "IP,Hostname",
                "indicator": "example.com",
                "grid_field": "gridField",
                "append": "false"
            },
            False,
            INDICATOR_RESPONSE,
            [
                {"IP": "192.168.1.3", "Hostname": "example.com"}
            ],
            False
        ),
        (
            # Test Case 5: Too many cells in a row
            {
                "input": '["192.168.1.3", "example.com", "bad_input"]',
                "headers": "IP,Hostname",
                "indicator": "example.com",
                "grid_field": "gridField",
                "append": "false"
            },
            False,
            INDICATOR_RESPONSE,
            'Each row must have the same number of elements as there are headers.',
            True
        ),
        (
            # Test Case 7: No keys from context, bad keys in dictionary
            {
                "input": [{"ip_addr": "192.168.1.2", "hostname": "example.net"}],
                "headers": "IP,Hostname",
                "indicator": "example.com",
                "grid_field": "gridField",
                "append": "false"
            },
            False,
            INDICATOR_RESPONSE,
            'Input dictionary keys must match headers when context keys are not provided.',
            True
        ),
        (
            # Test Case 7: No keys from context, valid keys in dictionary
            {
                "input": [{"IP": "192.168.1.2", "Hostname": "example.net"}],
                "headers": "IP,Hostname",
                "indicator": "example.com",
                "grid_field": "gridField",
                "append": "false"
            },
            False,
            INDICATOR_RESPONSE,
            [
                {"IP": "192.168.1.2", "Hostname": "example.net"}
            ],
            False
        ),
    ]
)
@patch.object(demisto, 'executeCommand')
@patch.object(demisto, 'args')
@patch.object(demisto, 'results')
@patch.object(SetIndicatorGridField, 'return_error')
def test_main(mock_return_error, mock_results, mock_args, mock_executeCommand,
              args, append, indicator_response, expected_results, expect_exception):

    # Mocking demisto.args to return the input args
    mock_args.return_value = args

    # Mocking the response to the 'findIndicators' command
    mock_executeCommand.side_effect = [
        indicator_response,  # Response for the 'findIndicators' command
        [{'Type': 1, 'Contents': 'success'}]  # Response for the 'setIndicator' command
    ]

    if expect_exception:
        mock_return_error.side_effect = Exception(expected_results)
        with pytest.raises(Exception, match=expected_results):
            main()

    else:
        main()
        mock_results.assert_called_with(f'Successfully updated indicator {args["indicator"]} grid field {args["grid_field"]}.')
        set_command_args = mock_executeCommand.call_args_list[append][0][1]
        assert set_command_args['value'] == args["indicator"]
        assert set_command_args[args['grid_field']] == expected_results
