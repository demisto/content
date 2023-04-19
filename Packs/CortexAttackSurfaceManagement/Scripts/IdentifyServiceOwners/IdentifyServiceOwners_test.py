import demistomock as demisto  # noqa: F401
import pytest
import unittest
from IdentifyServiceOwners import deduplicate, score, main, rank
from contextlib import nullcontext as does_not_raise


@pytest.mark.parametrize('owners,k,expected_out,expected_raises', [
    # different names
    (
        [
            {
                'Name': 'a', 'Email': 'email1@gmail.com', 'Source': 'source1',
                'Timestamp': '', 'Confidence Score': 1, 'Justification': 'source1'
            },
        ],
        1,
        [
            {
                'Name': 'a', 'Email': 'email1@gmail.com', 'Source': 'source1',
                'Timestamp': '', 'Confidence Score': 1, 'Justification': 'source1'
            },
        ],
        does_not_raise(),
    ),
    (
        [
            {
                'Name': 'a', 'Email': 'email1@gmail.com', 'Source': 'source1',
                'Timestamp': '', 'Confidence Score': 1, 'Justification': 'source1'
            },
        ],
        0,
        None,
        pytest.raises(ValueError),
    ),
    (
        [
            {
                'Name': 'a', 'Email': 'email1@gmail.com', 'Source': 'source1',
                'Timestamp': '', 'Confidence Score': 1, 'Justification': 'source1'
            },
        ],
        -1,
        None,
        pytest.raises(ValueError),
    ),
    (
        [
            {'Name': 'a', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': ''},
        ],
        1,
        None,
        pytest.raises(ValueError),
    ),
])
def test_rank(owners, k, expected_out, expected_raises):
    with expected_raises:
        assert rank(owners, k=k) == expected_out


@pytest.mark.parametrize('owners,expected_out', [
    # different names
    (
        [
            {'Name': 'aa', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1'},
            {'Name': 'a', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1'},
        ],
        [
            {'Name': 'aa', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1', 'Count': 2},
        ]
    ),
    # empty names
    (
        [
            {'Name': '', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1'},
            {'Name': '', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1'},
        ],
        [
            {'Name': '', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1', 'Count': 2},
        ]
    ),
    # different sources
    (
        [
            {'Name': 'a', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1'},
            {'Name': 'a', 'Email': 'email1@gmail.com', 'Source': 'source2', 'Timestamp': '1'},
        ],
        [
            {'Name': 'a', 'Email': 'email1@gmail.com', 'Source': 'source1 | source2', 'Timestamp': '1', 'Count': 2},
        ]
    ),
    # different timestamps
    (
        [
            {'Name': 'a', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1'},
            {'Name': 'a', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '2'},
        ],
        [
            {'Name': 'a', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '2', 'Count': 2},
        ]
    ),
    # different names, sources, and timestamps
    (
        [
            {'Name': 'aa', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1'},
            {'Name': 'a', 'Email': 'email1@gmail.com', 'Source': 'source2', 'Timestamp': '2'},
        ],
        [
            {'Name': 'aa', 'Email': 'email1@gmail.com', 'Source': 'source1 | source2', 'Timestamp': '2', 'Count': 2},
        ]
    ),
    # same names
    (
        [
            {'Name': 'a', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1'},
            {'Name': 'a', 'Email': 'email2@gmail.com', 'Source': 'source2', 'Timestamp': '2'},
            {'Name': 'a', 'Email': 'email1@gmail.com', 'Source': 'source2', 'Timestamp': '2'},
        ],
        [
            {'Name': 'a', 'Email': 'email1@gmail.com', 'Source': 'source1 | source2', 'Timestamp': '2', 'Count': 2},
            {'Name': 'a', 'Email': 'email2@gmail.com', 'Source': 'source2', 'Timestamp': '2', 'Count': 1},
        ]
    ),
    # whitespace
    (
        [
            {'Name': 'a', 'Email': 'email1@gmail.com  ', 'Source': 'source1', 'Timestamp': '1'},
            {'Name': 'a', 'Email': '   email1@gmail.com  ', 'Source': 'source1', 'Timestamp': '1'},
        ],
        [
            {'Name': 'a', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1', 'Count': 2},
        ]
    ),
])
def test_dedup_email(owners, expected_out):
    assert sorted(deduplicate(owners), key=lambda x: sorted(x.items())) == sorted(expected_out, key=lambda x: sorted(x.items()))


@pytest.mark.parametrize('owners,expected_out', [
    # different names
    (
        [
            {'Name': 'aa', 'Email': '', 'Source': 'source1', 'Timestamp': '1'},
            {'Name': 'a', 'Email': '', 'Source': 'source1', 'Timestamp': '2'},
        ],
        [
            {'Name': 'a', 'Email': '', 'Source': 'source1', 'Timestamp': '2', 'Count': 1},
            {'Name': 'aa', 'Email': '', 'Source': 'source1', 'Timestamp': '1', 'Count': 1},
        ]
    ),
    # same names, same source
    (
        [
            {'Name': 'a', 'Email': '', 'Source': 'source1', 'Timestamp': '1'},
            {'Name': 'a', 'Email': '', 'Source': 'source1', 'Timestamp': '2'},
        ],
        [
            {'Name': 'a', 'Email': '', 'Source': 'source1', 'Timestamp': '2', 'Count': 2},
        ]
    ),
    # same names, different source
    (
        [
            {'Name': 'a', 'Email': '', 'Source': 'source1', 'Timestamp': '1'},
            {'Name': 'a', 'Email': '', 'Source': 'source2', 'Timestamp': '2'},
        ],
        [
            {'Name': 'a', 'Email': '', 'Source': 'source1 | source2', 'Timestamp': '2', 'Count': 2},
        ]
    ),
    # some emails present, others missing
    (
        [
            {'Name': 'aa', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1'},
            {'Name': 'aa', 'Email': '', 'Source': 'source3', 'Timestamp': '3'},
            {'Name': 'a', 'Email': 'email1@gmail.com', 'Source': 'source2', 'Timestamp': '2'},
            {'Name': 'aa', 'Email': '', 'Source': 'source4', 'Timestamp': '4'},
        ],
        [
            {'Name': 'aa', 'Email': 'email1@gmail.com', 'Source': 'source1 | source2', 'Timestamp': '2', 'Count': 2},
            {'Name': 'aa', 'Email': '', 'Source': 'source3 | source4', 'Timestamp': '4', 'Count': 2},
        ]
    ),
    # empty input
    (
        [],
        []
    )
])
def test_dedup_name(owners, expected_out):
    assert sorted(deduplicate(owners), key=lambda x: sorted(x.items())) == sorted(expected_out, key=lambda x: sorted(x.items()))


@pytest.mark.parametrize('deduplicated, expected_out', [
    # equal counts
    (
        [
            {'Name': 'aa', 'Email': 'email1@gmail.com', 'Source': 'source1 | source2', 'Timestamp': '2', 'Count': 2},
            {'Name': 'aa', 'Email': '', 'Source': 'source3 | source4', 'Timestamp': '4', 'Count': 2},
        ],
        [
            {'Name': 'aa', 'Email': 'email1@gmail.com', 'Source': 'source1 | source2', 'Timestamp': '2', 'Confidence Score': 1.0},
            {'Name': 'aa', 'Email': '', 'Source': 'source3 | source4', 'Timestamp': '4', 'Confidence Score': 1.0},
        ]
    ),
    # unequal counts
    (
        [
            {'Name': 'aa', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '2', 'Count': 1},
            {'Name': 'aa', 'Email': '', 'Source': 'source3 | source4', 'Timestamp': '4', 'Count': 2},
        ],
        [
            {'Name': 'aa', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '2', 'Confidence Score': 0.5},
            {'Name': 'aa', 'Email': '', 'Source': 'source3 | source4', 'Timestamp': '4', 'Confidence Score': 1.0},
        ]
    ),
    # empty owners
    (
        [],
        []
    )
])
def test_score(deduplicated, expected_out):
    assert score(deduplicated) == expected_out


@pytest.mark.parametrize('owners, expected_out', [
    # ideal input
    (
        [
            {'Name': 'aa', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1'},
            {'Name': 'a', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1'},
        ],
        [
            {
                'Name': 'aa', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1',
                'Confidence Score': 1, 'Justification': 'source1'
            },
        ]
    ),
    # empty input
    (
        [],
        []
    ),
    # ideal input with garbage field added
    (
        [
            {'Name': 'aa', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1', 'Int Field': 1},
            {'Name': 'a', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1', 'String Field': 'val'},
        ],
        [
            {
                'Name': 'aa', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1',
                'Confidence Score': 1, 'Justification': 'source1'
            },
        ]
    ),
    # bad inputs -- None
    (
        None,
        []
    ),
    # bad inputs -- None
    (
        [None],
        []
    ),
    # bad input -- Name is None
    (
        [
            {'Name': None, 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1'},
        ],
        [
            {
                'Name': '', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1',
                'Confidence Score': 1, 'Justification': 'source1'
            },
        ]
    ),
    # bad input -- Email is None
    (
        [
            {'Name': 'a', 'Email': None, 'Source': 'source1', 'Timestamp': '1'},
        ],
        [
            {
                'Name': 'a', 'Email': '', 'Source': 'source1', 'Timestamp': '1',
                'Confidence Score': 1, 'Justification': 'source1'
            },
        ]
    ),
    # bad input -- Source is None
    (
        [
            {'Name': 'a', 'Email': 'email1@gmail.com', 'Source': None, 'Timestamp': '1'},
        ],
        [
            {
                'Name': 'a', 'Email': 'email1@gmail.com', 'Source': '', 'Timestamp': '1',
                'Confidence Score': 1, 'Justification': ''
            },
        ]
    ),
    # bad input -- Timestamp is None
    (
        [
            {'Name': 'a', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': None},
        ],
        [
            {
                'Name': 'a', 'Email': 'email1@gmail.com', 'Source': 'source1',
                'Timestamp': '', 'Confidence Score': 1, 'Justification': 'source1'
            },
        ]
    ),
    # bad input -- missing Name
    (
        [
            {'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1'},
        ],
        [
            {
                'Name': '', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1',
                'Confidence Score': 1, 'Justification': 'source1'
            },
        ]
    ),
    # bad input -- missing Email
    (
        [
            {'Name': 'a', 'Source': 'source1', 'Timestamp': '1'},
        ],
        [
            {
                'Name': 'a', 'Email': '', 'Source': 'source1', 'Timestamp': '1',
                'Confidence Score': 1, 'Justification': 'source1'
            },
        ]
    ),
    # bad input -- missing Source
    (
        [
            {'Name': 'a', 'Email': 'email1@gmail.com', 'Timestamp': '1'},
        ],
        [
            {
                'Name': 'a', 'Email': 'email1@gmail.com', 'Source': '', 'Timestamp': '1',
                'Confidence Score': 1, 'Justification': ''
            },
        ]
    ),
    # bad input -- missing Timestamp
    (
        [
            {'Name': 'a', 'Email': 'email1@gmail.com', 'Source': 'source1'},
        ],
        [
            {
                'Name': 'a', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '',
                'Confidence Score': 1, 'Justification': 'source1'
            },
        ]
    ),
    # Timestamp as numerical type
    (
        [
            {'Name': 'aa', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': 1},
            {'Name': 'a', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': 2},
        ],
        [
            {
                'Name': 'aa', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '2',
                'Confidence Score': 1, 'Justification': 'source1'
            },
        ]
    ),
])
def test_main(mocker, owners, expected_out):
    # Construct payload
    arg_payload = {}
    arg_payload["owners"] = owners
    mocker.patch.object(demisto,
                        'args',
                        return_value=arg_payload)

    # Execute main using a mock that we can inspect for `executeCommand`
    demisto_execution_mock = mocker.patch.object(demisto, 'executeCommand')
    main()

    # Verify the output value was set
    expected_calls_to_mock_object = [unittest.mock.call('setAlert', {'asmserviceowner': expected_out})]
    assert demisto_execution_mock.call_args_list == expected_calls_to_mock_object
