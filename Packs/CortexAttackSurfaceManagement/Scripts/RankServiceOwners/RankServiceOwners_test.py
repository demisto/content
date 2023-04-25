import demistomock as demisto  # noqa: F401
import pytest
import unittest
from RankServiceOwners import score, main, rank, _canonicalize, aggregate
from contextlib import nullcontext as does_not_raise


@pytest.mark.parametrize('owners,k,expected_out,expected_raises', [
    # different names
    (
        [
            {
                'Name': 'a', 'Email': 'email1@gmail.com', 'Source': 'source1',
                'Timestamp': '', 'Ranking Score': 1, 'Justification': 'source1'
            },
        ],
        1,
        [
            {
                'Name': 'a', 'Email': 'email1@gmail.com', 'Source': 'source1',
                'Timestamp': '', 'Ranking Score': 1, 'Justification': 'source1'
            },
        ],
        does_not_raise(),
    ),
    (
        [
            {
                'Name': 'a', 'Email': 'email1@gmail.com', 'Source': 'source1',
                'Timestamp': '', 'Ranking Score': 1, 'Justification': 'source1'
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
                'Timestamp': '', 'Ranking Score': 1, 'Justification': 'source1'
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
        pytest.raises(KeyError),
    ),
])
def test_rank(owners, k, expected_out, expected_raises):
    with expected_raises:
        assert rank(owners, k=k) == expected_out


@pytest.mark.parametrize('owner,expected_out', [
    # email with casing, whitespace
    (
        {'Name': 'Alice ', 'Email': 'aLiCe@example.com ', 'Source': 'source1', 'Timestamp': '1'},
        {'Name': 'Alice ', 'Email': 'alice@example.com', 'Source': 'source1', 'Timestamp': '1',
         'Canonicalization': 'alice@example.com'},
    ),
    # name with casing, whitespace
    (
        {'Name': 'Alice ', 'Email': '', 'Source': 'source1', 'Timestamp': '1'},
        {'Name': 'alice', 'Email': '', 'Source': 'source1', 'Timestamp': '1', 'Canonicalization': 'alice'},
    ),
    # neither
    (
        {'Name': '', 'Email': '', 'Source': 'source1', 'Timestamp': '1'},
        {'Name': '', 'Email': '', 'Source': 'source1', 'Timestamp': '1', 'Canonicalization': ''},
    ),
])
def test_canonicalize(owner, expected_out):
    assert _canonicalize(owner) == expected_out


@pytest.mark.parametrize('owners,expected_out', [
    # same email, different names, sources, timestamps
    (
        [
            {'Name': 'Alice ', 'Email': 'alice@example.com', 'Source': 'source1', 'Timestamp': '1',
             'Canonicalization': 'alice@example.com'},
            {'Name': 'Bob ', 'Email': 'alice@example.com', 'Source': 'source2', 'Timestamp': '2',
             'Canonicalization': 'alice@example.com'},
        ],
        [
            {'Name': 'Alice ', 'Email': 'alice@example.com', 'Source': 'source1 | source2', 'Timestamp': '2', 'Count': 2},
        ]
    ),
    # same email, no names
    (
        [
            {'Name': '', 'Email': 'alice@example.com', 'Source': 'source1', 'Timestamp': '1',
             'Canonicalization': 'alice@example.com'},
            {'Name': '', 'Email': 'alice@example.com', 'Source': 'source1', 'Timestamp': '1',
             'Canonicalization': 'alice@example.com'},
        ],
        [
            {'Name': '', 'Email': 'alice@example.com', 'Source': 'source1', 'Timestamp': '1', 'Count': 2},
        ]
    ),
    # same email, same names
    (
        [
            {'Name': 'Alice', 'Email': 'alice@example.com', 'Source': 'source1', 'Timestamp': '1',
             'Canonicalization': 'alice@example.com'},
            {'Name': 'Alice', 'Email': 'bob@example.com', 'Source': 'source2', 'Timestamp': '2',
             'Canonicalization': 'bob@example.com'},
            {'Name': 'Alice', 'Email': 'alice@example.com', 'Source': 'source2', 'Timestamp': '2',
             'Canonicalization': 'alice@example.com'},
        ],
        [
            {'Name': 'Alice', 'Email': 'alice@example.com', 'Source': 'source1 | source2', 'Timestamp': '2', 'Count': 2},
            {'Name': 'Alice', 'Email': 'bob@example.com', 'Source': 'source2', 'Timestamp': '2', 'Count': 1},
        ]
    ),
    # no email, different names
    (
        [
            {'Name': 'alice', 'Email': '', 'Source': 'source1', 'Timestamp': '1', 'Canonicalization': 'alice'},
            {'Name': 'bob', 'Email': '', 'Source': 'source2', 'Timestamp': '2', 'Canonicalization': 'bob'},
        ],
        [
            {'Name': 'alice', 'Email': '', 'Source': 'source1', 'Timestamp': '1', 'Count': 1},
            {'Name': 'bob', 'Email': '', 'Source': 'source2', 'Timestamp': '2', 'Count': 1},
        ]
    ),
    # no email, same names
    (
        [
            {'Name': 'alice', 'Email': '', 'Source': 'source1', 'Timestamp': '1', 'Canonicalization': 'alice'},
            {'Name': 'alice', 'Email': '', 'Source': 'source2', 'Timestamp': '2', 'Canonicalization': 'alice'},
        ],
        [
            {'Name': 'alice', 'Email': '', 'Source': 'source1 | source2', 'Timestamp': '2', 'Count': 2},
        ]
    ),
    # some emails present, others missing
    (
        [
            {'Name': 'Alice', 'Email': 'alice@example.com', 'Source': 'source1', 'Timestamp': '1',
             'Canonicalization': 'alice@example.com'},
            {'Name': 'alice', 'Email': '', 'Source': 'source3', 'Timestamp': '3',
             'Canonicalization': 'alice'},
            {'Name': 'Bob', 'Email': 'alice@example.com', 'Source': 'source2', 'Timestamp': '2',
             'Canonicalization': 'alice@example.com'},
            {'Name': 'alice', 'Email': '', 'Source': 'source4', 'Timestamp': '4',
             'Canonicalization': 'alice'},
        ],
        [
            {'Name': 'Alice', 'Email': 'alice@example.com', 'Source': 'source1 | source2', 'Timestamp': '2', 'Count': 2},
            {'Name': 'alice', 'Email': '', 'Source': 'source3 | source4', 'Timestamp': '4', 'Count': 2},
        ]
    ),
    # empty input
    (
        [],
        []
    )
])
def test_aggregate(owners, expected_out):
    assert sorted(aggregate(owners), key=lambda x: sorted(x.items())) == sorted(expected_out, key=lambda x: sorted(x.items()))


@pytest.mark.parametrize('deduplicated, expected_out', [
    # equal counts
    (
        [
            {'Name': 'aa', 'Email': 'email1@gmail.com', 'Source': 'source1 | source2', 'Timestamp': '2', 'Count': 2},
            {'Name': 'aa', 'Email': '', 'Source': 'source3 | source4', 'Timestamp': '4', 'Count': 2},
        ],
        [
            {'Name': 'aa', 'Email': 'email1@gmail.com', 'Source': 'source1 | source2', 'Timestamp': '2', 'Ranking Score': 1.0},
            {'Name': 'aa', 'Email': '', 'Source': 'source3 | source4', 'Timestamp': '4', 'Ranking Score': 1.0},
        ]
    ),
    # unequal counts
    (
        [
            {'Name': 'aa', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '2', 'Count': 1},
            {'Name': 'aa', 'Email': '', 'Source': 'source3 | source4', 'Timestamp': '4', 'Count': 2},
        ],
        [
            {'Name': 'aa', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '2', 'Ranking Score': 0.5},
            {'Name': 'aa', 'Email': '', 'Source': 'source3 | source4', 'Timestamp': '4', 'Ranking Score': 1.0},
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
                'Ranking Score': 1.0, 'Justification': 'source1'
            },
        ]
    ),
    # empty input
    (
        [],
        []
    ),
    # ideal input with new string field added
    (
        [
            {'Name': 'aa', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1', 'New Field': 'val1'},
            {'Name': 'a', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1', 'New Field': 'val2'},
        ],
        [
            {
                'Name': 'aa', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1',
                'Ranking Score': 1, 'Justification': 'source1', 'New Field': 'val1 | val2'
            },
        ]
    ),
    # ideal input with new numerical field added
    (
        [
            {'Name': 'aa', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1', 'New Field': 1},
            {'Name': 'a', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1', 'New Field': 2},
        ],
        [
            {
                'Name': 'aa', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1',
                'Ranking Score': 1, 'Justification': 'source1', 'New Field': 2,
            },
        ]
    ),
    # ideal input with some new field values added
    (
        [
            {'Name': 'aa', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1', 'New Field': 1},
            {'Name': 'a', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1'},
        ],
        [
            {
                'Name': 'aa', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1',
                'Ranking Score': 1, 'Justification': 'source1', 'New Field': 1,
            },
        ]
    ),
    # ideal input with some new field values added
    (
        [
            {'Name': 'aa', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1', 'New Field': 'val1'},
            {'Name': 'a', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1'},
        ],
        [
            {
                'Name': 'aa', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1',
                'Ranking Score': 1, 'Justification': 'source1', 'New Field': 'val1',
            },
        ]
    ),
    # ideal input with some new field values added that we can't handle
    (
        [
            {'Name': 'aa', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1', 'New Field': None},
            {'Name': 'a', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1'},
        ],
        [
            {
                'Name': 'aa', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1',
                'Ranking Score': 1, 'Justification': 'source1',
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
                'Ranking Score': 1, 'Justification': 'source1'
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
                'Name': 'a', 'Email': None, 'Source': 'source1', 'Timestamp': '1',
                'Ranking Score': 1, 'Justification': 'source1'
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
                'Ranking Score': 1, 'Justification': ''
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
                'Timestamp': '', 'Ranking Score': 1, 'Justification': 'source1'
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
                'Ranking Score': 1, 'Justification': 'source1'
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
                'Ranking Score': 1, 'Justification': 'source1'
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
                'Ranking Score': 1, 'Justification': ''
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
                'Ranking Score': 1, 'Justification': 'source1'
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
                'Name': 'aa', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': 2,
                'Ranking Score': 1.0, 'Justification': 'source1'
            },
        ]
    ),
])
def test_main(mocker, owners, expected_out, capfd):
    # Construct payload
    arg_payload = {}
    arg_payload["owners"] = owners
    mocker.patch.object(demisto,
                        'args',
                        return_value=arg_payload)

    # Execute main using a mock that we can inspect for `executeCommand`
    demisto_execution_mock = mocker.patch.object(demisto, 'executeCommand')
    with capfd.disabled():  # avoids test failures on demisto.error statements
        main()

    # Verify the output value was set
    expected_calls_to_mock_object = [unittest.mock.call('setAlert', {'asmserviceowner': expected_out})]
    assert demisto_execution_mock.call_args_list == expected_calls_to_mock_object
