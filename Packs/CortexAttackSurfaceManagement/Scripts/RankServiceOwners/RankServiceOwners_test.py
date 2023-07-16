import demistomock as demisto  # noqa: F401
import pytest
import unittest
from RankServiceOwners import score, main, rank, _canonicalize, aggregate, _get_k
from contextlib import nullcontext as does_not_raise


@pytest.mark.parametrize('owners,expected_out', [
    (
        # returned in sorted order
        [
            {
                'Name': 'bob', 'Email': 'bob@example.com', 'Source': '',
                'Timestamp': '', 'Ranking Score': 0.5, 'Justification': ''
            },
            {
                'Name': 'alice', 'Email': 'alice@example.com', 'Source': '',
                'Timestamp': '', 'Ranking Score': 1, 'Justification': ''
            },
        ],
        [
            {
                'Name': 'alice', 'Email': 'alice@example.com', 'Source': '',
                'Timestamp': '', 'Ranking Score': 1, 'Justification': ''
            },
            {
                'Name': 'bob', 'Email': 'bob@example.com', 'Source': '',
                'Timestamp': '', 'Ranking Score': 0.5, 'Justification': ''
            },
        ]
    ),
    (
        # wraps one test case from _get_k
        [
            {
                'Name': 'a', 'Email': 'a@example.com', 'Source': '',
                'Timestamp': '', 'Ranking Score': 10, 'Justification': ''
            },
            {
                'Name': 'b', 'Email': 'b@example.com', 'Source': '',
                'Timestamp': '', 'Ranking Score': 1, 'Justification': ''
            },
            {
                'Name': 'c', 'Email': 'c@example.com', 'Source': '',
                'Timestamp': '', 'Ranking Score': 1, 'Justification': ''
            },
            {
                'Name': 'd', 'Email': 'd@example.com', 'Source': '',
                'Timestamp': '', 'Ranking Score': 1, 'Justification': ''
            },
            {
                'Name': 'e', 'Email': 'e@example.com', 'Source': '',
                'Timestamp': '', 'Ranking Score': 1, 'Justification': ''
            },
            {
                'Name': 'f', 'Email': 'f@example.com', 'Source': '',
                'Timestamp': '', 'Ranking Score': 1, 'Justification': ''
            },
        ],
        [
            {
                'Name': 'a', 'Email': 'a@example.com', 'Source': '',
                'Timestamp': '', 'Ranking Score': 10, 'Justification': ''
            },
            {
                'Name': 'b', 'Email': 'b@example.com', 'Source': '',
                'Timestamp': '', 'Ranking Score': 1, 'Justification': ''
            },
            {
                'Name': 'c', 'Email': 'c@example.com', 'Source': '',
                'Timestamp': '', 'Ranking Score': 1, 'Justification': ''
            },
            {
                'Name': 'd', 'Email': 'd@example.com', 'Source': '',
                'Timestamp': '', 'Ranking Score': 1, 'Justification': ''
            },
            {
                'Name': 'e', 'Email': 'e@example.com', 'Source': '',
                'Timestamp': '', 'Ranking Score': 1, 'Justification': ''
            },
            {
                'Name': 'f', 'Email': 'f@example.com', 'Source': '',
                'Timestamp': '', 'Ranking Score': 1, 'Justification': ''
            },
        ]
    ),
])
def test_rank(owners, expected_out):
    assert rank(owners) == expected_out


@pytest.mark.parametrize('owner,expected_out', [
    # email with casing, whitespace
    (
        {'name': 'Alice ', 'email': 'aLiCe@example.com ', 'source': 'source1', 'timestamp': '1'},
        {'name': 'Alice ', 'email': 'alice@example.com', 'source': 'source1', 'timestamp': '1',
         'Canonicalization': 'alice@example.com'},
    ),
    # name with casing, whitespace
    (
        {'name': 'Alice ', 'email': '', 'source': 'source1', 'timestamp': '1'},
        {'name': 'alice', 'email': '', 'source': 'source1', 'timestamp': '1', 'Canonicalization': 'alice'},
    ),
    # neither
    (
        {'name': '', 'email': '', 'source': 'source1', 'timestamp': '1'},
        {'name': '', 'email': '', 'source': 'source1', 'timestamp': '1', 'Canonicalization': ''},
    ),
])
def test_canonicalize(owner, expected_out):
    assert _canonicalize(owner) == expected_out


@pytest.mark.parametrize('owners,expected_out', [
    # same email, different names, sources, timestamps
    (
        [
            {'name': 'Alice ', 'email': 'alice@example.com', 'source': 'source1', 'timestamp': '1',
             'Canonicalization': 'alice@example.com'},
            {'name': 'Bob ', 'email': 'alice@example.com', 'source': 'source2', 'timestamp': '2',
             'Canonicalization': 'alice@example.com'},
        ],
        [
            {'Name': 'Alice ', 'Email': 'alice@example.com', 'Source': 'source1 | source2', 'Timestamp': '2', 'Count': 2},
        ]
    ),
    # same email, no names
    (
        [
            {'name': '', 'email': 'alice@example.com', 'source': 'source1', 'timestamp': '1',
             'Canonicalization': 'alice@example.com'},
            {'name': '', 'email': 'alice@example.com', 'source': 'source1', 'timestamp': '1',
             'Canonicalization': 'alice@example.com'},
        ],
        [
            {'Name': '', 'Email': 'alice@example.com', 'Source': 'source1', 'Timestamp': '1', 'Count': 2},
        ]
    ),
    # same email, same names
    (
        [
            {'name': 'Alice', 'email': 'alice@example.com', 'source': 'source1', 'timestamp': '1',
             'Canonicalization': 'alice@example.com'},
            {'name': 'Alice', 'email': 'bob@example.com', 'source': 'source2', 'timestamp': '2',
             'Canonicalization': 'bob@example.com'},
            {'name': 'Alice', 'email': 'alice@example.com', 'source': 'source2', 'timestamp': '2',
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
            {'name': 'alice', 'email': '', 'source': 'source1', 'timestamp': '1', 'Canonicalization': 'alice'},
            {'name': 'bob', 'email': '', 'source': 'source2', 'timestamp': '2', 'Canonicalization': 'bob'},
        ],
        [
            {'Name': 'alice', 'Email': '', 'Source': 'source1', 'Timestamp': '1', 'Count': 1},
            {'Name': 'bob', 'Email': '', 'Source': 'source2', 'Timestamp': '2', 'Count': 1},
        ]
    ),
    # no email, same names
    (
        [
            {'name': 'alice', 'email': '', 'source': 'source1', 'timestamp': '1', 'Canonicalization': 'alice'},
            {'name': 'alice', 'email': '', 'source': 'source2', 'timestamp': '2', 'Canonicalization': 'alice'},
        ],
        [
            {'Name': 'alice', 'Email': '', 'Source': 'source1 | source2', 'Timestamp': '2', 'Count': 2},
        ]
    ),
    # some emails present, others missing
    (
        [
            {'name': 'Alice', 'email': 'alice@example.com', 'source': 'source1', 'timestamp': '1',
             'Canonicalization': 'alice@example.com'},
            {'name': 'alice', 'email': '', 'source': 'source3', 'timestamp': '3',
             'Canonicalization': 'alice'},
            {'name': 'Bob', 'email': 'alice@example.com', 'source': 'source2', 'timestamp': '2',
             'Canonicalization': 'alice@example.com'},
            {'name': 'alice', 'email': '', 'source': 'source4', 'timestamp': '4',
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
            {'name': 'aa', 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': '1'},
            {'name': 'a', 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': '1'},
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
            {'name': 'aa', 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': '1', 'New Field': 'val1'},
            {'name': 'a', 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': '1', 'New Field': 'val2'},
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
            {'name': 'aa', 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': '1', 'New Field': 1},
            {'name': 'a', 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': '1', 'New Field': 2},
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
            {'name': 'aa', 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': '1', 'New Field': 1},
            {'name': 'a', 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': '1'},
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
            {'name': 'aa', 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': '1', 'New Field': 'val1'},
            {'name': 'a', 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': '1'},
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
            {'name': 'aa', 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': '1', 'New Field': None},
            {'name': 'a', 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': '1'},
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
    # bad input -- name is None
    (
        [
            {'name': None, 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': '1'},
        ],
        [
            {
                'Name': '', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1',
                'Ranking Score': 1, 'Justification': 'source1'
            },
        ]
    ),
    # bad input -- email is None
    (
        [
            {'name': 'a', 'email': None, 'source': 'source1', 'timestamp': '1'},
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
            {'name': 'a', 'email': 'email1@gmail.com', 'source': None, 'timestamp': '1'},
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
            {'name': 'a', 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': None},
        ],
        [
            {
                'Name': 'a', 'Email': 'email1@gmail.com', 'Source': 'source1',
                'Timestamp': '', 'Ranking Score': 1, 'Justification': 'source1'
            },
        ]
    ),
    # bad input -- missing name
    (
        [
            {'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': '1'},
        ],
        [
            {
                'Name': '', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': '1',
                'Ranking Score': 1, 'Justification': 'source1'
            },
        ]
    ),
    # bad input -- missing email
    (
        [
            {'name': 'a', 'source': 'source1', 'timestamp': '1'},
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
            {'name': 'a', 'email': 'email1@gmail.com', 'timestamp': '1'},
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
            {'name': 'a', 'email': 'email1@gmail.com', 'source': 'source1'},
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
            {'name': 'aa', 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': 1},
            {'name': 'a', 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': 2},
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


def test_get_k():
    """
    These cases are designed to specify the intuition we are trying to implement with the algorithm
    and verify its default hyperparameters.
    We assert that if the algorithm matches our intuition at least 80% of the time, it's probably fine.

    See function documentation for explanation of hyperparameters and their defaults.
    """

    # The first value in each cases is the list of scores output by the model (one per owner)
    # and the second value is the expected k
    cases = [
        # If smallish set of owners, return all or find obvious cutoff
        ([1], 1),
        ([1, 1], 2),
        ([1, 1, 1], 3),
        ([10, 1, 1], 3),
        ([1, 1, 1, 1], 4),
        ([10, 1, 1, 1], 4),
        ([10, 10, 1, 1], 4),  # or 2; either seems fine
        ([10, 10, 1, 1], 2),  # or 4; either seems fine
        ([1, 1, 1, 1, 1], 5),
        ([10, 1, 1, 1, 1], 5),
        ([10, 10, 1, 1, 1], 2),
        ([1, 1, 1, 1, 1, 1], 6),
        ([1, 1, 1, 1, 1, 1, 1], 7),

        # If larger set of owners, return top handful or find obvious cutoff
        ([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1], 5),
        ([10, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1], 5),
        ([10, 10, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1], 5),  # or 2; either seems fine
        ([10, 10, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1], 2),  # or 5; either seems fine
        ([10, 10, 10, 1, 1, 1, 1, 1, 1, 1, 1, 1], 3),
        ([10, 10, 10, 10, 1, 1, 1, 1, 1, 1, 1, 1], 4),
        ([10, 10, 10, 10, 10, 1, 1, 1, 1, 1, 1, 1], 5),
        ([100, 10, 10, 10, 10, 1, 1, 1, 1, 1, 1, 1], 5),
        ([100, 10, 10, 10, 10, 10, 1, 1, 1, 1, 1, 1], 6),

        # Do something reasonable for non-obvious cutoffs
        ([10, 9, 8, 7, 6, 5, 4, 3, 2, 1], 5),
        ([19, 17, 15, 13, 11, 9, 7, 5, 3, 1], 5),

        # Do something reasonable for larger scales
        ([500, 200, 100, 50, 25, 10, 1], 3),
    ]
    num_correct = 0
    for scores, expected_k in cases:
        if _get_k(scores) == expected_k:
            num_correct += 1

    assert (num_correct / len(cases)) >= 0.8


@pytest.mark.parametrize('target_k, k_tol, a_tol, min_score_proportion, expected_raises', [
    (-1, 2, 1.0, 0.75, pytest.raises(ValueError, match="target_k must be non-negative")),
    (5, -1, 1.0, 0.75, pytest.raises(ValueError, match="k_tol must be non-negative")),
    (5, 2, -1, 0.75, pytest.raises(ValueError, match="a_tol must be non-negative")),
    (5, 2, 1.0, -1, pytest.raises(ValueError, match="min_score_proportion must be a value between 0 and 1")),
    (5, 2, 1.0, 1.1, pytest.raises(ValueError, match="min_score_proportion must be a value between 0 and 1")),
    (5, 2, 1.0, 0.75, does_not_raise()),
])
def test_get_k_bad_values(target_k, k_tol, a_tol, min_score_proportion, expected_raises):
    scores = [1, 1, 1]
    with expected_raises:
        assert _get_k(
            scores,
            target_k=target_k,
            k_tol=k_tol,
            a_tol=a_tol,
            min_score_proportion=min_score_proportion,
        )
