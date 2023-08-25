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
                'name': 'bob', 'email': 'bob@example.com', 'source': '',
                'timestamp': '', 'ranking_score': 0.5, 'justification': ''
            },
            {
                'name': 'alice', 'email': 'alice@example.com', 'source': '',
                'timestamp': '', 'ranking_score': 1, 'justification': ''
            },
        ],
        [
            {
                'name': 'alice', 'email': 'alice@example.com', 'source': '',
                'timestamp': '', 'ranking_score': 1, 'justification': ''
            },
            {
                'name': 'bob', 'email': 'bob@example.com', 'source': '',
                'timestamp': '', 'ranking_score': 0.5, 'justification': ''
            },
        ]
    ),
    (
        # wraps one test case from _get_k
        [
            {
                'name': 'a', 'email': 'a@example.com', 'source': '',
                'timestamp': '', 'ranking_score': 10, 'justification': ''
            },
            {
                'name': 'b', 'email': 'b@example.com', 'source': '',
                'timestamp': '', 'ranking_score': 1, 'justification': ''
            },
            {
                'name': 'c', 'email': 'c@example.com', 'source': '',
                'timestamp': '', 'ranking_score': 1, 'justification': ''
            },
            {
                'name': 'd', 'email': 'd@example.com', 'source': '',
                'timestamp': '', 'ranking_score': 1, 'justification': ''
            },
            {
                'name': 'e', 'email': 'e@example.com', 'source': '',
                'timestamp': '', 'ranking_score': 1, 'justification': ''
            },
            {
                'name': 'f', 'email': 'f@example.com', 'source': '',
                'timestamp': '', 'ranking_score': 1, 'justification': ''
            },
        ],
        [
            {
                'name': 'a', 'email': 'a@example.com', 'source': '',
                'timestamp': '', 'ranking_score': 10, 'justification': ''
            },
            {
                'name': 'b', 'email': 'b@example.com', 'source': '',
                'timestamp': '', 'ranking_score': 1, 'justification': ''
            },
            {
                'name': 'c', 'email': 'c@example.com', 'source': '',
                'timestamp': '', 'ranking_score': 1, 'justification': ''
            },
            {
                'name': 'd', 'email': 'd@example.com', 'source': '',
                'timestamp': '', 'ranking_score': 1, 'justification': ''
            },
            {
                'name': 'e', 'email': 'e@example.com', 'source': '',
                'timestamp': '', 'ranking_score': 1, 'justification': ''
            },
            {
                'name': 'f', 'email': 'f@example.com', 'source': '',
                'timestamp': '', 'ranking_score': 1, 'justification': ''
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
            {'name': 'Alice ', 'email': 'alice@example.com', 'source': 'source1 | source2', 'timestamp': '2', 'Count': 2},
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
            {'name': '', 'email': 'alice@example.com', 'source': 'source1', 'timestamp': '1', 'Count': 2},
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
            {'name': 'Alice', 'email': 'alice@example.com', 'source': 'source1 | source2', 'timestamp': '2', 'Count': 2},
            {'name': 'Alice', 'email': 'bob@example.com', 'source': 'source2', 'timestamp': '2', 'Count': 1},
        ]
    ),
    # no email, different names
    (
        [
            {'name': 'alice', 'email': '', 'source': 'source1', 'timestamp': '1', 'Canonicalization': 'alice'},
            {'name': 'bob', 'email': '', 'source': 'source2', 'timestamp': '2', 'Canonicalization': 'bob'},
        ],
        [
            {'name': 'alice', 'email': '', 'source': 'source1', 'timestamp': '1', 'Count': 1},
            {'name': 'bob', 'email': '', 'source': 'source2', 'timestamp': '2', 'Count': 1},
        ]
    ),
    # no email, same names
    (
        [
            {'name': 'alice', 'email': '', 'source': 'source1', 'timestamp': '1', 'Canonicalization': 'alice'},
            {'name': 'alice', 'email': '', 'source': 'source2', 'timestamp': '2', 'Canonicalization': 'alice'},
        ],
        [
            {'name': 'alice', 'email': '', 'source': 'source1 | source2', 'timestamp': '2', 'Count': 2},
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
            {'name': 'Alice', 'email': 'alice@example.com', 'source': 'source1 | source2', 'timestamp': '2', 'Count': 2},
            {'name': 'alice', 'email': '', 'source': 'source3 | source4', 'timestamp': '4', 'Count': 2},
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
            {'name': 'aa', 'email': 'email1@gmail.com', 'source': 'source1 | source2', 'timestamp': '2', 'Count': 2},
            {'name': 'aa', 'email': '', 'source': 'source3 | source4', 'timestamp': '4', 'Count': 2},
        ],
        [
            {'name': 'aa', 'email': 'email1@gmail.com', 'source': 'source1 | source2', 'timestamp': '2', 'ranking_score': 1.0},
            {'name': 'aa', 'email': '', 'source': 'source3 | source4', 'timestamp': '4', 'ranking_score': 1.0},
        ]
    ),
    # unequal counts
    (
        [
            {'name': 'aa', 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': '2', 'Count': 1},
            {'name': 'aa', 'email': '', 'source': 'source3 | source4', 'timestamp': '4', 'Count': 2},
        ],
        [
            {'name': 'aa', 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': '2', 'ranking_score': 0.5},
            {'name': 'aa', 'email': '', 'source': 'source3 | source4', 'timestamp': '4', 'ranking_score': 1.0},
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
                'name': 'aa', 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': '1',
                'ranking_score': 1.0, 'justification': 'source1'
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
                'name': 'aa', 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': '1',
                'ranking_score': 1, 'justification': 'source1', 'New Field': 'val1 | val2'
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
                'name': 'aa', 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': '1',
                'ranking_score': 1, 'justification': 'source1', 'New Field': 2,
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
                'name': 'aa', 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': '1',
                'ranking_score': 1, 'justification': 'source1', 'New Field': 1,
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
                'name': 'aa', 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': '1',
                'ranking_score': 1, 'justification': 'source1', 'New Field': 'val1',
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
                'name': 'aa', 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': '1',
                'ranking_score': 1, 'justification': 'source1',
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
                'name': '', 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': '1',
                'ranking_score': 1, 'justification': 'source1'
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
                'name': 'a', 'email': None, 'source': 'source1', 'timestamp': '1',
                'ranking_score': 1, 'justification': 'source1'
            },
        ]
    ),
    # bad input -- source is None
    (
        [
            {'name': 'a', 'email': 'email1@gmail.com', 'source': None, 'timestamp': '1'},
        ],
        [
            {
                'name': 'a', 'email': 'email1@gmail.com', 'source': '', 'timestamp': '1',
                'ranking_score': 1, 'justification': ''
            },
        ]
    ),
    # bad input -- timestamp is None
    (
        [
            {'name': 'a', 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': None},
        ],
        [
            {
                'name': 'a', 'email': 'email1@gmail.com', 'source': 'source1',
                'timestamp': '', 'ranking_score': 1, 'justification': 'source1'
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
                'name': '', 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': '1',
                'ranking_score': 1, 'justification': 'source1'
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
                'name': 'a', 'email': '', 'source': 'source1', 'timestamp': '1',
                'ranking_score': 1, 'justification': 'source1'
            },
        ]
    ),
    # bad input -- missing source
    (
        [
            {'name': 'a', 'email': 'email1@gmail.com', 'timestamp': '1'},
        ],
        [
            {
                'name': 'a', 'email': 'email1@gmail.com', 'source': '', 'timestamp': '1',
                'ranking_score': 1, 'justification': ''
            },
        ]
    ),
    # bad input -- missing timestamp
    (
        [
            {'name': 'a', 'email': 'email1@gmail.com', 'source': 'source1'},
        ],
        [
            {
                'name': 'a', 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': '',
                'ranking_score': 1, 'justification': 'source1'
            },
        ]
    ),
    # timestamp as numerical type
    (
        [
            {'name': 'aa', 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': 1},
            {'name': 'a', 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': 2},
        ],
        [
            {
                'name': 'aa', 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': 2,
                'ranking_score': 1.0, 'justification': 'source1'
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
