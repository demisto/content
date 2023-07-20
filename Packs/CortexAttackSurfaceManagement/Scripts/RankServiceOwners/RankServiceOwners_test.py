import demistomock as demisto  # noqa: F401
import pytest
import unittest
from RankServiceOwners import (
    score,
    main,
    rank,
    _canonicalize,
    aggregate,
    _get_k,
    OwnerFeaturizationPipeline,
    load_pickled_xpanse_object,
    LOCAL_MODEL_CACHE_PATH,
    featurize,
    normalize_scores,
)
from contextlib import nullcontext as does_not_raise
import numpy as np
from unittest.mock import Mock
import os
import dill as pickle


def test_load_pickled_xpanse_object():
    obj = [1, 2, 3]
    file_name = "test_model.pkl"
    os.makedirs(LOCAL_MODEL_CACHE_PATH, exist_ok=True)
    cache_path = os.path.join(LOCAL_MODEL_CACHE_PATH, file_name)
    with open(cache_path, "wb") as f:
        pickle.dump(obj, f)

    assert load_pickled_xpanse_object(file_name) == obj
    os.remove(cache_path)
    os.rmdir(LOCAL_MODEL_CACHE_PATH)


@pytest.mark.parametrize('owners,expected_out', [
    (
        # returned in sorted order
        [{'Ranking Score': 0.5}, {'Ranking Score': 1}],
        [{'Ranking Score': 1}, {'Ranking Score': 0.5}]
    ),
    (
        # wraps one test case from _get_k
        [
            {'Ranking Score': 10},
            {'Ranking Score': 1},
            {'Ranking Score': 1},
            {'Ranking Score': 1},
            {'Ranking Score': 1},
            {'Ranking Score': 1},
        ],
        [
            {'Ranking Score': 10},
            {'Ranking Score': 1},
            {'Ranking Score': 1},
            {'Ranking Score': 1},
            {'Ranking Score': 1},
            {'Ranking Score': 1},
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
            {'Name': 'Alice ', 'Email': 'alice@example.com', 'Source': 'source1 | source2', 'Timestamp': '2'},
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
            {'Name': '', 'Email': 'alice@example.com', 'Source': 'source1', 'Timestamp': '1'},
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
            {'Name': 'Alice', 'Email': 'alice@example.com', 'Source': 'source1 | source2', 'Timestamp': '2'},
            {'Name': 'Alice', 'Email': 'bob@example.com', 'Source': 'source2', 'Timestamp': '2'},
        ]
    ),
    # no email, different names
    (
        [
            {'name': 'alice', 'email': '', 'source': 'source1', 'timestamp': '1', 'Canonicalization': 'alice'},
            {'name': 'bob', 'email': '', 'source': 'source2', 'timestamp': '2', 'Canonicalization': 'bob'},
        ],
        [
            {'Name': 'alice', 'Email': '', 'Source': 'source1', 'Timestamp': '1'},
            {'Name': 'bob', 'Email': '', 'Source': 'source2', 'Timestamp': '2'},
        ]
    ),
    # no email, same names
    (
        [
            {'name': 'alice', 'email': '', 'source': 'source1', 'timestamp': '1', 'Canonicalization': 'alice'},
            {'name': 'alice', 'email': '', 'source': 'source2', 'timestamp': '2', 'Canonicalization': 'alice'},
        ],
        [
            {'Name': 'alice', 'Email': '', 'Source': 'source1 | source2', 'Timestamp': '2'},
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
            {'Name': 'Alice', 'Email': 'alice@example.com', 'Source': 'source1 | source2', 'Timestamp': '2'},
            {'Name': 'alice', 'Email': '', 'Source': 'source3 | source4', 'Timestamp': '4'},
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


@pytest.mark.parametrize('scores,expected_out', [
    ([0.5, 1], [0.67, 0.83]),
    ([1, 10, 100], [.5, .55, .95]),
    ([], []),
])
def test_normalize_scores(scores, expected_out):
    assert np.allclose(normalize_scores(scores), expected_out, atol=0.01)


def test_score(mocker):
    model_mock = Mock()
    model_mock.predict.return_value = np.array([4, 7, 31, 0.33, 15])

    mocker.patch(
        'RankServiceOwners.load_pickled_xpanse_object',
        return_value=model_mock
    )

    asm_system_ids = ["afr-rdp-1", "j291mv-is"]

    owners = [
        {'Name': 'Amira', 'Email': 'amira@example.com', 'Source': 'GCP | \
            Chain: GCP project owner of a service account attached to the VM | \
                Owner-In-Tags-From-PrismaCloud | Owner-In-Tags-From-GCP', 'Timestamp': '1'},
        {'Name': 'Brandon', 'Email': 'brandon@example.com', 'Source': 'GCP | \
            Owner-In-Tags-From-GCP | Tenable.io | New-Log-Source', 'Timestamp': '2'},
        {'Name': 'Chun', 'Email': 'chun@example.com', 'Source': 'SNOW-CMDB', 'Timestamp': '3'},
        {'Name': 'Divya', 'Email': 'divya@example.com', 'Source': 'Chain: Chain: \VM launches with a service account, \
            which belongs to GCP project my-project that grants Editor permissions to svc-acct@my-project.gserviceaccount.com, \
                which this person can impersonate', 'Timestamp': '4'},
        {'Name': 'Automation First Remediation', 'Email': 'afr@example.com', 'Source': 'GCP | Splunk', 'Timestamp': '5'},
    ]
    scores_out = [owner['Ranking Score'] for owner in score(asm_system_ids=asm_system_ids, owners=owners)]
    assert np.allclose(scores_out, [0.53, 0.56, 0.77, 0.5, 0.63])


@pytest.mark.parametrize('owners, asm_system_ids, expected_out', [
    # ideal input
    (
        [
            {'name': 'aa', 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': '1'},
            {'name': 'a', 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': '1'},
        ],
        [''],
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
        [],
        []
    ),
    # ideal input with new string field added
    (
        [
            {'name': 'aa', 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': '1', 'New Field': 'val1'},
            {'name': 'a', 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': '1', 'New Field': 'val2'},
        ],
        [''],
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
        [''],
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
        [''],
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
        [''],
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
        [''],
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
        None,
        []
    ),
    # bad inputs -- None
    (
        [None],
        [None],
        []
    ),
    # bad input -- name is None
    (
        [
            {'name': None, 'email': 'email1@gmail.com', 'source': 'source1', 'timestamp': '1'},
        ],
        [''],
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
        [''],
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
        [''],
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
        [''],
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
        [''],
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
        [''],
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
        [''],
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
        [''],
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
        [''],
        [
            {
                'Name': 'aa', 'Email': 'email1@gmail.com', 'Source': 'source1', 'Timestamp': 2,
                'Ranking Score': 1.0, 'Justification': 'source1'
            },
        ]
    ),
])
def test_main(mocker, owners, asm_system_ids, expected_out, capfd):
    # Construct payload
    arg_payload = {}
    arg_payload["owners"] = owners
    arg_payload["asmsystemids"] = asm_system_ids
    mocker.patch.object(demisto,
                        'args',
                        return_value=arg_payload)

    model_mock = Mock()
    model_mock.predict.return_value = np.array([1.0])

    mocker.patch(
        'RankServiceOwners.load_pickled_xpanse_object',
        return_value=model_mock
    )

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


# Featurization Pipeline Tests
def test_get_num_distinct_reasons():
    pipeline = OwnerFeaturizationPipeline()
    out = pipeline.get_num_reasons({
        'Name': 'Amira',
        'Email': 'amira@example.com',
        'Source': 'GCP | Chain: GCP project owner of a service account attached to the VM \
            | Owner-In-Tags-From-PrismaCloud | Owner-In-Tags-From-GCP',
        'Timestamp': '1'
    })
    assert out == 4


def test_get_num_distinct_sources():
    pipeline = OwnerFeaturizationPipeline()
    out = pipeline.get_num_distinct_sources({
        'Name': 'Amira',
        'Email': 'amira@example.com',
        'Source': 'GCP | Chain: GCP project owner of a service account attached to the VM \
            | Owner-In-Tags-From-PrismaCloud | Owner-In-Tags-From-GCP',
        'Timestamp': '1'
    })
    assert out == 2


def test_get_min_path_length():
    pipeline = OwnerFeaturizationPipeline()
    out = pipeline.get_min_path_length({
        'Name': 'Amira',
        'Email': 'amira@example.com',
        'Source': 'X',
        'Timestamp': '1'
    })
    assert out == 1

    pipeline = OwnerFeaturizationPipeline()
    out = pipeline.get_min_path_length({
        'Name': 'Amira',
        'Email': 'amira@example.com',
        'Source': 'Chain: Chain: Chain: Chain: X',
        'Timestamp': '1'
    })
    assert out == 5

    pipeline = OwnerFeaturizationPipeline()
    out = pipeline.get_min_path_length({
        'Name': 'Amira',
        'Email': 'amira@example.com',
        'Source': 'X | Chain: Chain: Chain: Chain: Y',
        'Timestamp': '1'
    })
    assert out == 1


def test_get_name_similarity_person_asset():
    owner = {
        'Name': 'Amira Muhammad',
        'Email': 'amuhammad@example.com',
        'Source': 'irrelevant',
        'Timestamp': '1'
    }

    # has 1/1 matched
    pipeline = OwnerFeaturizationPipeline()
    out = pipeline.get_name_similarity_person_asset(["amira-instance"], owner)
    assert np.isclose(out, 1, rtol=0.01)

    # has 1/2 matched
    pipeline = OwnerFeaturizationPipeline()
    out = pipeline.get_name_similarity_person_asset(["amira-instance", "abc-123"], owner)
    assert out > 1

    # has weak match
    pipeline = OwnerFeaturizationPipeline()
    out = pipeline.get_name_similarity_person_asset(["afm-instance"], owner)
    assert out > 0
    assert out < 1

    # has no match
    pipeline = OwnerFeaturizationPipeline()
    out = pipeline.get_name_similarity_person_asset(["cp-instance"], owner)
    assert out == 0

    # has no asset name info
    pipeline = OwnerFeaturizationPipeline()
    out = pipeline.get_name_similarity_person_asset([], owner)
    assert out == 0

    # has no owner details
    pipeline = OwnerFeaturizationPipeline()
    out = pipeline.get_name_similarity_person_asset(["amira-instance"], {})
    assert out == 0


def test_get_in_cmdb():
    # CMDB attested
    pipeline = OwnerFeaturizationPipeline()
    out = pipeline.get_in_cmdb({
        'Name': 'Amira',
        'Email': 'amira@example.com',
        'Source': 'ABC-XYZ CMDB',
        'Timestamp': '1'
    })
    assert out == 1

    # CMDB not attested
    pipeline = OwnerFeaturizationPipeline()
    out = pipeline.get_in_cmdb({
        'Name': 'Amira',
        'Email': 'amira@example.com',
        'Source': 'Some other source',
        'Timestamp': '1'
    })
    assert out == 0


def test_get_in_logs():
    # Splunk attested
    pipeline = OwnerFeaturizationPipeline()
    out = pipeline.get_in_logs({
        'Name': 'Amira',
        'Email': 'amira@example.com',
        'Source': 'Splunk',
        'Timestamp': '1'
    })
    assert out == 1

    # arbitrary log attested
    pipeline = OwnerFeaturizationPipeline()
    out = pipeline.get_in_logs({
        'Name': 'Amira',
        'Email': 'amira@example.com',
        'Source': 'some LOG source',
        'Timestamp': '1'
    })
    assert out == 1

    # logs not attested
    pipeline = OwnerFeaturizationPipeline()
    out = pipeline.get_in_logs({
        'Name': 'Amira',
        'Email': 'amira@example.com',
        'Source': 'Some other source',
        'Timestamp': '1'
    })
    assert out == 0


def test_base_case():
    """
    Verifies the working case.
    """
    asm_system_ids = ["afr-rdp-1", "j291mv-is"]

    owners = [
        {'Name': 'Amira', 'Email': 'amira@example.com', 'Source': 'GCP | \
            Chain: GCP project owner of a service account attached to the VM | \
                Owner-In-Tags-From-PrismaCloud | Owner-In-Tags-From-GCP', 'Timestamp': '1'},
        {'Name': 'Brandon', 'Email': 'brandon@example.com', 'Source': 'GCP | \
            Owner-In-Tags-From-GCP | Tenable.io | New-Log-Source', 'Timestamp': '2'},
        {'Name': 'Chun', 'Email': 'chun@example.com', 'Source': 'SNOW-CMDB', 'Timestamp': '3'},
        {'Name': 'Divya', 'Email': 'divya@example.com', 'Source': 'Chain: Chain: \VM launches with a service account, \
            which belongs to GCP project my-project that grants Editor permissions to svc-acct@my-project.gserviceaccount.com, \
                which this person can impersonate', 'Timestamp': '4'},
        {'Name': 'Automation First Remediation', 'Email': 'afr@example.com', 'Source': 'GCP | Splunk', 'Timestamp': '5'},
    ]

    observed_output = featurize(asm_system_ids, owners)
    expected_output = np.array(
        [
            # Columns are:
            #  idx_num_reasons = 0,
            #  idx_num_distinct_sources = 1,
            #  idx_min_path_length = 2,
            #  idx_name_similarity_person_asset = 3,
            #  idx_is_attested_in_cmdb = 4,
            #  idx_is_attested_in_recent_logs = 5,
            [4, 2, 1, 0.0, 0, 0],
            [4, 2, 1, 0.0, 0, 1],
            [1, 1, 1, 0.0, 1, 0],
            [1, 1, 3, 0.0, 0, 0],
            [2, 2, 1, 1.0, 0, 1],
        ]
    )
    assert np.allclose(observed_output, expected_output)


def test_missing_data():
    """
    Should not fail if no system IDs or owners are provided
    """
    observed_output = featurize([], [])
    assert np.array_equal(observed_output, np.empty(shape=(0, 6)))
