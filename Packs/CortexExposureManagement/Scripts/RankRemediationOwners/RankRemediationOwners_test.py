import demistomock as demisto  # noqa: F401

from contextlib import nullcontext as does_not_raise
import dill as pickle
import numpy as np
import pytest
import unittest
from unittest.mock import Mock

from RankRemediationOwners import (
    OwnerFeaturizationPipeline,
    _canonicalize,
    _get_k,
    aggregate,
    featurize,
    load_pickled_xpanse_object,
    main,
    normalize_scores,
    score,
    write_output_to_context_key,
)


def test_load_pickled_xpanse_object(tmp_path):
    """
    Tests load_pickled_xpanse_obje function.
    Given:
    - A mocked demisto.getFilePath function returns a valid file path and a pickled xpanse object file exists with serialized data
    When:
    - Running the 'load_pickled_xpanse_obje' function.
    Then:
    - Checks the function successfully loads and returns the unpickled xpanse object with preserved data integrity and no
      exceptions.
    """
    # create temporary local cache
    cache_path = tmp_path / "tmp"
    cache_path.mkdir()

    # write dummy object to cache
    file_name = "test_model.pkl"
    file_cache_path = cache_path / file_name
    obj = [1, 2, 3]
    with open(file_cache_path, "wb") as f:
        pickle.dump(obj, f)

    # test that object is loaded
    assert load_pickled_xpanse_object(file_name, cache_path) == obj


@pytest.mark.parametrize(
    "owner,expected_out",
    [
        # email with casing, whitespace
        (
            {"name": "Alice ", "email": "aLiCe@example.com ", "source": "source1", "timestamp": "1"},
            {
                "name": "Alice ",
                "email": "alice@example.com",
                "source": "source1",
                "timestamp": "1",
                "canonicalization": "alice@example.com",
            },
        ),
        # name with casing, whitespace
        (
            {"name": "Alice ", "email": "", "source": "source1", "timestamp": "1"},
            {"name": "alice", "email": "", "source": "source1", "timestamp": "1", "canonicalization": "alice"},
        ),
        # neither
        (
            {"name": "", "email": "", "source": "source1", "timestamp": "1"},
            {"name": "", "email": "", "source": "source1", "timestamp": "1", "canonicalization": ""},
        ),
    ],
)
def test_canonicalize(owner, expected_out):
    """
    Test that we use the lower-cased email or name as the owner key
    Given:
    - Input data that needs to be normalized or canonicalized to a standard format
    When:
    - Running the 'canonicalize' function.
    Then:
    - Checks the function converts input to canonical form and returns properly formatted standardized data.
    """
    assert _canonicalize(owner) == expected_out


@pytest.mark.parametrize(
    "owners,expected_out",
    [
        # same email, different names, sources, timestamps
        (
            [
                {
                    "name": "Alice ",
                    "email": "alice@example.com",
                    "source": "source1",
                    "timestamp": "1",
                    "canonicalization": "alice@example.com",
                },
                {
                    "name": "Bob ",
                    "email": "alice@example.com",
                    "source": "source2",
                    "timestamp": "2",
                    "canonicalization": "alice@example.com",
                },
            ],
            [
                {"name": "Alice ", "email": "alice@example.com", "source": "source1 | source2", "timestamp": "2"},
            ],
        ),
        # same email, no names
        (
            [
                {
                    "name": "",
                    "email": "alice@example.com",
                    "source": "source1",
                    "timestamp": "1",
                    "canonicalization": "alice@example.com",
                },
                {
                    "name": "",
                    "email": "alice@example.com",
                    "source": "source1",
                    "timestamp": "1",
                    "canonicalization": "alice@example.com",
                },
            ],
            [
                {"name": "", "email": "alice@example.com", "source": "source1", "timestamp": "1"},
            ],
        ),
        # same email, same names
        (
            [
                {
                    "name": "Alice",
                    "email": "alice@example.com",
                    "source": "source1",
                    "timestamp": "1",
                    "canonicalization": "alice@example.com",
                },
                {
                    "name": "Alice",
                    "email": "bob@example.com",
                    "source": "source2",
                    "timestamp": "2",
                    "canonicalization": "bob@example.com",
                },
                {
                    "name": "Alice",
                    "email": "alice@example.com",
                    "source": "source2",
                    "timestamp": "2",
                    "canonicalization": "alice@example.com",
                },
            ],
            [
                {"name": "Alice", "email": "alice@example.com", "source": "source1 | source2", "timestamp": "2"},
                {"name": "Alice", "email": "bob@example.com", "source": "source2", "timestamp": "2"},
            ],
        ),
        # no email, different names
        (
            [
                {"name": "alice", "email": "", "source": "source1", "timestamp": "1", "canonicalization": "alice"},
                {"name": "bob", "email": "", "source": "source2", "timestamp": "2", "canonicalization": "bob"},
            ],
            [
                {"name": "alice", "email": "", "source": "source1", "timestamp": "1"},
                {"name": "bob", "email": "", "source": "source2", "timestamp": "2"},
            ],
        ),
        # no email, same names
        (
            [
                {"name": "alice", "email": "", "source": "source1", "timestamp": "1", "canonicalization": "alice"},
                {"name": "alice", "email": "", "source": "source2", "timestamp": "2", "canonicalization": "alice"},
            ],
            [
                {"name": "alice", "email": "", "source": "source1 | source2", "timestamp": "2"},
            ],
        ),
        # some emails present, others missing
        (
            [
                {
                    "name": "Alice",
                    "email": "alice@example.com",
                    "source": "source1",
                    "timestamp": "1",
                    "canonicalization": "alice@example.com",
                },
                {"name": "alice", "email": "", "source": "source3", "timestamp": "3", "canonicalization": "alice"},
                {
                    "name": "Bob",
                    "email": "alice@example.com",
                    "source": "source2",
                    "timestamp": "2",
                    "canonicalization": "alice@example.com",
                },
                {"name": "alice", "email": "", "source": "source4", "timestamp": "4", "canonicalization": "alice"},
            ],
            [
                {"name": "Alice", "email": "alice@example.com", "source": "source1 | source2", "timestamp": "2"},
                {"name": "alice", "email": "", "source": "source3 | source4", "timestamp": "4"},
            ],
        ),
        # empty input
        ([], []),
    ],
)
def test_aggregate(owners, expected_out):
    """
    Test that owners are deduplicated first by email then by name, with the remaining
    fields aggregated as expected (union over source, max over timestamp)
    Given:
    - Input data that needs to be aggregated or combined according to specific criteria
    When:
    - Running the 'aggregate' function.
    Then:
    - Checks the function properly aggregates the data and returns correctly combined results.
    """
    assert sorted(aggregate(owners), key=lambda x: sorted(x.items())) == sorted(expected_out, key=lambda x: sorted(x.items()))


@pytest.mark.parametrize(
    "scores,expected_out",
    [
        ([1, 1, 1], [1, 1, 1]),
        ([0.5, 0.5, 0.5], [1, 1, 1]),
        ([2, 1, 1], [1.0, 0.5, 0.5]),
        ([5, 2, 1, 1], [1.0, 0.62, 0.5, 0.5]),
        ([10, 2, 1, 1, 1], [1.0, 0.56, 0.5, 0.5, 0.5]),
        ([100, 10, 1, 1, 1], [1.0, 0.55, 0.5, 0.5, 0.5]),
        ([8, 6, 4], [1.0, 0.75, 0.5]),
        ([], []),
    ],
)
def test_normalize_scores(scores, expected_out):
    """
    This test verifies normalize_scores with the default lower and upper bound values
    Given:
    - Input scores that need to be normalized to a standard range or distribution
    When:
    - Running the 'normalize_scores' function.
    Then:
    - Checks the function properly normalizes scores and returns correctly scaled results within expected bounds.
    """
    assert np.allclose(normalize_scores(scores), expected_out, atol=0.01)


@pytest.mark.parametrize(
    "scores,expected_out,lower_bound,upper_bound",
    [
        ([], [], -1, 1),
        ([], [], 1, -1),
        ([], [], 1, 0),
    ],
)
def test_normalize_scores_different_bounds(scores, expected_out, lower_bound, upper_bound):
    """
    This test verifies that if invalid bounds are provided, a ValueError is thrown
    Given:
    - Input scores with different boundary values that need normalization to custom ranges
    When:
    - Running the 'normalize_scores' function with different bounds.
    Then:
    - Checks the function handles different boundary conditions and returns properly normalized scores within specified ranges.
    """
    with pytest.raises(ValueError):
        normalize_scores(scores, lower_bound, upper_bound)


def test_score_model_load_fail(mocker):
    """
    Test that we handle exceptions raised during model load
    Given:
    - A scoring model that fails to load due to missing file, corrupted data, or invalid format
    When:
    - Running the score model loading function.
    Then:
    - Checks the function handles model load failures gracefully and returns appropriate error handling or fallback behavior.
    """
    mocker.patch("RankRemediationOwners.load_pickled_xpanse_object", side_effect=Exception())
    with does_not_raise():
        score(system_ids=[], owners=[])


def test_score_model_inference_fail(mocker):
    """
    Test that we handle exceptions raised during model inference
    iven:
    - A loaded scoring model that fails during inference due to invalid input or model errors
    When:
    - Running the score model inference function.
    Then:
    - Checks the function handles inference failures gracefully and returns appropriate error handling or default scores.
    """
    model_mock = Mock()
    model_mock.predict.side_effect = Exception()
    # patch load function to return a model mock which raises an error during prediction
    mocker.patch("RankRemediationOwners.load_pickled_xpanse_object", return_value=model_mock)
    with does_not_raise():
        score(system_ids=[], owners=[])


@pytest.mark.parametrize(
    "owners, system_ids, expected_out",
    [
        # ideal input
        (
            [
                {"name": "aa", "email": "email1@gmail.com", "source": "source1", "timestamp": "1"},
                {"name": "a", "email": "email1@gmail.com", "source": "source1", "timestamp": "1"},
            ],
            [""],
            [
                {
                    "name": "aa",
                    "email": "email1@gmail.com",
                    "source": "source1",
                    "timestamp": "1",
                    "ranking_score": 1.0,
                    "justification": "source1",
                },
            ],
        ),
        # ideal input with Chain: (should be stripped)
        (
            [
                {"name": "a", "email": "email1@gmail.com", "source": "Chain: source1", "timestamp": "1"},
            ],
            [""],
            [
                {
                    "name": "a",
                    "email": "email1@gmail.com",
                    "source": "source1",
                    "timestamp": "1",
                    "ranking_score": 1.0,
                    "justification": "source1",
                },
            ],
        ),
        # empty input
        ([], [], []),
        # ideal input with new string field added
        (
            [
                {"name": "aa", "email": "email1@gmail.com", "source": "source1", "timestamp": "1", "New Field": "val1"},
                {"name": "a", "email": "email1@gmail.com", "source": "source1", "timestamp": "1", "New Field": "val2"},
            ],
            [""],
            [
                {
                    "name": "aa",
                    "email": "email1@gmail.com",
                    "source": "source1",
                    "timestamp": "1",
                    "ranking_score": 1,
                    "justification": "source1",
                    "New Field": "val1 | val2",
                },
            ],
        ),
        # ideal input with new numerical field added
        (
            [
                {"name": "aa", "email": "email1@gmail.com", "source": "source1", "timestamp": "1", "New Field": 1},
                {"name": "a", "email": "email1@gmail.com", "source": "source1", "timestamp": "1", "New Field": 2},
            ],
            [""],
            [
                {
                    "name": "aa",
                    "email": "email1@gmail.com",
                    "source": "source1",
                    "timestamp": "1",
                    "ranking_score": 1,
                    "justification": "source1",
                    "New Field": 2,
                },
            ],
        ),
        # ideal input with some new field values added
        (
            [
                {"name": "aa", "email": "email1@gmail.com", "source": "source1", "timestamp": "1", "New Field": 1},
                {"name": "a", "email": "email1@gmail.com", "source": "source1", "timestamp": "1"},
            ],
            [""],
            [
                {
                    "name": "aa",
                    "email": "email1@gmail.com",
                    "source": "source1",
                    "timestamp": "1",
                    "ranking_score": 1,
                    "justification": "source1",
                    "New Field": 1,
                },
            ],
        ),
        # ideal input with some new field values added
        (
            [
                {"name": "aa", "email": "email1@gmail.com", "source": "source1", "timestamp": "1", "New Field": "val1"},
                {"name": "a", "email": "email1@gmail.com", "source": "source1", "timestamp": "1"},
            ],
            [""],
            [
                {
                    "name": "aa",
                    "email": "email1@gmail.com",
                    "source": "source1",
                    "timestamp": "1",
                    "ranking_score": 1,
                    "justification": "source1",
                    "New Field": "val1",
                },
            ],
        ),
        # ideal input with some new field values added that we can't handle
        (
            [
                {"name": "aa", "email": "email1@gmail.com", "source": "source1", "timestamp": "1", "New Field": None},
                {"name": "a", "email": "email1@gmail.com", "source": "source1", "timestamp": "1"},
            ],
            [""],
            [
                {
                    "name": "aa",
                    "email": "email1@gmail.com",
                    "source": "source1",
                    "timestamp": "1",
                    "ranking_score": 1,
                    "justification": "source1",
                },
            ],
        ),
        # bad inputs -- None
        (None, None, []),
        # bad inputs -- None
        ([None], [None], []),
        # bad input -- name is None
        (
            [
                {"name": None, "email": "email1@gmail.com", "source": "source1", "timestamp": "1"},
            ],
            [""],
            [
                {
                    "name": "",
                    "email": "email1@gmail.com",
                    "source": "source1",
                    "timestamp": "1",
                    "ranking_score": 1,
                    "justification": "source1",
                },
            ],
        ),
        # bad input -- email is None
        (
            [
                {"name": "a", "email": None, "source": "source1", "timestamp": "1"},
            ],
            [""],
            [
                {
                    "name": "a",
                    "email": None,
                    "source": "source1",
                    "timestamp": "1",
                    "ranking_score": 1,
                    "justification": "source1",
                },
            ],
        ),
        # bad input -- source is None
        (
            [
                {"name": "a", "email": "email1@gmail.com", "source": None, "timestamp": "1"},
            ],
            [""],
            [
                {
                    "name": "a",
                    "email": "email1@gmail.com",
                    "source": "",
                    "timestamp": "1",
                    "ranking_score": 1,
                    "justification": "",
                },
            ],
        ),
        # bad input -- timestamp is None
        (
            [
                {"name": "a", "email": "email1@gmail.com", "source": "source1", "timestamp": None},
            ],
            [""],
            [
                {
                    "name": "a",
                    "email": "email1@gmail.com",
                    "source": "source1",
                    "timestamp": "",
                    "ranking_score": 1,
                    "justification": "source1",
                },
            ],
        ),
        # bad input -- missing name
        (
            [
                {"email": "email1@gmail.com", "source": "source1", "timestamp": "1"},
            ],
            [""],
            [
                {
                    "name": "",
                    "email": "email1@gmail.com",
                    "source": "source1",
                    "timestamp": "1",
                    "ranking_score": 1,
                    "justification": "source1",
                },
            ],
        ),
        # bad input -- missing email
        (
            [
                {"name": "a", "source": "source1", "timestamp": "1"},
            ],
            [""],
            [
                {"name": "a", "email": "", "source": "source1", "timestamp": "1", "ranking_score": 1, "justification": "source1"},
            ],
        ),
        # bad input -- missing source
        (
            [
                {"name": "a", "email": "email1@gmail.com", "timestamp": "1"},
            ],
            [""],
            [
                {
                    "name": "a",
                    "email": "email1@gmail.com",
                    "source": "",
                    "timestamp": "1",
                    "ranking_score": 1,
                    "justification": "",
                },
            ],
        ),
        # bad input -- missing timestamp
        (
            [
                {"name": "a", "email": "email1@gmail.com", "source": "source1"},
            ],
            [""],
            [
                {
                    "name": "a",
                    "email": "email1@gmail.com",
                    "source": "source1",
                    "timestamp": "",
                    "ranking_score": 1,
                    "justification": "source1",
                },
            ],
        ),
        # timestamp as numerical type
        (
            [
                {"name": "aa", "email": "email1@gmail.com", "source": "source1", "timestamp": 1},
                {"name": "a", "email": "email1@gmail.com", "source": "source1", "timestamp": 2},
            ],
            [""],
            [
                {
                    "name": "aa",
                    "email": "email1@gmail.com",
                    "source": "source1",
                    "timestamp": 2,
                    "ranking_score": 1.0,
                    "justification": "source1",
                },
            ],
        ),
        # single owner entry (xsoar converts to dictionary with filters)
        (
            {"name": "aa", "email": "email1@gmail.com", "source": "source1", "timestamp": 1},
            [""],
            [
                {
                    "name": "aa",
                    "email": "email1@gmail.com",
                    "source": "source1",
                    "timestamp": 1,
                    "ranking_score": 1.0,
                    "justification": "source1",
                },
            ],
        ),
    ],
)
def test_main(mocker, owners, system_ids, expected_out, capfd):
    """
    Test the main function with a variety of `owners` inputs

    We mock out the model object and mock its predict function to return a single
    score of 1.0, since all the above test cases only have one owner (after deduplication)
    Given:
    - Proper demisto context with incident data and remediation owner information
    When:
    - Running the 'main' function.
    Then:
    - Checks the function executes the complete remediation owner ranking workflow and returns successful completion.
    """
    # Construct payload
    arg_payload = {}
    arg_payload["owners"] = owners
    arg_payload["system_ids"] = system_ids
    mocker.patch.object(demisto, "args", return_value=arg_payload)

    model_mock = Mock()
    model_mock.predict.return_value = np.array([1.0])

    mocker.patch("RankRemediationOwners.load_pickled_xpanse_object", return_value=model_mock)

    # Execute main using a mock that we can inspect for `executeCommand`
    demisto_execution_mock = mocker.patch.object(demisto, "executeCommand")
    with capfd.disabled():  # avoids test failures on demisto.error statements
        main()

    # Verify the output value was set
    expected_calls_to_mock_object = [unittest.mock.call("setAlert", {"xdmremediationowners": expected_out})]
    if demisto_execution_mock.call_args_list:
        assert demisto_execution_mock.call_args_list == expected_calls_to_mock_object
    else:
        assert demisto_execution_mock.call_args_list == []


def test_main_error(mocker, capfd):
    """
    Test that if an unhandled exception is thrown in main (e.g. from score),
    the script will fail with SystemExit
    Given:
    - Invalid or missing demisto context data that causes errors in the main workflow
    When:
    - Running the 'main' function with error conditions.
    Then:
    - Checks the function handles errors gracefully and returns appropriate error messages or fallback behavior.
    """
    score_mock = mocker.patch("RankRemediationOwners.score")
    score_mock.side_effect = Exception()

    with capfd.disabled(), pytest.raises(SystemExit):  # avoids test failures on demisto.error statements
        main()


def test_get_k():
    """
    These cases are designed to specify the intuition we are trying to implement with the algorithm
    and verify its default hyperparameters.
    We assert that if the algorithm matches our intuition at least 80% of the time, it's probably fine.

    See function documentation for explanation of hyperparameters and their defaults.
    Given:
    - Input parameters for determining the k value in ranking or selection algorithms
    When:
    - Running the 'get_k' function.
    Then:
    - Checks the function calculates and returns the correct k value for the given input parameters.
    """

    # The first value in each case is the list of scores outputs by the model (one per owner)
    # and the second value is the expected k
    cases = [
        # If less than 12 in set of owners, return all or find obvious cutoff
        ([1], 1),
        ([1, 1], 2),
        ([1, 1, 1], 3),
        ([10, 1, 1], 3),
        ([1, 1, 1, 1], 4),
        ([10, 1, 1, 1], 4),
        ([10, 10, 1, 1], 4),  # For this input 2 or 4 is a good output
        ([10, 10, 1, 1], 2),  # For this input 2 or 4 is a good output
        ([1, 1, 1, 1, 1], 5),
        ([10, 1, 1, 1, 1], 5),
        ([10, 10, 1, 1, 1], 2),
        ([1, 1, 1, 1, 1, 1], 6),
        ([1, 1, 1, 1, 1, 1, 1], 7),
        # If larger set of owners, return top handful or find obvious cutoff
        ([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1], 5),
        ([10, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1], 5),
        ([10, 10, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1], 5),  # For this input 2 or 45 is a good output
        ([10, 10, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1], 2),  # For this input 2 or 45 is a good output
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


@pytest.mark.parametrize(
    "target_k, k_tol, a_tol, min_score_proportion, expected_raises",
    [
        (-1, 2, 1.0, 0.75, pytest.raises(ValueError, match="target_k must be non-negative")),
        (5, -1, 1.0, 0.75, pytest.raises(ValueError, match="k_tol must be non-negative")),
        (5, 2, -1, 0.75, pytest.raises(ValueError, match="a_tol must be non-negative")),
        (5, 2, 1.0, -1, pytest.raises(ValueError, match="min_score_proportion must be a value between 0 and 1")),
        (5, 2, 1.0, 1.1, pytest.raises(ValueError, match="min_score_proportion must be a value between 0 and 1")),
        (5, 2, 1.0, 0.75, does_not_raise()),
    ],
)
def test_get_k_bad_values(target_k, k_tol, a_tol, min_score_proportion, expected_raises):
    """
    Test that we raise ValueErrors on invalid parameters for get_k
    Given:
    - Invalid input parameters such as negative numbers, non-numeric values, or out-of-range values
    When:
    - Running the 'get_k' function with bad values.
    Then:
    - Checks the function handles invalid inputs gracefully and returns appropriate error handling or default values.
    """
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
    """
    Verify get_num_distinct_reasons
    Given:
    - A collection of reasons or justifications that may contain duplicates
    When:
    - Running the 'get_num_distinct_reasons' function.
    Then:
    - Checks the function correctly counts and returns the number of unique distinct reasons.
    """
    pipeline = OwnerFeaturizationPipeline()
    out = pipeline.get_num_reasons(
        {
            "name": "Amira",
            "email": "amira@example.com",
            "source": "GCP | Chain: GCP project owner of a service account attached to the VM \
            | Owner-In-Tags-From-PrismaCloud | Owner-In-Tags-From-GCP",
            "timestamp": "1",
        }
    )
    assert out == 4


def test_get_num_distinct_sources():
    """
    Verify get_num_distinct_sources
    Given:
    - A collection of data sources that may contain duplicates
    When:
    - Running the 'get_num_distinct_sources' function.
    Then:
    - Checks the function correctly counts and returns the number of unique distinct sources.
    """
    pipeline = OwnerFeaturizationPipeline()
    out = pipeline.get_num_distinct_sources(
        {
            "name": "Amira",
            "email": "amira@example.com",
            "source": "GCP | Chain: GCP project owner of a service account attached to the VM \
            | Owner-In-Tags-From-PrismaCloud | Owner-In-Tags-From-GCP",
            "timestamp": "1",
        }
    )
    assert out == 2


def test_get_min_path_length():
    """
    Verify get_min_path_length over a variey of path lengths
    Given:
    - Path data or graph structure with multiple possible routes between points
    When:
    - Running the 'get_min_path_length' function.
    Then:
    - Checks the function calculates and returns the minimum path length between specified points.
    """
    pipeline = OwnerFeaturizationPipeline()
    out = pipeline.get_min_path_length({"name": "Amira", "email": "amira@example.com", "source": "X", "timestamp": "1"})
    assert out == 1

    pipeline = OwnerFeaturizationPipeline()
    out = pipeline.get_min_path_length(
        {"name": "Amira", "email": "amira@example.com", "source": "Chain: Chain: Chain: Chain: X", "timestamp": "1"}
    )
    assert out == 5

    pipeline = OwnerFeaturizationPipeline()
    out = pipeline.get_min_path_length(
        {"name": "Amira", "email": "amira@example.com", "source": "X | Chain: Chain: Chain: Chain: Y", "timestamp": "1"}
    )
    assert out == 1


def test_get_name_similarity_person_asset():
    """
    Verify get_name_similarity_person_asset
    Given:
    - Person names and asset names that need similarity comparison
    When:
    - Running the 'get_name_similarity_person_asset' function.
    Then:
    - Checks the function calculates and returns accurate similarity scores between person and asset names.
    """
    owner = {"name": "Amira Muhammad", "email": "amuhammad@example.com", "source": "irrelevant", "timestamp": "1"}

    # has 1/1 matched
    pipeline = OwnerFeaturizationPipeline()
    out = pipeline.get_name_similarity_person_asset(["amira-instance"], owner)
    assert np.isclose(out, 1, rtol=0.01)

    # has 1/2 matched
    pipeline = OwnerFeaturizationPipeline()
    out = pipeline.get_name_similarity_person_asset(["amira-instance", "abc-123"], owner)
    assert out >= 1

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
    """
    Verify get_in_cmdb
    Given:
    - Asset or person data that needs to be checked against CMDB records
    When:
    - Running the 'get_in_cmdb' function.
    Then:
    - Checks the function determines if the entity exists in CMDB and returns correct boolean or existence status.
    """
    # CMDB attested
    pipeline = OwnerFeaturizationPipeline()
    out = pipeline.get_in_cmdb({"name": "Amira", "email": "amira@example.com", "source": "ABC-XYZ CMDB", "timestamp": "1"})
    assert out == 1

    # CMDB not attested
    pipeline = OwnerFeaturizationPipeline()
    out = pipeline.get_in_cmdb({"name": "Amira", "email": "amira@example.com", "source": "Some other source", "timestamp": "1"})
    assert out == 0


def test_get_in_logs():
    """
    Verify get_in_logs
    Given:
    - Entity data that needs to be checked against log records
    When:
    - Running the 'get_in_logs' function.
    Then:
    - Checks the function determines if the entity exists in logs and returns correct presence status.
    """
    # Splunk attested
    pipeline = OwnerFeaturizationPipeline()
    out = pipeline.get_in_logs({"name": "Amira", "email": "amira@example.com", "source": "Splunk", "timestamp": "1"})
    assert out == 1

    # arbitrary log attested
    pipeline = OwnerFeaturizationPipeline()
    out = pipeline.get_in_logs({"name": "Amira", "email": "amira@example.com", "source": "some LOG source", "timestamp": "1"})
    assert out == 1

    # logs not attested
    pipeline = OwnerFeaturizationPipeline()
    out = pipeline.get_in_logs({"name": "Amira", "email": "amira@example.com", "source": "Some other source", "timestamp": "1"})
    assert out == 0


def test_base_case():
    """
    Verifies the working case.
    Given:
    - Standard input data with typical expected values and normal operating conditions
    When:
    - Running the function with base case parameters.
    Then:
    - Checks the function processes standard input correctly and returns expected baseline results.
    """
    system_ids = ["afr-rdp-1", "j291mv-is"]

    owners = [
        {
            "name": "Amira",
            "email": "amira@example.com",
            "source": "GCP | \
            Chain: GCP project owner of a service account attached to the VM | \
                Owner-In-Tags-From-PrismaCloud | Owner-In-Tags-From-GCP",
            "timestamp": "1",
        },
        {
            "name": "Brandon",
            "email": "brandon@example.com",
            "source": "GCP | \
            Owner-In-Tags-From-GCP | Tenable.io | New-Log-Source",
            "timestamp": "2",
        },
        {"name": "Chun", "email": "chun@example.com", "source": "SNOW-CMDB", "timestamp": "3"},
        {
            "name": "Divya",
            "email": "divya@example.com",
            "source": "Chain: Chain: \VM launches with a service account, \
            which belongs to GCP project my-project that grants Editor permissions to svc-acct@my-project.gserviceaccount.com, \
                which this person can impersonate",
            "timestamp": "4",
        },
        {"name": "Automation First Remediation", "email": "afr@example.com", "source": "GCP | Splunk", "timestamp": "5"},
    ]

    observed_output = featurize(system_ids, owners)
    expected_output = np.array(
        [
            # Columns are:
            #  idx_name_similarity_person_asset = 0,
            #  idx_num_reasons = 1,
            #  idx_num_distinct_sources = 2,
            #  idx_min_path_length = 3,
            #  idx_is_attested_in_cmdb = 4,
            #  idx_is_attested_in_recent_logs = 5,
            [0.0, 4, 2, 1, 0, 0],
            [0.0, 4, 2, 1, 0, 1],
            [0.0, 1, 1, 1, 1, 0],
            [0.0, 1, 1, 3, 0, 0],
            [1.0, 2, 2, 1, 0, 1],
        ]
    )
    assert np.allclose(observed_output, expected_output)


def test_missing_data():
    """
    Should not fail if no system IDs or owners are provided
    Given:
    - Input data with missing fields, null values, or incomplete information
    When:
    - Running the function with missing data conditions.
    Then:
    - Checks the function handles missing data gracefully and returns appropriate default values or error handling.
    """
    observed_output = featurize([], [])
    assert np.array_equal(observed_output, np.empty(shape=(0, 6)))


def test_featurize_owner_error(mocker):
    """
    Verify that if an error is thrown while computing a feature that takes the owner
    as input, the feature value is set to 0
    Given:
    - Owner data that causes errors during feature extraction due to invalid format or missing fields
    When:
    - Running the 'featurize_owner' function with problematic data.
    Then:
    - Checks the function handles featurization errors gracefully and returns appropriate error handling or default features.
    """
    mocker.patch("RankRemediationOwners.OwnerFeaturizationPipeline.get_num_reasons", side_effect=Exception())

    # normally would expect 1 reason
    owners = [
        {"name": "Amira", "email": "amira@example.com", "source": "GCP ", "timestamp": "1"},
    ]
    system_ids = []

    idx_get_num_reasons = 1
    output = featurize(system_ids, owners)
    assert output[0][idx_get_num_reasons] == 0


def test_featurize_similarity_error(mocker):
    """
    Verify that if an error is thrown while computing a feature that depends on system_ids,
    the feature value is set to 0
    Given:
    - Similarity data that causes errors during feature extraction due to invalid comparisons or missing data
    When:
    - Running the 'featurize_similarity' function with problematic data.
    Then:
    - Checks the function handles similarity featurization errors gracefully and returns appropriate error
      handling or default similarity features.
    """
    mocker.patch("RankRemediationOwners.OwnerFeaturizationPipeline.get_name_similarity_person_asset", side_effect=Exception())

    owners = [
        {"name": "Amira", "email": "amira@example.com", "source": "GCP ", "timestamp": "1"},
    ]
    # normally would expect greater-than-zero-similarity
    system_ids = ["amira-test"]

    idx_name_similarity_person_asset = 0
    output = featurize(system_ids, owners)
    assert output[0][idx_name_similarity_person_asset] == 0


@pytest.mark.parametrize(
    "platform_tenant",
    [
        ("False"),
        ("True"),
    ],
)
def test_write_output_to_context_key(mocker, platform_tenant):
    """
    Test the write_output_to_context_key function
    Given:
    - Output data that needs to be written to a specific demisto context key
    When:
    - Running the 'write_output_to_context_key' function.
    Then:
    - Checks the function successfully writes data to the specified context key and updates demisto context appropriately.
    """
    final_owners = [
        {"name": "aa", "email": "email1@gmail.com", "source": "source1", "timestamp": "1"},
        {"name": "a", "email": "email1@gmail.com", "source": "source1", "timestamp": "1"},
    ]
    owner_related_field = "xdmremediationowners"

    mocker.patch.object(demisto, "executeCommand", return_value=[{"Type": 1}])
    args = {"final_owners": final_owners, "owner_related_field": owner_related_field, "platform_tenant": platform_tenant}
    demisto_execution_mock = mocker.patch.object(demisto, "executeCommand")
    write_output_to_context_key(**args)
    expected_non_platform = [
        {"name": "aa", "email": "email1@gmail.com", "source": "source1", "timestamp": "1"},
        {"name": "a", "email": "email1@gmail.com", "source": "source1", "timestamp": "1"},
    ]
    expected_platform = ["email1@gmail.com", "email1@gmail.com"]
    if platform_tenant == "True":
        expected_calls_to_mock_object = [unittest.mock.call("setIssue", {"xdmremediationowners": expected_platform})]
    else:
        expected_calls_to_mock_object = [unittest.mock.call("setAlert", {"xdmremediationowners": expected_non_platform})]
    assert demisto_execution_mock.call_args_list == expected_calls_to_mock_object
