import json

import demistomock as demisto
from NetskopeURLLookupLabels import build_labels, main


def test_build_labels_joins_nested_name_arrays():
    """
    Given:
        - A lookup result with nested categories and url_lists arrays of {name} objects.
    When:
        - Running build_labels.
    Then:
        - Each array's names are joined into a single comma-separated label value.
    """
    result = {
        "url": "evil.com",
        "site": "evil.com",
        "app": "Unknown",
        "categories": [{"name": "Malware"}, {"name": "Phishing"}],
        "resolved_ip": "1.2.3.4",
        "dynamic_classification": True,
        "url_lists": [{"name": "blocklist1"}, {"name": "blocklist2"}],
    }
    labels = build_labels(result)
    assert {"NetskopeURLLookupCategories": "Malware,Phishing"} in labels
    assert {"NetskopeURLLookupCustomLists": "blocklist1,blocklist2"} in labels
    assert {"NetskopeURLLookupURL": "evil.com"} in labels


def test_build_labels_handles_missing_nested_arrays():
    """
    Given:
        - A lookup result with no categories or url_lists.
    When:
        - Running build_labels.
    Then:
        - The corresponding labels are empty strings, not an error.
    """
    labels = build_labels({"url": "evil.com"})
    assert {"NetskopeURLLookupCategories": ""} in labels
    assert {"NetskopeURLLookupCustomLists": ""} in labels


def test_main_handles_lookup_result_as_dict(mocker):
    """
    Given:
        - lookup_result provided as a single dict (XSOAR can unwrap a one-item list this way).
    When:
        - Running main.
    Then:
        - labels_json is built from it, same as if it were a one-element list.
    """
    mocker.patch.object(demisto, "args", return_value={"lookup_result": {"url": "evil.com"}})
    results_mock = mocker.patch.object(demisto, "results")

    main()

    outputs = results_mock.call_args[0][0]["EntryContext"]["NetskopeURLLookupLabels"]
    labels = json.loads(outputs["labels_json"])
    assert {"NetskopeURLLookupURL": "evil.com"} in labels


def test_main_handles_list_result_uses_first_entry(mocker):
    """
    Given:
        - lookup_result provided as a list (the normal Netskope.URLLookup shape).
    When:
        - Running main.
    Then:
        - The first (only) result is used to build labels.
    """
    mocker.patch.object(demisto, "args", return_value={"lookup_result": [{"url": "evil.com"}]})
    results_mock = mocker.patch.object(demisto, "results")

    main()

    outputs = results_mock.call_args[0][0]["EntryContext"]["NetskopeURLLookupLabels"]
    assert outputs["summary"] == 'Recorded Netskope URL Lookup labels on the incident for "evil.com".'


def test_main_handles_empty_result(mocker):
    """
    Given:
        - lookup_result is an empty list.
    When:
        - Running main.
    Then:
        - No labels are built and a "nothing to record" summary is returned.
    """
    mocker.patch.object(demisto, "args", return_value={"lookup_result": []})
    results_mock = mocker.patch.object(demisto, "results")

    main()

    outputs = results_mock.call_args[0][0]["EntryContext"]["NetskopeURLLookupLabels"]
    assert outputs["labels_json"] == "[]"
    assert "No URL Lookup result" in outputs["summary"]
