import json

import demistomock as demisto
from NetskopeFileScanLabels import build_labels, main


def test_build_labels_extracts_expected_fields():
    """
    Given:
        - A scan result dict with jobid/status/verdict/md5/sha256.
    When:
        - Running build_labels.
    Then:
        - One label object is built per field, matching setIncident's addLabels shape.
    """
    result = {"jobid": "123", "status": "done", "verdict": "clean", "md5": "a" * 32, "sha256": "b" * 64}
    labels = build_labels(result)
    assert labels == [
        {"NetskopeFileScanJobID": "123"},
        {"NetskopeFileScanStatus": "done"},
        {"NetskopeFileScanVerdict": "clean"},
        {"NetskopeFileScanMD5": "a" * 32},
        {"NetskopeFileScanSHA256": "b" * 64},
    ]


def test_main_handles_scan_result_as_dict(mocker):
    """
    Given:
        - scan_result provided as a plain dict.
    When:
        - Running main.
    Then:
        - labels_json is built from it.
    """
    mocker.patch.object(demisto, "args", return_value={"scan_result": {"jobid": "123", "verdict": "clean"}})
    results_mock = mocker.patch.object(demisto, "results")

    main()

    outputs = results_mock.call_args[0][0]["EntryContext"]["NetskopeFileScanLabels"]
    labels = json.loads(outputs["labels_json"])
    assert {"NetskopeFileScanJobID": "123"} in labels


def test_main_handles_scan_result_as_single_element_list(mocker):
    """
    Given:
        - scan_result provided as a single-element list (XSOAR sometimes wraps context this way).
    When:
        - Running main.
    Then:
        - The dict inside the list is used, same as if it were passed directly.
    """
    mocker.patch.object(demisto, "args", return_value={"scan_result": [{"jobid": "123", "verdict": "clean"}]})
    results_mock = mocker.patch.object(demisto, "results")

    main()

    outputs = results_mock.call_args[0][0]["EntryContext"]["NetskopeFileScanLabels"]
    labels = json.loads(outputs["labels_json"])
    assert {"NetskopeFileScanJobID": "123"} in labels


def test_main_handles_empty_scan_result(mocker):
    """
    Given:
        - scan_result is an empty list.
    When:
        - Running main.
    Then:
        - No labels are built and a "nothing to record" summary is returned.
    """
    mocker.patch.object(demisto, "args", return_value={"scan_result": []})
    results_mock = mocker.patch.object(demisto, "results")

    main()

    outputs = results_mock.call_args[0][0]["EntryContext"]["NetskopeFileScanLabels"]
    assert outputs["labels_json"] == "[]"
    assert "No scan result" in outputs["summary"]
