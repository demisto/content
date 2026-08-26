import demistomock as demisto
from NetskopeFileHashSync import build_query, extract_hashes, is_valid_hash, main


def test_is_valid_hash_accepts_md5():
    """
    Given:
        - A 32-character hex string.
    When:
        - Running is_valid_hash.
    Then:
        - It's recognized as a valid MD5.
    """
    assert is_valid_hash("a" * 32) is True


def test_is_valid_hash_accepts_sha256():
    """
    Given:
        - A 64-character hex string.
    When:
        - Running is_valid_hash.
    Then:
        - It's recognized as a valid SHA256.
    """
    assert is_valid_hash("a" * 64) is True


def test_is_valid_hash_rejects_wrong_length():
    """
    Given:
        - A hex string that's neither 32 nor 64 characters.
    When:
        - Running is_valid_hash.
    Then:
        - It's rejected.
    """
    assert is_valid_hash("a" * 10) is False


def test_is_valid_hash_rejects_none():
    """
    Given:
        - A None value.
    When:
        - Running is_valid_hash.
    Then:
        - It's rejected without raising.
    """
    assert is_valid_hash(None) is False


def test_extract_hashes_from_value():
    """
    Given:
        - An indicator whose primary value is a valid hash.
    When:
        - Running extract_hashes.
    Then:
        - The value is extracted.
    """
    assert extract_hashes({"value": "a" * 32}) == ["a" * 32]


def test_extract_hashes_from_custom_fields():
    """
    Given:
        - An indicator whose value isn't a hash, but its CustomFields carry md5/sha256.
    When:
        - Running extract_hashes.
    Then:
        - Both custom field hashes are extracted.
    """
    ioc = {"value": "not-a-hash", "CustomFields": {"md5": "a" * 32, "sha256": "b" * 64}}
    assert extract_hashes(ioc) == ["a" * 32, "b" * 64]


def test_build_query_includes_file_types_and_tags():
    """
    Given:
        - A list of tags.
    When:
        - Running build_query.
    Then:
        - The query includes the File/File MD5/File SHA-256 types and the tags filter.
    """
    query = build_query(["malware"])
    assert query == 'type:(File "File MD5" "File SHA-256") and tags:(malware)'


def test_main_computes_new_and_merged_hashes(mocker):
    """
    Given:
        - One indicator with an already-tracked hash, one with a genuinely new hash, and one
          without any valid hash.
    When:
        - Running main.
    Then:
        - new_hashes contains only the new one, and merged_hashes contains both, sorted.
    """
    existing_hash = "a" * 32
    new_hash = "b" * 32
    mocker.patch.object(demisto, "args", return_value={"existing_hashes": existing_hash})
    mocker.patch.object(
        demisto,
        "searchIndicators",
        return_value={
            "iocs": [
                {"value": existing_hash},
                {"value": new_hash},
                {"value": "not-a-hash", "CustomFields": {}},
            ]
        },
    )
    results_mock = mocker.patch.object(demisto, "results")

    main()

    outputs = results_mock.call_args[0][0]["EntryContext"]["NetskopeHashSync"]
    assert outputs["new_hashes"] == [new_hash]
    assert outputs["merged_hashes"] == sorted([existing_hash, new_hash])
    assert outputs["skipped_no_valid_hash"] == 1


def test_main_handles_none_iocs(mocker):
    """
    Given:
        - demisto.searchIndicators returns {"iocs": None} when nothing matches.
    When:
        - Running main.
    Then:
        - No exception is raised and merged_hashes falls back to just existing_hashes.
    """
    mocker.patch.object(demisto, "args", return_value={"existing_hashes": "a" * 32})
    mocker.patch.object(demisto, "searchIndicators", return_value={"iocs": None})
    results_mock = mocker.patch.object(demisto, "results")

    main()

    outputs = results_mock.call_args[0][0]["EntryContext"]["NetskopeHashSync"]
    assert outputs["new_hashes"] == []
    assert outputs["merged_hashes"] == ["a" * 32]
