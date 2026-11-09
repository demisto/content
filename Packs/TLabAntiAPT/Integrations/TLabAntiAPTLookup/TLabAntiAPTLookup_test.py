"""Tests for the tLab Anti-APT Lookup integration."""

import json
from pathlib import Path

import pytest

import TLabAntiAPTLookup as lookup
from TLabAntiAPTApiModule import AUTH_SOURCE_KEY, TLabClient

BASE = "https://tlab.example.com"
DATA = Path(__file__).parent / "test_data"

SHA256 = "aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999"
SHA1 = "aaaabbbbccccddddeeeeffff0000111122223333"
MD5 = "aaaabbbbccccddddeeeeffff00001111"


def load(name: str):
    return json.loads((DATA / f"{name}.json").read_text())


@pytest.fixture
def client():
    return TLabClient(base_url=BASE, auth_mode=AUTH_SOURCE_KEY, credentials={"password": "key"}, verify=False)


@pytest.fixture
def params():
    return {"reliability": "B - Usually reliable", "lookup_limit": 1}


# ------------------------------------------------------------------ reputation


def test_file_reputation_by_sha256(client, params, requests_mock):
    requests_mock.get(f"{BASE}/sample_reports", json=load("reports_by_sha256"))
    results = lookup.file_reputation_command(client, {"file": SHA256}, params)
    assert len(results) == 1
    assert results[0].outputs["Verdict"] == "MALWARE"
    assert results[0].indicator.dbot_score.score == 3
    assert results[0].indicator.dbot_score.reliability == "B - Usually reliable"


def test_file_reputation_by_sha1_uses_the_sha1_filter(client, params, requests_mock):
    requests_mock.get(f"{BASE}/sample_reports", json=load("reports_by_sha256"))
    lookup.file_reputation_command(client, {"file": SHA1}, params)
    assert requests_mock.last_request.qs["filehashsha1"] == [SHA1]


def test_md5_is_resolved_through_hash_search_not_the_report_filter(client, params, requests_mock):
    # fileHashMd5 exists as a filter but is not in the server's role allow-list,
    # so for a non-admin account it is dropped and the query matches everything.
    search = requests_mock.get(f"{BASE}/files/hash_search", json=load("hash_search_md5"))
    reports = requests_mock.get(f"{BASE}/sample_reports", json=load("reports_by_sha256"))

    results = lookup.file_reputation_command(client, {"file": MD5}, params)

    assert search.call_count == 1
    assert search.last_request.qs["hashtype"] == ["md5"]
    # The lookup then proceeds by sha256, which IS an allow-listed filter.
    assert reports.last_request.qs["filehashsha256"] == [SHA256]
    assert results[0].outputs["Verdict"] == "MALWARE"


def test_md5_with_no_match_reports_not_found(client, params, requests_mock):
    requests_mock.get(f"{BASE}/files/hash_search", json=[])
    results = lookup.file_reputation_command(client, {"file": MD5}, params)
    assert "No analysis found" in results[0].readable_output


def test_report_for_a_different_hash_is_discarded(client, params, requests_mock):
    # The server's hash filters are prefix matches OR'd against the archive
    # hash, so a report for another sample can come back. Trusting it would
    # give a confident verdict about the wrong file.
    requests_mock.get(f"{BASE}/sample_reports", json=load("reports_hash_mismatch"))
    results = lookup.file_reputation_command(client, {"file": SHA256}, params)
    assert "No analysis found" in results[0].readable_output
    assert results[0].outputs is None


def test_partial_hash_is_refused_rather_than_searched(client, params, requests_mock):
    # A prefix search would match unrelated samples and produce a confident
    # wrong answer, so short values are skipped with an explanation.
    matcher = requests_mock.get(f"{BASE}/sample_reports", json=load("reports_by_sha256"))
    results = lookup.file_reputation_command(client, {"file": "aaaabbbb"}, params)
    assert matcher.call_count == 0
    assert "Partial hashes are not looked up" in results[0].readable_output


def test_non_hex_input_is_refused(client, params, requests_mock):
    results = lookup.file_reputation_command(client, {"file": "not-a-hash-value"}, params)
    assert "expected a full MD5, SHA1 or SHA256" in results[0].readable_output


def test_unknown_file_scores_zero_not_good(client, params, requests_mock):
    # "We have no record" is a different statement from "this is benign".
    # Returning Good here would suppress other vendors' findings.
    requests_mock.get(f"{BASE}/sample_reports", json=load("reports_empty"))
    results = lookup.file_reputation_command(client, {"file": SHA256}, params)
    assert results[0].indicator.dbot_score.score == 0


def test_unknown_can_be_reported_as_benign_when_configured(client, params, requests_mock):
    requests_mock.get(f"{BASE}/sample_reports", json=load("reports_by_sha256"))
    payload = load("reports_by_sha256")
    payload["content"][0]["verdict"] = "UNKNOWN"
    payload["content"][0]["file"]["fileVerdict"] = "UNKNOWN"
    payload["content"][0]["sampleReportCompleteness"] = "PARTIALLY_COMPLETE"
    payload["content"][0]["sampleScoreExists"] = False
    requests_mock.get(f"{BASE}/sample_reports", json=payload)

    plain = lookup.file_reputation_command(client, {"file": SHA256}, params)
    assert plain[0].indicator.dbot_score.score == 0

    benign = lookup.file_reputation_command(client, {"file": SHA256}, {**params, "unknown_is_benign": True})
    assert benign[0].indicator.dbot_score.score == 1


def test_multiple_hashes_return_one_result_each(client, params, requests_mock):
    requests_mock.get(f"{BASE}/sample_reports", json=load("reports_by_sha256"))
    results = lookup.file_reputation_command(client, {"file": f"{SHA256},{SHA1}"}, params)
    assert len(results) == 2


def test_file_argument_is_required(client, params):
    with pytest.raises(Exception, match="file argument is required"):
        lookup.file_reputation_command(client, {}, params)


def test_both_raw_verdict_fields_are_preserved(client, params, requests_mock):
    requests_mock.get(f"{BASE}/sample_reports", json=load("reports_by_sha256"))
    results = lookup.file_reputation_command(client, {"file": SHA256}, params)
    assert results[0].outputs["ScoreLevel"] == "MALICIOUS"
    assert results[0].outputs["FileVerdict"] == "MALWARE"
    assert results[0].outputs["Verdict"] == "MALWARE"


def test_lookup_asks_for_the_newest_analysis_first(client, params, requests_mock):
    requests_mock.get(f"{BASE}/sample_reports", json=load("reports_by_sha256"))
    lookup.file_reputation_command(client, {"file": SHA256}, params)
    assert requests_mock.last_request.qs["sort"] == ["samplereportid,desc"]


# ----------------------------------------------------------------- scan result


def test_scan_result_returns_rows(client, params, requests_mock):
    requests_mock.get(f"{BASE}/sample_reports", json=load("reports_by_sha256"))
    results = lookup.scan_result_command(client, {"hash": SHA256}, params)
    assert results.outputs[0]["SampleReportId"] == 412839


def test_scan_result_reports_a_miss_without_failing(client, params, requests_mock):
    requests_mock.get(f"{BASE}/sample_reports", json=load("reports_empty"))
    results = lookup.scan_result_command(client, {"hash": SHA256}, params)
    assert results.outputs["Found"] is False


def test_scan_result_rejects_an_undeterminable_hash(client, params):
    with pytest.raises(Exception, match="Could not determine the hash type"):
        lookup.scan_result_command(client, {"hash": "abc"}, params)


# ------------------------------------------------------------------- file info


def test_file_info_reads_the_stored_verdict(client, params, requests_mock):
    # The verdict is read from FileDto. The /verdict routes are POST setters
    # guarded by @PreAuthorize, not readers.
    requests_mock.get(f"{BASE}/files/{SHA256}", json=load("file_dto"))
    results = lookup.file_info_command(client, {"sha256": SHA256}, params)
    assert results.outputs["FileVerdict"] == "MALWARE"
    # tlab-server's internal id is of no use in XSOAR: no command takes it.
    assert "FileId" not in results.outputs
    assert results.outputs_key_field == "HashSha256"


def test_unset_file_verdict_is_not_shown(client, params, requests_mock):
    # UNKNOWN is the default of a verdict nobody set; next to a MALWARE
    # analysis it would read as a contradiction.
    requests_mock.get(f"{BASE}/files/{SHA256}", json={**load("file_dto"), "fileVerdict": "UNKNOWN"})
    results = lookup.file_info_command(client, {"sha256": SHA256}, params)
    assert "FileVerdict" not in results.outputs


def test_file_info_requires_a_full_sha256(client, params):
    with pytest.raises(Exception, match="full 64-character"):
        lookup.file_info_command(client, {"sha256": "aaaa"}, params)


# ---------------------------------------------------------------- search reports


def test_search_reports_rejects_the_create_time_sort(client, params):
    # The server ignores this key silently and reorders by update_time DESC.
    with pytest.raises(Exception, match="createTime"):
        lookup.search_reports_command(client, {"sort": "createTime,asc"}, params)


def test_search_reports_warns_about_admin_only_filters(client, params, requests_mock):
    # With a lower role the server discards these without an error, so a narrow
    # query silently becomes "return everything".
    requests_mock.get(f"{BASE}/sample_reports", json=load("reports_by_sha256"))
    results = lookup.search_reports_command(client, {"file_verdict": "MALWARE", "root_only": "true"}, params)
    assert "admin or developer" in results.readable_output
    assert "fileVerdict" in results.readable_output
    assert "rootOnly" in results.readable_output


def test_search_reports_does_not_warn_for_role_safe_filters(client, params, requests_mock):
    requests_mock.get(f"{BASE}/sample_reports", json=load("reports_by_sha256"))
    results = lookup.search_reports_command(client, {"completeness": "COMPLETE", "tags": "phishing"}, params)
    assert "Warning" not in results.readable_output


def test_role_safe_and_admin_only_filter_sets_do_not_overlap():
    assert not (lookup.ROLE_SAFE_FILTERS & lookup.ADMIN_ONLY_FILTERS)


# ------------------------------------------------------------------ hash search


def test_hash_search_requires_three_characters(client):
    with pytest.raises(Exception, match="at least 3 characters"):
        lookup.hash_search_command(client, {"hash_type": "md5", "hash_part": "ab"})


def test_hash_search_rejects_an_unknown_type(client):
    with pytest.raises(Exception, match="hash_type must be"):
        lookup.hash_search_command(client, {"hash_type": "crc32", "hash_part": "abcd"})


def test_hash_search_returns_rows(client, requests_mock):
    requests_mock.get(f"{BASE}/files/hash_search", json=load("hash_search_md5"))
    results = lookup.hash_search_command(client, {"hash_type": "md5", "hash_part": "aaaa"})
    assert results.outputs[0]["HashValue"] == MD5
    assert all("FileId" not in row for row in results.outputs)


# -------------------------------------------------------------- indicator codes


def test_list_indicator_codes(client, requests_mock):
    requests_mock.get(f"{BASE}/report_indicators", json=load("indicator_codes"))
    results = lookup.list_indicator_codes_command(client, {})
    assert {r["Code"] for r in results.outputs} == {9, 6}


def test_list_indicator_codes_filtered_by_analysis_type(client, requests_mock):
    requests_mock.get(f"{BASE}/report_indicators", json=load("indicator_codes"))
    results = lookup.list_indicator_codes_command(client, {"analysis_type": "DYN_ANALYSIS"})
    assert [r["Code"] for r in results.outputs] == [6]


# ----------------------------------------------------------------- test-module


def test_test_module_reports_identity(client, requests_mock):
    requests_mock.get(f"{BASE}/auth/test", json={"userLogin": "svc", "userRole": "user"})
    assert lookup.test_module_command(client) == "ok"


# ------------------------------------------------------------ yml drift guard


def _yml():
    import yaml

    return yaml.safe_load((Path(__file__).parent / "TLabAntiAPTLookup.yml").read_text())


def _implemented_commands() -> set:
    import re

    source = (Path(__file__).parent / "TLabAntiAPTLookup.py").read_text()
    return set(re.findall(r'command == "([a-z0-9-]+)"', source))


def test_every_declared_command_is_implemented():
    declared = {c["name"] for c in _yml()["script"]["commands"]}
    assert not declared - _implemented_commands()


def test_every_implemented_command_is_declared():
    declared = {c["name"] for c in _yml()["script"]["commands"]}
    assert not _implemented_commands() - declared - {"test-module"}


def test_file_command_is_a_proper_reputation_command():
    command = next(c for c in _yml()["script"]["commands"] if c["name"] == "file")
    argument = next(a for a in command["arguments"] if a["name"] == "file")
    # Without default: true the command cannot be wired into XSOAR's generic
    # enrichment playbooks, which pass the indicator positionally.
    assert argument.get("default") is True
    assert argument.get("isArray") is True
    outputs = {o["contextPath"] for o in command["outputs"]}
    assert {"DBotScore.Score", "DBotScore.Reliability", "File.SHA256", "File.Malicious.Vendor"} <= outputs


def test_admin_only_filters_are_documented_as_such():
    # An operator with a lower role must be able to tell from the argument help
    # that the filter will be ignored.
    command = next(c for c in _yml()["script"]["commands"] if c["name"] == "tlab-search-reports")
    by_name = {a["name"]: a for a in command["arguments"]}
    for name in ("file_verdict", "score_level", "source_id", "root_only", "min_report_id"):
        assert "admin or developer" in by_name[name]["description"], name


def test_sort_argument_warns_about_create_time():
    command = next(c for c in _yml()["script"]["commands"] if c["name"] == "tlab-search-reports")
    sort_arg = next(a for a in command["arguments"] if a["name"] == "sort")
    assert "createTime" in sort_arg["description"]


def test_yml_pins_the_same_docker_image_as_the_api_module():
    import yaml

    module_path = Path(__file__).parents[3] / "ApiModules" / "Scripts" / "TLabAntiAPTApiModule" / "TLabAntiAPTApiModule.yml"
    module = yaml.safe_load(module_path.read_text())
    assert _yml()["script"]["dockerimage"] == module["dockerimage"]
