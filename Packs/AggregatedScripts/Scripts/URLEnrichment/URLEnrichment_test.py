import json
import pytest
import demistomock as demisto
from URLEnrichment import url_enrichment_script, normalize_urls, _is_cidr


def util_load_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# =================================================================================================
# == Tests for _is_cidr
# =================================================================================================


@pytest.mark.parametrize(
    "value, expected",
    [
        # IPv4 CIDRs
        ("1.1.1.0/24", True),
        ("10.0.0.0/8", True),
        ("192.168.1.0/32", True),
        ("0.0.0.0/0", True),
        # IPv6 CIDRs
        ("::1/128", True),
        ("2001:db8::/32", True),
        # Not CIDRs
        ("example.com/path", False),
        ("example.com/24", False),
        ("www.example.com/page", False),
        ("not-a-cidr", False),
        ("1.1.1.1", False),
        ("", False),
        # Edge cases
        ("1.1.1.0/200", False),  # mask > 128
        ("abc/24", False),  # left side not IP-like
    ],
)
def test_is_cidr(value: str, expected: bool):
    """
    Given:
        - Various string inputs that may or may not be CIDR notation.
    When:
        - _is_cidr is called.
    Then:
        - Returns True for valid CIDR-like patterns, False otherwise.
    """
    assert _is_cidr(value) == expected


# =================================================================================================
# == Tests for normalize_urls
# =================================================================================================


class TestNormalizeUrls:
    """Tests for the normalize_urls function."""

    def test_urls_with_scheme_unchanged(self):
        """
        Given:
            - URLs that already have a scheme (http://, https://, ftp://, hxxp://, hxxps://).
        When:
            - normalize_urls is called.
        Then:
            - URLs are returned unchanged.
        """
        urls = [
            "https://example.com",
            "http://example.com/path",
            "ftp://files.example.com",
            "hxxp://malicious.com",
            "hxxps://defanged.com/page",
        ]
        result = normalize_urls(urls)
        assert result == urls

    def test_www_prefix_gets_scheme(self):
        """
        Given:
            - URLs starting with 'www.' without a scheme.
        When:
            - normalize_urls is called.
        Then:
            - 'https://' is prepended.
        """
        result = normalize_urls(["www.example.com", "www.example.com/path"])
        assert result == ["https://www.example.com", "https://www.example.com/path"]

    def test_ftp_prefix_gets_scheme(self):
        """
        Given:
            - URLs starting with 'ftp.' without a scheme.
        When:
            - normalize_urls is called.
        Then:
            - 'https://' is prepended.
        """
        result = normalize_urls(["ftp.example.com"])
        assert result == ["https://ftp.example.com"]

    def test_defanged_prefixes_left_as_is(self):
        """
        Given:
            - Defanged URLs with 'www[.]' or 'ftp[.]' prefixes.
        When:
            - normalize_urls is called.
        Then:
            - They are NOT prepended with https:// (would create malformed URLs).
        """
        defanged = ["www[.]example[.]com", "ftp[.]files[.]example[.]com"]
        result = normalize_urls(defanged)
        assert result == defanged

    def test_domain_with_path_gets_scheme(self):
        """
        Given:
            - A domain with a path separator (e.g., 'example.com/path').
        When:
            - normalize_urls is called.
        Then:
            - 'https://' is prepended since the path indicates URL intent.
        """
        result = normalize_urls(["example.com/path/to/page"])
        assert result == ["https://example.com/path/to/page"]

    def test_cidr_notation_left_as_is(self):
        """
        Given:
            - CIDR notation strings (e.g., '1.1.1.0/24', '10.0.0.0/8').
        When:
            - normalize_urls is called.
        Then:
            - They are NOT prepended with https:// (they are not URLs).
        """
        cidrs = ["1.1.1.0/24", "10.0.0.0/8", "192.168.0.0/16"]
        result = normalize_urls(cidrs)
        assert result == cidrs

    def test_bare_domains_left_as_is(self):
        """
        Given:
            - Bare domain names without scheme, prefix, or path.
        When:
            - normalize_urls is called.
        Then:
            - They are returned unchanged (extractIndicators will classify them as domains).
        """
        domains = ["example.com", "openclaw.ai", "google.com"]
        result = normalize_urls(domains)
        assert result == domains

    def test_empty_and_whitespace_filtered(self):
        """
        Given:
            - A list containing empty strings and whitespace-only entries.
        When:
            - normalize_urls is called.
        Then:
            - Empty/whitespace entries are filtered out.
        """
        result = normalize_urls(["", "  ", "https://example.com", "  "])
        assert result == ["https://example.com"]

    def test_whitespace_stripped(self):
        """
        Given:
            - URLs with leading/trailing whitespace.
        When:
            - normalize_urls is called.
        Then:
            - Whitespace is stripped before processing.
        """
        result = normalize_urls(["  https://example.com  ", "  www.example.com  "])
        assert result == ["https://example.com", "https://www.example.com"]

    def test_case_insensitive_scheme_detection(self):
        """
        Given:
            - URLs with uppercase scheme prefixes.
        When:
            - normalize_urls is called.
        Then:
            - They are recognized as having a scheme and left unchanged.
        """
        result = normalize_urls(["HTTPS://EXAMPLE.COM", "HTTP://example.com"])
        assert result == ["HTTPS://EXAMPLE.COM", "HTTP://example.com"]

    def test_mixed_inputs(self):
        """
        Given:
            - A mix of URLs with schemes, www prefixes, paths, CIDRs, bare domains, and defanged.
        When:
            - normalize_urls is called.
        Then:
            - Each input is handled correctly according to its type.
        """
        inputs = [
            "https://already-has-scheme.com",
            "www.needs-scheme.com",
            "example.com/has/path",
            "1.1.1.0/24",
            "bare-domain.com",
            "www[.]defanged[.]com",
        ]
        expected = [
            "https://already-has-scheme.com",
            "https://www.needs-scheme.com",
            "https://example.com/has/path",
            "1.1.1.0/24",
            "bare-domain.com",
            "www[.]defanged[.]com",
        ]
        result = normalize_urls(inputs)
        assert result == expected


# =================================================================================================
# == End-to-end test
# =================================================================================================


def test_url_enrichment_script_end_to_end_with_files(mocker):
    """
    Given:
        - Input is Two URLs: https://example.com, https://example2.com.
        - TIM results from test_data/mock_tim_results.json.
        - Batch results from test_data/mock_batch_results.json (only create + enrichIndicators).
    When:
        - url_enrichment_script runs end-to-end (external_enrichment=True).
    Then:
        - URLEnrichment contains both URLs.
        - For https://example.com:
            * Results has 3 entries (TIM + brand1 + brand2).
              - TIM is summarized via top-level TIMScore/Status/ModifiedTime.
              - TIM row in Results has NO Status/ModifiedTime (they're popped).
            * MaxScore=3, MaxVerdict=Malicious, TIMScore=3.
            * Vendor rows include All standard output fields.
            * Top-level Status == "Manual" (due to manuallyEditedFields.Score).
        - For https://example2.com:
            * Results has 2 entries (TIM + brand3), and brand3 Reliability is Low.
    """
    # ---------- Load fixtures ----------
    tim_pages = util_load_json("test_data/mock_tim_results.json")["pages"]
    batch_blob = util_load_json("test_data/mock_batch_results.json")

    url_list = ["https://example.com", "https://example2.com"]

    # demisto.args() passthrough (used by ctor)
    mocker.patch.object(demisto, "args", return_value={"url_list": ",".join(url_list)})

    # ---------- Mock execute_command ONLY for extractIndicators ----------
    def extractIndicators_side_effect(cmd, args=None, extract_contents=False, fail_on_error=True):
        if cmd == "extractIndicators":
            return [{"EntryContext": {"ExtractedIndicators": {"URL": url_list}}}]
        return []

    mocker.patch("AggregatedCommandApiModule.execute_command", side_effect=extractIndicators_side_effect)

    # ---------- TIM search via IndicatorsSearcher ----------
    class _MockSearcher:
        def __init__(self, pages):
            self.pages = pages

        def __iter__(self):
            return iter(self.pages)

    mocker.patch("AggregatedCommandApiModule.IndicatorsSearcher", return_value=_MockSearcher(tim_pages))

    # ---------- Enabled modules/brands (BrandManager) ----------
    mocker.patch.object(
        demisto,
        "getModules",
        return_value={
            "m1": {"state": "active", "brand": "brand1"},
            "m2": {"state": "active", "brand": "brand2"},
            # brand3 not enabled; still appears via TIM context (not enrichIndicators)
        },
    )

    # ---------- Mock BatchExecutor.execute_list_of_batches using JSON ----------
    def _fake_execute_list_of_batches(self, list_of_batches, brands_to_run=None, verbose=False):
        out = []

        # Batch 0: CreateNewIndicatorsOnly -> one command in the script
        batch0_cmds = list_of_batches[0]
        batch0_results = []
        create_items = list(batch_blob.get("createNewIndicator", []))
        for _ in batch0_cmds:
            item = create_items[0] if create_items else {"Type": 1, "EntryContext": {}}
            batch0_results.append([(item, "", "")])
        out.append(batch0_results)

        # Batch 1: enrichIndicators only (single command with 2 entries for 2 URLs)
        enrich_items = list(batch_blob.get("enrichIndicators", []))
        batch1_cmds = list_of_batches[1]
        batch1_results = []
        for cmd in batch1_cmds:
            assert cmd.name == "enrichIndicators"
            items = enrich_items if enrich_items else [{"Type": 1, "EntryContext": {}}]
            batch1_results.append([(e, "", "") for e in items])
        out.append(batch1_results)

        return out

    mocker.patch("AggregatedCommandApiModule.BatchExecutor.execute_list_of_batches", _fake_execute_list_of_batches)

    # ---------- Act ----------
    command_results = url_enrichment_script(
        url_list=url_list,
        external_enrichment=True,
        verbose=True,
        enrichment_brands=["brand1", "brand2"],
        additional_fields=False,
    )
    outputs = command_results.outputs

    # ---------- Assert: URLEnrichment indicators ----------
    enrichment_key = "URLEnrichment(val.Value && val.Value == obj.Value)"
    enrichment_list = outputs.get(enrichment_key, [])
    enrichment_map = {item["Value"]: item for item in enrichment_list}
    assert set(enrichment_map.keys()) == set(url_list)

    # https://example.com should have TIM + brand1 + brand2
    ex1 = enrichment_map["https://example.com"]
    brands_present_ex1 = {r.get("Brand") for r in ex1["Results"]}
    assert brands_present_ex1 == {"TIM", "brand1", "brand2"}
    assert len(ex1["Results"]) == 3

    # vendor rows with reliability
    b1 = next(r for r in ex1["Results"] if r["Brand"] == "brand1")
    assert b1["Score"] == 2
    assert b1["PositiveDetections"] == 5
    assert b1.get("Reliability") == "High"

    b2 = next(r for r in ex1["Results"] if r["Brand"] == "brand2")
    assert b2["Score"] == 3
    assert b2["PositiveDetections"] == 37
    assert b2.get("Reliability") == "Medium"

    # TIM row present but without Status/ModifiedTime (popped to top-level)
    tim_row_ex1 = next(r for r in ex1["Results"] if r["Brand"] == "TIM")
    assert "Status" not in tim_row_ex1
    assert "ModifiedTime" not in tim_row_ex1

    # Max fields + TIMScore + top-level Status/ModifiedTime
    assert ex1["MaxScore"] == 3
    assert ex1["MaxVerdict"] == "Malicious"
    assert ex1["TIMScore"] == 3
    assert ex1.get("Status") == "Manual"
    assert ex1.get("ModifiedTime") == "2025-09-01T00:00:00Z"

    # https://example2.com should have TIM + brand3 (from TIM; brand3 not enabled)
    ex2 = enrichment_map["https://example2.com"]
    brands_present_ex2 = {r.get("Brand") for r in ex2["Results"]}
    assert brands_present_ex2 == {"TIM", "brand3"}
    b3 = next(r for r in ex2["Results"] if r["Brand"] == "brand3")
    assert b3["Score"] == 1
    assert b3.get("Reliability") == "Low"
