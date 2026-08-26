import pytest

import demistomock as demisto
from CheckEmailAuthenticity import get_authentication_value, get_spf, main, normalize_headers

MOCK_HEADERS = [
    {"name": "Message-ID", "value": "test_message_id"},
    {
        "name": "received-spf",
        "value": "Pass (test.com: domain of test.com designates 8.8.8.8 as permitted sender)"
        "receiver=test.com; client-ip=8.8.8.8; helo=test.com;",
    },
    {
        "name": "Authentication-Results",
        "value": "spf=pass (sender IP is 8.8.8.8) smtp.mailfrom=test.com; dkim=fail (body hash did not verify) "
        "header.d=test.com; dmarc=pass action=none header.from=test.com;compauth=pass reason=100",
    },
]

MOCK_HEADERS_DIFFERENT_AUTH_HEADER = [
    {"name": "Message-ID", "value": "test_message_id"},
    {
        "name": "received-spf",
        "value": "Pass (test.com: domain of test.com designates 8.8.8.8 as permitted sender)"
        "receiver=test.com; client-ip=8.8.8.8; helo=test.com;",
    },
    {"name": "Authentication-Results", "value": "mock_different_value"},
]

EMAIL_KEY = (
    "Email(val.Headers.filter(function(header) { return header && header.name === 'Message-ID' && "
    "header.value === 'test_message_id';}))"
)


def test_check_email_auth(mocker):
    mocker.patch.object(demisto, "args", return_value={"headers": MOCK_HEADERS})
    mocker.patch.object(demisto, "results")

    main()

    results = demisto.results.call_args[0]

    # assert (str(results[0]['EntryContext'])) == '3'

    dmarc = results[0]["EntryContext"][f"{EMAIL_KEY}.DMARC"]
    assert dmarc["Validation-Result"] == "pass"
    assert dmarc["Signing-Domain"] == "test.com"

    spf = results[0]["EntryContext"][f"{EMAIL_KEY}.SPF"]
    assert spf["Validation-Result"] == "pass"
    assert spf["Sender-IP"] == "8.8.8.8"

    dkim = results[0]["EntryContext"][f"{EMAIL_KEY}.DKIM"]
    assert dkim["Validation-Result"] == "fail"
    assert dkim["Reason"] == "body hash did not verify"

    # AuthenticityCheck fails because DKIM failed
    assert results[0]["EntryContext"][f"{EMAIL_KEY}.AuthenticityCheck"] == "Fail"


def test_get_authentication_value():
    """
    Given:
        an authenticator header that is not a part of the given headers array.
    When:
        there is an intermediate server which changes the email and holds the original value of the header in a
        different header.
    Then:
        override the given authenticator headers in the headers array and use the original one.
    """

    original_authentication_header_included_in_headers = "Authentication-Results"
    original_authentication_header_not_included_in_headers = "Authentication-Results-Not-Included"

    assert (
        get_authentication_value(MOCK_HEADERS_DIFFERENT_AUTH_HEADER, original_authentication_header_not_included_in_headers)
        == "mock_different_value"
    )
    assert (
        get_authentication_value(MOCK_HEADERS, original_authentication_header_included_in_headers)
        == "spf=pass (sender IP is 8.8.8.8) smtp.mailfrom=test.com; dkim=fail (body hash did not verify) "
        "header.d=test.com; dmarc=pass action=none header.from=test.com;compauth=pass reason=100"
    )


def test_get_spf_formats():
    spf_with_parentheses = "Pass (test.com: domain of test.com designates 8.8.8.8 as permitted sender)"
    spf_without_parentheses = "Pass test.com: domain of test.com designates 8.8.8.8 as permitted sender"

    spf_data = get_spf(auth=None, spf=spf_with_parentheses)
    assert spf_data["Validation-Result"] == "pass"
    assert spf_data["Sender-IP"] == "8.8.8.8"

    spf_data = get_spf(auth=None, spf=spf_without_parentheses)
    assert spf_data["Validation-Result"] == "pass"
    assert spf_data["Sender-IP"] == "8.8.8.8"


# --- XSUP-73120: header container shape support -------------------------------
# `ParseEmailFilesV2` deprecated the legacy `Email.Headers` list in favour of the
# flat `Email.HeadersMap` object. The three fixtures below describe the *same*
# email in the three shapes the script can receive, mirroring the customer data
# attached to XSUP-73120 (spf=pass, dkim=pass, dmarc=pass -> "Pass").

AUTH_RESULTS_VALUE = (
    "spf=pass (sender IP is 8.8.8.8) smtp.mailfrom=test.com; dkim=pass (signature was verified) "
    "header.d=test.com; dmarc=pass action=none header.from=test.com;compauth=pass reason=100"
)
RECEIVED_SPF_VALUE = (
    "Pass (test.com: domain of test.com designates 8.8.8.8 as permitted sender)"
    "receiver=test.com; client-ip=8.8.8.8; helo=test.com;"
)
RECEIVED_VALUE = (
    "from mail.test.com (mail.test.com [8.8.8.8]) by mx.test.com with SMTP id abc123, Mon, 14 Jun 2026 21:46:58 +0000"
)

# Shape A - legacy list of {name, value} dicts (the EWS / O365 path).
HEADERS_AS_LIST = [
    {"name": "Message-ID", "value": "test_message_id"},
    {"name": "Received-SPF", "value": RECEIVED_SPF_VALUE},
    {"name": "Authentication-Results", "value": AUTH_RESULTS_VALUE},
]

# Shape B - flat HeadersMap object (the .eml / Microsoft Graph Mail path).
HEADERS_AS_MAP = {
    "Message-ID": "test_message_id",
    "Received-SPF": RECEIVED_SPF_VALUE,
    "Authentication-Results": AUTH_RESULTS_VALUE,
}

# Shape C - the raw header block as a single string.
HEADERS_AS_STRING = (
    f"Message-ID: test_message_id\r\n"
    f"Received-SPF: {RECEIVED_SPF_VALUE}\r\n"
    f"Authentication-Results: {AUTH_RESULTS_VALUE}\r\n"
)


def _run_main_and_get_context(mocker, headers, **extra_args):
    """Run the script's main() with the given headers and return its EntryContext."""
    args = {"headers": headers}
    args.update(extra_args)
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(demisto, "results")

    main()

    return demisto.results.call_args[0][0]["EntryContext"]


@pytest.mark.parametrize(
    "shape_name, headers",
    [
        ("legacy list", HEADERS_AS_LIST),
        ("HeadersMap dict", HEADERS_AS_MAP),
        ("raw header string", HEADERS_AS_STRING),
    ],
)
def test_authenticity_is_identical_for_every_header_shape(mocker, shape_name, headers):
    """
    Given:
        The same email, expressed as a legacy list, a HeadersMap object and a raw header string.
    When:
        Running the script on each shape.
    Then:
        All three produce the same "Pass" verdict, so the result does not depend on
        which integration delivered the email (XSUP-73120).
    """
    entry_context = _run_main_and_get_context(mocker, headers)

    assert entry_context[f"{EMAIL_KEY}.AuthenticityCheck"] == "Pass", f"unexpected verdict for {shape_name}"
    assert entry_context[f"{EMAIL_KEY}.SPF"]["Validation-Result"] == "pass"
    assert entry_context[f"{EMAIL_KEY}.DKIM"]["Validation-Result"] == "pass"
    assert entry_context[f"{EMAIL_KEY}.DMARC"]["Validation-Result"] == "pass"


def test_received_spf_is_read_from_a_headers_map():
    """
    Given:
        A HeadersMap holding a Received-SPF header but no Authentication-Results header.
    When:
        Normalizing the headers and evaluating SPF.
    Then:
        The SPF result is still resolved. This covers the second isinstance() filter in
        main(), which guards the Received-SPF lookup separately from the authentication one.
    """
    headers = normalize_headers({"Message-ID": "test_message_id", "Received-SPF": RECEIVED_SPF_VALUE})

    spf_value = next(header["value"] for header in headers if header["name"].lower() == "received-spf")
    spf_data = get_spf(auth=None, spf=spf_value)

    assert spf_data["Validation-Result"] == "pass"
    assert spf_data["Sender-IP"] == "8.8.8.8"


def test_message_id_survives_normalization_so_context_stays_keyed(mocker):
    """
    Given:
        Headers delivered as a HeadersMap.
    When:
        Running the script.
    Then:
        The outputs are still keyed by the Message-ID based DT expression, so results merge
        into the same Email context entry as on the legacy path.
    """
    entry_context = _run_main_and_get_context(mocker, HEADERS_AS_MAP)

    assert f"{EMAIL_KEY}.AuthenticityCheck" in entry_context


def test_original_authentication_header_override_works_on_a_headers_map():
    """
    Given:
        A HeadersMap where the original Authentication-Results value was moved to another header.
    When:
        Passing that header name as original_authentication_header.
    Then:
        The overriding header's value is used.
    """
    headers = normalize_headers(
        {
            "Message-ID": "test_message_id",
            "Authentication-Results": "mock_different_value",
            "X-Original-Authentication-Results": AUTH_RESULTS_VALUE,
        }
    )

    assert get_authentication_value(headers, "x-original-authentication-results") == AUTH_RESULTS_VALUE


class TestNormalizeHeaders:
    """Unit tests for the header container normalization helper."""

    def test_a_legacy_list_is_returned_unchanged(self):
        assert normalize_headers(HEADERS_AS_LIST) == HEADERS_AS_LIST

    def test_a_mapping_becomes_name_value_pairs(self):
        assert normalize_headers({"Subject": "hello"}) == [{"name": "Subject", "value": "hello"}]

    def test_a_multi_valued_key_expands_into_one_entry_per_value(self):
        """Repeated headers such as Received arrive as a list under a single key."""
        normalized = normalize_headers({"Received": ["hop one", "hop two"]})

        assert normalized == [
            {"name": "Received", "value": "hop one"},
            {"name": "Received", "value": "hop two"},
        ]

    def test_a_raw_header_block_is_parsed_into_pairs(self):
        normalized = normalize_headers("Subject: hello\r\nTo: user@test.com\r\n")

        assert normalized == [
            {"name": "Subject", "value": "hello"},
            {"name": "To", "value": "user@test.com"},
        ]

    def test_a_folded_header_value_is_unfolded(self):
        """RFC 5322 allows a long value to continue on an indented line."""
        normalized = normalize_headers("Subject: a very\r\n  long subject\r\n")

        assert len(normalized) == 1
        assert normalized[0]["name"] == "Subject"
        assert "a very" in normalized[0]["value"]
        assert "long subject" in normalized[0]["value"]

    def test_a_value_containing_commas_is_never_split(self):
        """argToList would comma-split this string and destroy the header."""
        normalized = normalize_headers(f"Received: {RECEIVED_VALUE}\r\n")

        assert normalized == [{"name": "Received", "value": RECEIVED_VALUE}]

    def test_a_comma_separated_list_of_header_lines_is_preserved(self):
        """A list of raw header lines is a shape argToList can produce."""
        normalized = normalize_headers(["Subject: hello", "To: user@test.com"])

        assert normalized == [
            {"name": "Subject", "value": "hello"},
            {"name": "To", "value": "user@test.com"},
        ]

    @pytest.mark.parametrize("empty_value", [None, "", [], {}])
    def test_empty_input_yields_an_empty_list(self, empty_value):
        assert normalize_headers(empty_value) == []


def test_missing_headers_still_report_no_information(mocker):
    """
    Given:
        No usable header information.
    When:
        Running the script.
    Then:
        The existing "undetermined" behaviour is preserved, so playbooks depending on it
        are unaffected by the normalization change.
    """
    mocker.patch.object(demisto, "args", return_value={"headers": []})
    mocker.patch.object(demisto, "results")

    with pytest.raises(SystemExit):
        main()

    results = demisto.results.call_args[0][0]
    assert "No header information was found." in results["HumanReadable"]
