import demistomock as demisto
import pytest

EMAIL_HTML = """
<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head><body><div dir="ltr">image 1:
<div><div><img src="cid:ii_kgjzy6yh0" alt="image_1.png" width="275" height="184"><br></div></div><div>image 2:
</div><div><div><img src="cid:ii_kgjzygxz1" alt="image_2.png" width="225" height="224"><br></div></div></div><br>
<div class="gmail_quote"><div dir="ltr" class="gmail_attr">On Thu, Oct 22, 2020 at 1:56 AM Avishai Brandeis &lt;
<a href="mailto:avishai@demistodev.onmicrosoft.com">avishai@demistodev.onmicrosoft.com</a>&gt; wrote:<br></div>
<blockquote class="gmail_quote" style="margin: 0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204)"><u></u><div>
<p>please add multiple inline images</p></div></blockquote></div></body></html>"""

EMAIL_HTML_NO_ALT = """
<html><head>

<meta http-equiv="Content-Type" content="text/html; charset=utf-8"><style type="text/css" style="display:none">

<!-

p

    {margin-top:0;

    margin-bottom:0}

->

</style></head>
<body dir="ltr"><div style="font-family:Calibri,Arial,Helvetica,sans-serif; font-size:12pt; color:rgb(0,0,0)">
<img size="178792" data-outlook-trace="F:1|T:1" src="cid:89593b98-b18d-46aa-ba4f-26773138c3f7" style="max-width:100%">
</div><div style="font-family:Calibri,Arial,Helvetica,sans-serif; font-size:12pt; color:rgb(0,0,0)">
<img size="8023" data-outlook-trace="F:1|T:1" src="cid:6a65eb70-7748-4bba-aaac-fe93235f63bd" style="max-width:100%">
</div></body></html>
"""  # noqa: RUF001

EXPECTED_RESULT_1 = """
<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head><body><div dir="ltr">image 1:
<div><div><img src=/entry/download/37@119 alt="image_1.png" width="275" height="184"><br></div></div><div>image 2:
</div><div><div><img src=/entry/download/38@120 alt="image_2.png" width="225" height="224"><br></div></div></div><br>
<div class="gmail_quote"><div dir="ltr" class="gmail_attr">On Thu, Oct 22, 2020 at 1:56 AM Avishai Brandeis &lt;
<a href="mailto:avishai@demistodev.onmicrosoft.com">avishai@demistodev.onmicrosoft.com</a>&gt; wrote:<br></div>
<blockquote class="gmail_quote" style="margin: 0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204)"><u></u><div>
<p>please add multiple inline images</p></div></blockquote></div></body></html>"""

EXPECTED_RESULT_2 = """
<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head><body><div dir="ltr">image 1:
<div><div><img src=acc_test_tenant/entry/download/37@119 alt="image_1.png" width="275" height="184"><br></div></div>\
<div>image 2:
</div><div><div><img src=acc_test_tenant/entry/download/38@120 alt="image_2.png" width="225" height="224"><br></div>\
</div></div><br>
<div class="gmail_quote"><div dir="ltr" class="gmail_attr">On Thu, Oct 22, 2020 at 1:56 AM Avishai Brandeis &lt;
<a href="mailto:avishai@demistodev.onmicrosoft.com">avishai@demistodev.onmicrosoft.com</a>&gt; wrote:<br></div>
<blockquote class="gmail_quote" style="margin: 0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204)"><u></u><div>
<p>please add multiple inline images</p></div></blockquote></div></body></html>"""

EXPECTED_RESULT_NO_ALT = """
<html><head>

<meta http-equiv="Content-Type" content="text/html; charset=utf-8"><style type="text/css" style="display:none">

<!-

p

    {margin-top:0;

    margin-bottom:0}

->

</style></head>
<body dir="ltr"><div style="font-family:Calibri,Arial,Helvetica,sans-serif; font-size:12pt; color:rgb(0,0,0)">
<img size="178792" data-outlook-trace="F:1|T:1" src=/entry/download/37@119 style="max-width:100%">
</div><div style="font-family:Calibri,Arial,Helvetica,sans-serif; font-size:12pt; color:rgb(0,0,0)">
<img size="8023" data-outlook-trace="F:1|T:1" src=/entry/download/38@120 style="max-width:100%">
</div></body></html>
"""  # noqa: RUF001

EXPECTED_RESULT_XSOAR_SAAS = """
<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head><body><div dir="ltr">image 1:
<div><div><img src=/xsoar/entry/download/37@119 alt="image_1.png" width="275" height="184"><br></div></div><div>image 2:
</div><div><div><img src="cid:ii_kgjzygxz1" alt="image_2.png" width="225" height="224"><br></div></div></div><br>
<div class="gmail_quote"><div dir="ltr" class="gmail_attr">On Thu, Oct 22, 2020 at 1:56 AM Avishai Brandeis &lt;
<a href="mailto:avishai@demistodev.onmicrosoft.com">avishai@demistodev.onmicrosoft.com</a>&gt; wrote:<br></div>
<blockquote class="gmail_quote" style="margin: 0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204)"><u></u><div>
<p>please add multiple inline images</p></div></blockquote></div></body></html>"""


@pytest.mark.parametrize(
    "email_html,entry_id_list,expected",
    [
        (EMAIL_HTML, [("image_1.png", "37@119"), ("image_2.png", "38@120")], EXPECTED_RESULT_1),
        (EMAIL_HTML_NO_ALT, [("image_1.png", "37@119"), ("image_2.png", "38@120")], EXPECTED_RESULT_NO_ALT),
    ],
)
def test_create_email_html(email_html, entry_id_list, expected):
    """
    Given
    - The email's Html representation
    When
    3. All images were uploaded to the server
    Then
    - The images' src attribute would be replaced as expected
    """
    from DisplayEmailHtml import create_email_html

    result = create_email_html(email_html, entry_id_list)
    assert result == expected


def test_create_email_html_saas(mocker):
    """
    Given
    - The email's Html representation on saas xsoar/xsiam machine.
    When
    - Creating the html thread
    Then
    - The images' src attribute would be replaced as expected with a prefix of xsoar.
    """

    from DisplayEmailHtml import create_email_html

    email_html = EMAIL_HTML
    entry_id_list = [("image_1.png", "37@119")]
    expected = EXPECTED_RESULT_XSOAR_SAAS
    mocker.patch("DisplayEmailHtml.is_xsiam_or_xsoar_saas", return_value=True)
    result = create_email_html(email_html, entry_id_list)
    assert result == expected


@pytest.mark.parametrize(
    "email_html,entry_id_list,expected", [(EMAIL_HTML, [("image_1.png", "37@119"), ("image_2.png", "38@120")], EXPECTED_RESULT_2)]
)
def test_create_email_html_mt(mocker, email_html, entry_id_list, expected):
    """
    Given
    - The email's Html representation with multi tenant environment
    When
    - All images were uploaded to the server
    Then
    - The images' src attribute would be replaced as expected with account tenant name
    """
    from DisplayEmailHtml import create_email_html

    mocker.patch.object(demisto, "demistoUrls", return_value={"server": "https://localhost:8443:/acc_test_tenant"})

    result = create_email_html(email_html, entry_id_list)
    assert result == expected


class TestSetEmailReplyXSSPrevention:
    """Tests for XSS prevention in set_email_reply header fields."""

    def test_xss_in_email_from(self):
        """Validate that XSS payload in email_from is escaped."""
        from DisplayEmailHtml import set_email_reply

        result = set_email_reply('<script>alert("from")</script>', "to@test.com", "cc@test.com", "Subject", "<p>body</p>", None)
        assert "&lt;script&gt;" in result
        assert '<script>alert("from")</script>' not in result

    def test_xss_in_email_to(self):
        """Validate that XSS payload in email_to is escaped."""
        from DisplayEmailHtml import set_email_reply

        result = set_email_reply(
            "from@test.com", '<img src=x onerror=alert("to")>', "cc@test.com", "Subject", "<p>body</p>", None
        )
        assert "&lt;img src=x onerror=alert(&quot;to&quot;)&gt;" in result
        # The raw unescaped tag must not appear
        assert "<img src=x onerror=" not in result

    def test_xss_in_email_cc(self):
        """Validate that XSS payload in email_cc is escaped."""
        from DisplayEmailHtml import set_email_reply

        result = set_email_reply("from@test.com", "to@test.com", '<iframe src="evil.com">', "Subject", "<p>body</p>", None)
        assert "&lt;iframe src=&quot;evil.com&quot;&gt;" in result
        assert "<iframe" not in result.split("<p>body</p>")[0]

    def test_xss_in_email_subject(self):
        """Validate that XSS payload in email_subject is escaped."""
        from DisplayEmailHtml import set_email_reply

        result = set_email_reply(
            "from@test.com", "to@test.com", "cc@test.com", "<img src=x onerror=alert(document.domain)>", "<p>body</p>", None
        )
        assert "&lt;img src=x onerror=alert(document.domain)&gt;" in result
        # The raw unescaped tag must not appear
        assert "<img src=x onerror=" not in result

    def test_xss_in_attachment_names(self):
        """Validate that XSS payload in attachment names is escaped."""
        from DisplayEmailHtml import set_email_reply

        attachments = [
            {"name": '<script>alert("attach1")</script>'},
            {"name": 'file"><img src=x onerror=alert(1)>.pdf'},
        ]
        result = set_email_reply("from@test.com", "to@test.com", "cc@test.com", "Subject", "<p>body</p>", attachments)
        assert "&lt;script&gt;" in result
        # The raw unescaped tags must not appear
        assert "<script>alert(" not in result
        assert "<img src=x onerror=" not in result

    def test_html_body_not_escaped(self):
        """Validate that the HTML body content is NOT escaped (intentional HTML rendering)."""
        from DisplayEmailHtml import set_email_reply

        html_body = '<table><tr><td style="color:red">Important</td></tr></table>'
        result = set_email_reply("from@test.com", "to@test.com", "cc@test.com", "Subject", html_body, None)
        # Body should appear as-is (or sanitized by nh3, but not html.escaped)
        assert "Important" in result

    def test_none_fields_render_as_empty(self):
        """Validate that None header fields render as empty strings."""
        from DisplayEmailHtml import set_email_reply

        result = set_email_reply(None, None, None, None, "<p>body</p>", None)
        assert "From: " in result
        assert "To: " in result
        assert "CC: " in result
        assert "Subject: " in result
        assert "None" not in result

    def test_ampersand_in_subject(self):
        """Validate that & character in subject is escaped to &amp;."""
        from DisplayEmailHtml import set_email_reply

        result = set_email_reply("from@test.com", "to@test.com", "", "Tom & Jerry <together>", "<p>body</p>", None)
        assert "Tom &amp; Jerry &lt;together&gt;" in result


class TestCreateEmailHtmlRegexEscape:
    """Tests for regex injection prevention in create_email_html."""

    def test_filename_with_regex_metacharacters(self):
        """Validate that filenames with regex metacharacters don't cause errors."""
        from DisplayEmailHtml import create_email_html

        malicious_name = "image(1)+[2].png"
        email_html = f'<img src="cid:test" alt="{malicious_name}" width="100">'
        entry_id_list = [(malicious_name, "42@100")]
        result = create_email_html(email_html, entry_id_list)
        assert "entry/download/42@100" in result

    def test_filename_with_dot_star(self):
        """Validate that .* in filename doesn't match everything."""
        from DisplayEmailHtml import create_email_html

        malicious_name = ".*"
        email_html = '<img src="cid:test" alt="safe.png" width="100"><img src="cid:other" alt=".*" width="50">'
        entry_id_list = [(malicious_name, "42@100")]
        result = create_email_html(email_html, entry_id_list)
        # Should only replace the exact match, not the safe.png
        assert 'alt="safe.png"' in result

    def test_filename_with_backslash(self):
        """Validate that backslashes in filename don't break regex."""
        from DisplayEmailHtml import create_email_html

        malicious_name = r"file\name.png"
        email_html = f'<img src="cid:test" alt="{malicious_name}" width="100">'
        entry_id_list = [(malicious_name, "42@100")]
        # Should not raise re.error
        result = create_email_html(email_html, entry_id_list)
        assert isinstance(result, str)


class TestSanitizeHtmlBody:
    """Tests for HTML body sanitization.

    These tests require nh3 to be installed. When nh3 is not available
    (e.g. Docker image not yet updated), tests are skipped with a clear message.
    """

    def test_strips_script_tags(self):
        """Validate that script tags are removed."""
        pytest.importorskip("nh3", reason="nh3 not installed in Docker image")
        from DisplayEmailHtml import sanitize_html_body

        result = sanitize_html_body('<p>Hello</p><script>alert("xss")</script><p>World</p>')
        assert "<script>" not in result
        assert "Hello" in result
        assert "World" in result

    def test_strips_onerror_attribute(self):
        """Validate that onerror attribute is removed."""
        pytest.importorskip("nh3", reason="nh3 not installed in Docker image")
        from DisplayEmailHtml import sanitize_html_body

        result = sanitize_html_body('<img src="x" onerror="alert(1)">')
        assert "onerror" not in result

    def test_strips_iframe(self):
        """Validate that iframe tags are removed."""
        pytest.importorskip("nh3", reason="nh3 not installed in Docker image")
        from DisplayEmailHtml import sanitize_html_body

        result = sanitize_html_body('<p>Safe</p><iframe src="evil.com"></iframe>')
        assert "<iframe" not in result
        assert "Safe" in result

    def test_preserves_safe_formatting(self):
        """Validate that safe HTML tags are preserved."""
        pytest.importorskip("nh3", reason="nh3 not installed in Docker image")
        from DisplayEmailHtml import sanitize_html_body

        safe_html = "<p>Hello <b>World</b></p><table><tr><td>Cell</td></tr></table><ul><li>Item</li></ul>"
        result = sanitize_html_body(safe_html)
        assert "<p>" in result
        assert "<b>" in result
        assert "<table>" in result
        assert "<li>" in result

    def test_empty_input(self):
        """Validate that empty input returns empty string."""
        from DisplayEmailHtml import sanitize_html_body

        assert sanitize_html_body("") == ""

    def test_strips_onclick(self):
        """Validate that onclick event handler is removed."""
        pytest.importorskip("nh3", reason="nh3 not installed in Docker image")
        from DisplayEmailHtml import sanitize_html_body

        result = sanitize_html_body('<div onclick="alert(1)">Click me</div>')
        assert "onclick" not in result
        assert "Click me" in result

    def test_strips_object_embed(self):
        """Validate that object and embed tags are removed."""
        pytest.importorskip("nh3", reason="nh3 not installed in Docker image")
        from DisplayEmailHtml import sanitize_html_body

        result = sanitize_html_body('<object data="evil.swf"></object><embed src="evil.swf">')
        assert "<object" not in result
        assert "<embed" not in result

    def test_fallback_when_nh3_unavailable(self, mocker):
        """Validate graceful fallback when nh3 is not available."""
        from DisplayEmailHtml import sanitize_html_body

        mocker.patch.dict("sys.modules", {"nh3": None})
        malicious_html = "<script>alert(1)</script>"
        # When nh3 is not available, HTML is returned as-is
        result = sanitize_html_body(malicious_html)
        assert result == malicious_html
