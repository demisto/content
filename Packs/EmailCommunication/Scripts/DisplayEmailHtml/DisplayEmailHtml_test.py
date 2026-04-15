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


class TestSanitizeHtmlBody:
    """Tests for sanitize_html_body - validates safe HTML output encoding."""

    def test_sanitize_html_body_strips_disallowed_tags(self, mocker):
        """
        Given
        - An HTML body containing tags not in the allowlist
        When
        - sanitize_html_body is called with bleach available
        Then
        - Disallowed tags are removed from the output
        """
        import types
        import DisplayEmailHtml

        mock_bleach = types.ModuleType("bleach")

        def mock_clean(html, tags=None, strip=False):
            import re

            result = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=re.DOTALL | re.IGNORECASE)
            return result

        mock_bleach.clean = mock_clean
        mocker.patch.dict("sys.modules", {"bleach": mock_bleach})

        result = DisplayEmailHtml.sanitize_html_body('<p>Hello</p><script>alert("test")</script><b>World</b>')
        assert "<script>" not in result
        assert "Hello" in result
        assert "World" in result

    def test_sanitize_html_body_preserves_allowed_tags(self):
        """
        Given
        - An HTML body containing only allowed tags
        When
        - sanitize_html_body is called
        Then
        - All allowed tags are preserved in the output (with or without bleach)
        """
        from DisplayEmailHtml import sanitize_html_body

        html_input = "<p>Hello <b>World</b></p><br><div>Content</div>"
        result = sanitize_html_body(html_input)
        assert "Hello" in result
        assert "World" in result
        assert "Content" in result

    def test_sanitize_html_body_handles_empty_string(self):
        """
        Given
        - An empty HTML body
        When
        - sanitize_html_body is called
        Then
        - An empty string is returned
        """
        from DisplayEmailHtml import sanitize_html_body

        assert sanitize_html_body("") == ""

    def test_sanitize_html_body_fallback_passes_through_when_bleach_unavailable(self):
        """
        Given
        - An HTML body and bleach is not installed
        When
        - sanitize_html_body is called
        Then
        - The HTML is returned as-is since full escaping would break rendering
        """
        from DisplayEmailHtml import sanitize_html_body

        html_input = "<p>Test</p>"
        result = sanitize_html_body(html_input)
        # Without bleach, HTML passes through unchanged to avoid breaking rendering
        assert result == html_input


class TestSetEmailReplyHeaderEncoding:
    """Tests for set_email_reply - validates header field output encoding."""

    def test_set_email_reply_encodes_html_in_from_field(self):
        """
        Given
        - An email 'from' field containing HTML-like characters
        When
        - set_email_reply is called
        Then
        - The output contains encoded entities instead of raw angle brackets
        """
        from DisplayEmailHtml import set_email_reply

        result = set_email_reply(
            email_from="<user>test@example.com",
            email_to="recipient@example.com",
            email_cc="",
            email_subject="Test Subject",
            html_body="<p>Body</p>",
            attachments=None,
        )
        assert "&lt;user&gt;" in result
        assert "<user>" not in result

    def test_set_email_reply_encodes_html_in_to_field(self):
        """
        Given
        - An email 'to' field containing HTML-like characters
        When
        - set_email_reply is called
        Then
        - The output contains encoded entities instead of raw angle brackets
        """
        from DisplayEmailHtml import set_email_reply

        result = set_email_reply(
            email_from="sender@example.com",
            email_to="<admin>recipient@example.com",
            email_cc="",
            email_subject="Test Subject",
            html_body="<p>Body</p>",
            attachments=None,
        )
        assert "&lt;admin&gt;" in result

    def test_set_email_reply_encodes_html_in_cc_field(self):
        """
        Given
        - An email 'cc' field containing HTML-like characters
        When
        - set_email_reply is called
        Then
        - The output contains encoded entities instead of raw angle brackets
        """
        from DisplayEmailHtml import set_email_reply

        result = set_email_reply(
            email_from="sender@example.com",
            email_to="recipient@example.com",
            email_cc="<manager>cc@example.com",
            email_subject="Test Subject",
            html_body="<p>Body</p>",
            attachments=None,
        )
        assert "&lt;manager&gt;" in result

    def test_set_email_reply_encodes_html_in_subject_field(self):
        """
        Given
        - An email 'subject' field containing HTML-like characters
        When
        - set_email_reply is called
        Then
        - The output contains encoded entities instead of raw angle brackets
        """
        from DisplayEmailHtml import set_email_reply

        result = set_email_reply(
            email_from="sender@example.com",
            email_to="recipient@example.com",
            email_cc="",
            email_subject="<Important> Alert & Notice",
            html_body="<p>Body</p>",
            attachments=None,
        )
        assert "&lt;Important&gt;" in result
        assert "&amp;" in result

    def test_set_email_reply_encodes_attachment_names(self):
        """
        Given
        - Attachments with names containing HTML-like characters
        When
        - set_email_reply is called
        Then
        - The attachment names in the output are properly encoded
        """
        from DisplayEmailHtml import set_email_reply

        result = set_email_reply(
            email_from="sender@example.com",
            email_to="recipient@example.com",
            email_cc="",
            email_subject="Test Subject",
            html_body="<p>Body</p>",
            attachments=[{"name": "<file>.txt"}],
        )
        assert "&lt;file&gt;" in result

    def test_set_email_reply_handles_none_fields(self):
        """
        Given
        - None values for all header fields
        When
        - set_email_reply is called
        Then
        - No error is raised and the output is valid
        """
        from DisplayEmailHtml import set_email_reply

        result = set_email_reply(
            email_from=None,
            email_to=None,
            email_cc=None,
            email_subject=None,
            html_body=None,
            attachments=None,
        )
        assert "From:" in result
        assert "To:" in result


class TestCreateEmailHtmlRegexSafety:
    """Tests for create_email_html - validates safe regex pattern handling for attachment names."""

    def test_create_email_html_with_special_chars_in_attachment_name(self):
        """
        Given
        - An attachment name containing regex special characters (e.g., parentheses, dots)
        When
        - create_email_html is called
        Then
        - No regex error is raised and the function completes successfully
        """
        from DisplayEmailHtml import create_email_html

        html_input = '<img src="cid:test" alt="file(1).png">'
        entry_id_list = [("file(1).png", "42@100")]
        # Should not raise re.error
        result = create_email_html(html_input, entry_id_list)
        assert isinstance(result, str)

    def test_create_email_html_with_brackets_in_attachment_name(self):
        """
        Given
        - An attachment name containing square brackets
        When
        - create_email_html is called
        Then
        - No regex error is raised and the function completes successfully
        """
        from DisplayEmailHtml import create_email_html

        html_input = '<img src="cid:test" alt="file[1].png">'
        entry_id_list = [("file[1].png", "42@100")]
        result = create_email_html(html_input, entry_id_list)
        assert isinstance(result, str)

    def test_create_email_html_with_plus_in_attachment_name(self):
        """
        Given
        - An attachment name containing plus signs and other regex metacharacters
        When
        - create_email_html is called
        Then
        - No regex error is raised and the function completes successfully
        """
        from DisplayEmailHtml import create_email_html

        html_input = '<img src="cid:test" alt="file+name.png">'
        entry_id_list = [("file+name.png", "42@100")]
        result = create_email_html(html_input, entry_id_list)
        assert isinstance(result, str)
