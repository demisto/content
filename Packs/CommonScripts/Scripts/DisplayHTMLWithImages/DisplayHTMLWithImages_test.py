import demistomock as demisto
import pytest

EMAIL_HTML = """
<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head><body><div dir="ltr">image 1:
<div><div><img src="cid:ii_kgjzy6yh0" alt="image_1.png" width="275" height="184"><br></div></div><div>image 2:
</div><div><div><img src="cid:ii_kgjzygxz1" alt="image_2.png" width="225" height="224"><br></div></div></div><br>
<div class="gmail_quote"><div dir="ltr" class="gmail_attr">On Thu, Oct 22, 2020 at 1:56 AM Some Person &lt;
<a href="mailto:some.person@demistodev.onmicrosoft.com">some.person@demistodev.onmicrosoft.com</a>&gt; wrote:<br></div>
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
<img size="178792" data-outlook-trace="F:1|T:1" src="cid:ii_kgjzy6yh0" style="max-width:100%">
</div><div style="font-family:Calibri,Arial,Helvetica,sans-serif; font-size:12pt; color:rgb(0,0,0)">
<img size="8023" data-outlook-trace="F:1|T:1" src="cid:ii_kgjzygxz1" style="max-width:100%">
</div></body></html>
"""  # noqa: RUF001

EXPECTED_RESULT_1 = """
<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head><body><div dir="ltr">image 1:
<div><div><img src=/entry/download/37@119 alt="image_1.png" width="275" height="184"><br></div></div><div>image 2:
</div><div><div><img src=/entry/download/38@120 alt="image_2.png" width="225" height="224"><br></div></div></div><br>
<div class="gmail_quote"><div dir="ltr" class="gmail_attr">On Thu, Oct 22, 2020 at 1:56 AM Some Person &lt;
<a href="mailto:some.person@demistodev.onmicrosoft.com">some.person@demistodev.onmicrosoft.com</a>&gt; wrote:<br></div>
<blockquote class="gmail_quote" style="margin: 0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204)"><u></u><div>
<p>please add multiple inline images</p></div></blockquote></div></body></html>"""

EXPECTED_RESULT_2 = """
<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head><body><div dir="ltr">image 1:
<div><div><img src=acc_test_tenant/entry/download/37@119 alt="image_1.png" width="275" height="184"><br></div></div>\
<div>image 2:
</div><div><div><img src=acc_test_tenant/entry/download/38@120 alt="image_2.png" width="225" height="224"><br></div>\
</div></div><br>
<div class="gmail_quote"><div dir="ltr" class="gmail_attr">On Thu, Oct 22, 2020 at 1:56 AM Some Person &lt;
<a href="mailto:some.person@demistodev.onmicrosoft.com">some.person@demistodev.onmicrosoft.com</a>&gt; wrote:<br></div>
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
<img size="178792" data-outlook-trace="F:1|T:1" src=acc_test_tenant/entry/download/37@119 style="max-width:100%">
</div><div style="font-family:Calibri,Arial,Helvetica,sans-serif; font-size:12pt; color:rgb(0,0,0)">
<img size="8023" data-outlook-trace="F:1|T:1" src=acc_test_tenant/entry/download/38@120 style="max-width:100%">
</div></body></html>
"""  # noqa: RUF001


@pytest.mark.parametrize("email_html,expected", [(EMAIL_HTML, EXPECTED_RESULT_2), (EMAIL_HTML_NO_ALT, EXPECTED_RESULT_NO_ALT)])
def test_main_mt(mocker, email_html, expected):
    """
    Given
    - Html contained images src
    When
    - All images were uploaded to the server
    Then
    - The images' src attribute would be replaced as expected with account tenant name
    """
    import DisplayHTMLWithImages
    from DisplayHTMLWithImages import main

    mocked_incident = {
        "CustomFields": {"emailbody": email_html},
        "attachment": [{"name": "image_1.png"}, {"name": "image_2.png"}],
    }
    mocked_files = [{"Name": "image_1.png", "EntryID": "37@119"}, {"Name": "image_2.png", "EntryID": "38@120"}]

    mocker.patch.object(demisto, "demistoUrls", return_value={"server": "https://localhost:8443:/acc_test_tenant"})
    mocker.patch.object(demisto, "incident", return_value=mocked_incident)
    mocker.patch.object(demisto, "context", return_value={"File": mocked_files})
    mocker.patch.object(DisplayHTMLWithImages, "return_results")

    main()

    assert expected in DisplayHTMLWithImages.return_results.call_args[0][0]["Contents"]


@pytest.mark.parametrize("email_html,expected", [(EMAIL_HTML, EXPECTED_RESULT_2), (EMAIL_HTML_NO_ALT, EXPECTED_RESULT_NO_ALT)])
def test_imgaes_not_attached_to_incident(mocker, email_html, expected):
    """
    Given
    - Html contained images src but not attached to incident.
    When
    - All images were uploaded to the server
    Then
    - The images' src attribute would be replaced as expected with account tenant name
    """
    import DisplayHTMLWithImages
    from DisplayHTMLWithImages import main

    mocked_incident = {"CustomFields": {"emailbody": email_html}, "attachment": []}
    mocked_files = [{"Name": "image_1.png", "EntryID": "37@119"}, {"Name": "image_2.png", "EntryID": "38@120"}]

    mocked_context = {
        "Email": {
            "AttachmentsData": [
                {
                    "Content-Disposition": 'attachment; filename="image_1.png"',
                    "Content-ID": "<ii_kgjzy6yh0>",
                    "Name": "image_1.png",
                },
                {
                    "Content-Disposition": 'attachment; filename="image_2.png"',
                    "Content-ID": "<ii_kgjzygxz1>",
                    "Name": "image_2.png",
                },
            ]
        },
        "File": mocked_files,
    }

    mocker.patch.object(demisto, "demistoUrls", return_value={"server": "https://localhost:8443:/acc_test_tenant"})
    mocker.patch.object(demisto, "incident", return_value=mocked_incident)
    mocker.patch.object(demisto, "context", return_value=mocked_context)
    mocker.patch.object(DisplayHTMLWithImages, "return_results")

    main()

    assert expected in DisplayHTMLWithImages.return_results.call_args[0][0]["Contents"]


def test_2_imgaes_with_same_name(mocker):
    """
    Given
    - Html contained 2 images with same name and another file.
    When
    - All images were uploaded to the server
    Then
    - The images' src attribute would be replaced as expected with the correct entry id
    """
    import DisplayHTMLWithImages
    from DisplayHTMLWithImages import main

    mocked_incident = {
        "CustomFields": {"emailbody": '<img src="cid:ii_lyfigebl1"><img src="cid:ii_wweegebl1">'},
    }
    mocked_files = [
        {"Name": "test.pdf", "EntryID": "36@119"},
        {"Name": "image_1.png", "EntryID": "37@119"},
        {"Name": "image_1.png", "EntryID": "38@119"},
    ]

    mocked_context = {
        "Email": {
            "AttachmentsData": [
                {"Content-ID": "<ii_FFFFFFFFF>", "Name": "test.pdf"},
                {"Content-ID": "<ii_lyfigebl1>", "Name": "image_1.png"},
                {"Content-ID": "<ii_wweegebl1>", "Name": "image_1.png"},
            ]
        },
        "File": mocked_files,
    }

    mocker.patch.object(demisto, "demistoUrls", return_value={"server": "test_url"})
    mocker.patch.object(demisto, "incident", return_value=mocked_incident)
    mocker.patch.object(demisto, "context", return_value=mocked_context)
    mocker.patch.object(DisplayHTMLWithImages, "return_results")

    main()

    expected = "<img src=/entry/download/37@119><img src=/entry/download/38@119>"
    assert expected in DisplayHTMLWithImages.return_results.call_args[0][0]["Contents"]


def test_2_imgaes_with_same_name_gmail_format(mocker):
    """
    Given
    - Html contained 2 images with same name with the Gmail format (with alt=image name).
    When
    - All images were uploaded to the server
    Then
    - The images' src attribute would be replaced as expected with the correct entry id
    """
    import DisplayHTMLWithImages
    from DisplayHTMLWithImages import main

    mocked_incident = {
        "CustomFields": {"emailbody": '<img src="cid:ii_lyfigebl1" alt="image.png"><img src="cid:ii_wweegebl1" alt="image.png">'},
    }
    mocked_files = [{"Name": "image.png", "EntryID": "37@119"}, {"Name": "image.png", "EntryID": "38@119"}]

    mocked_context = {
        "Email": {
            "AttachmentsData": [
                {"Content-ID": "<ii_lyfigebl1>", "Name": "image.png"},
                {"Content-ID": "<ii_wweegebl1>", "Name": "image.png"},
            ]
        },
        "File": mocked_files,
    }

    mocker.patch.object(demisto, "demistoUrls", return_value={"server": "test_url"})
    mocker.patch.object(demisto, "incident", return_value=mocked_incident)
    mocker.patch.object(demisto, "context", return_value=mocked_context)
    mocker.patch.object(DisplayHTMLWithImages, "return_results")

    main()

    expected = '<img src=/entry/download/37@119 alt="image.png"><img src=/entry/download/38@119 alt="image.png">'
    assert expected in DisplayHTMLWithImages.return_results.call_args[0][0]["Contents"]


def test_one_imgae_in_emailhtml(mocker):
    """
    Given
    - Incident contained the Html which contained one image in the emailhtml filed.
    When
    - Image were uploaded to the server
    Then
    - The image' src attribute would be replaced as expected with the correct entry id
    """
    import DisplayHTMLWithImages
    from DisplayHTMLWithImages import main

    mocked_incident = {
        "CustomFields": {"emailhtml": '<img src="cid:ii_wweegebl1">'},
    }
    mocked_file = {"Name": "image_1.png", "EntryID": "38@119"}

    mocked_context = {
        "Email": {"AttachmentsData": [{"Content-ID": "<ii_wweegebl1>", "Name": "image_1.png"}]},
        "File": mocked_file,
    }

    mocker.patch.object(demisto, "demistoUrls", return_value={"server": "test_url"})
    mocker.patch.object(demisto, "incident", return_value=mocked_incident)
    mocker.patch.object(demisto, "context", return_value=mocked_context)
    mocker.patch.object(DisplayHTMLWithImages, "return_results")

    main()

    expected = "<img src=/entry/download/38@119>"
    assert expected in DisplayHTMLWithImages.return_results.call_args[0][0]["Contents"]


def test_content_id_none(mocker):
    """
    Given
    - The COntent ID of attachment in context are None.
    When
    - Image were uploaded to the server
    Then
    - The image' src attribute would not be replaced.
    """
    import DisplayHTMLWithImages
    from DisplayHTMLWithImages import main

    mocked_incident = {
        "CustomFields": {"emailhtml": '<img src="cid:ii_wweegebl1">'},
    }
    mocked_file = {"Name": "image_1.png", "EntryID": "38@119"}

    mocked_context = {"Email": {"AttachmentsData": [{"Content-ID": None, "Name": "image_1.png"}]}, "File": mocked_file}

    mocker.patch.object(demisto, "demistoUrls", return_value={"server": "test_url"})
    mocker.patch.object(demisto, "incident", return_value=mocked_incident)
    mocker.patch.object(demisto, "context", return_value=mocked_context)
    mocker.patch.object(DisplayHTMLWithImages, "return_results")

    main()

    expected = '<img src="cid:ii_wweegebl1">'
    assert expected in DisplayHTMLWithImages.return_results.call_args[0][0]["Contents"]


@pytest.mark.parametrize("is_xsoar_saas, expected_prefix", [(True, "/xsoar"), (False, "")])
def test_xsoar_saas(mocker, is_xsoar_saas, expected_prefix):
    """
    Given
    - The is_xsiam_or_xsoar_saas is True or False.
    When
    - Image were uploaded to the server
    Then
    - The image' src attribute would be replaced with the right download url (with /xsoar in case xsoar saas).
    """
    import DisplayHTMLWithImages
    from DisplayHTMLWithImages import main

    mocked_incident = {
        "CustomFields": {"emailhtml": '<img src="cid:ii_wweegebl1">'},
    }
    mocked_file = {"Name": "image_1.png", "EntryID": "38@119"}

    mocked_context = {"Email": {"AttachmentsData": {"Content-ID": "<ii_wweegebl1>", "Name": "image_1.png"}}, "File": mocked_file}

    mocker.patch.object(demisto, "demistoUrls", return_value={"server": "test_url"})
    mocker.patch.object(demisto, "incident", return_value=mocked_incident)
    mocker.patch.object(demisto, "context", return_value=mocked_context)
    mocker.patch.object(DisplayHTMLWithImages, "return_results")
    mocker.patch.object(DisplayHTMLWithImages, "is_xsiam_or_xsoar_saas", return_value=is_xsoar_saas)

    main()

    expected = f"<img src={expected_prefix}/entry/download/38@119>"
    assert expected in DisplayHTMLWithImages.return_results.call_args[0][0]["Contents"]


class TestSanitizeHtml:
    """Tests for HTML sanitization in _sanitize_html."""

    def test_strips_script_tags(self, mocker):
        """
        Given
        - An HTML body containing script tags
        When
        - _sanitize_html is called with bleach available
        Then
        - Script tags and their content are removed while safe content is preserved
        """
        import types
        import DisplayHTMLWithImages

        # Create a mock bleach module that simulates real bleach.clean behavior
        mock_bleach = types.ModuleType("bleach")

        def mock_clean(html, tags=None, strip=False, attributes=None):
            """Simulate bleach: strip disallowed tags, keep allowed ones."""
            import re

            # Remove script tags and their content (not in allowed tags)
            result = re.sub(r"<\s*script[^>]*>.*?<\s*/\s*script[^>]*>", "", html, flags=re.DOTALL | re.IGNORECASE)
            return result

        mock_bleach.clean = mock_clean
        mocker.patch.dict("sys.modules", {"bleach": mock_bleach})

        # Re-import to pick up the mock
        result = DisplayHTMLWithImages._sanitize_html('<p>Hello</p><script>alert("test")</script><p>World</p>')
        assert "<script>" not in result
        assert "alert" not in result
        assert "Hello" in result
        assert "World" in result

    def test_preserves_allowed_tags(self, mocker):
        """
        Given
        - An HTML body containing only allowed tags (p, br, div, table, etc.)
        When
        - _sanitize_html is called with bleach available
        Then
        - All allowed tags are preserved in the output
        """
        import types
        import DisplayHTMLWithImages

        mock_bleach = types.ModuleType("bleach")

        def mock_clean(html, tags=None, strip=False, attributes=None):
            # Allowed tags pass through unchanged
            return html

        mock_bleach.clean = mock_clean
        mocker.patch.dict("sys.modules", {"bleach": mock_bleach})

        html_input = "<div><p>Text</p><br><table><tr><td>Cell</td></tr></table></div>"
        result = DisplayHTMLWithImages._sanitize_html(html_input)
        assert "<div>" in result
        assert "<p>" in result
        assert "<table>" in result
        assert "<td>" in result

    def test_preserves_formatting_tags(self, mocker):
        """
        Given
        - An HTML body with formatting tags like b, i, u, strong, em
        When
        - _sanitize_html is called with bleach available
        Then
        - Formatting tags are preserved
        """
        import types
        import DisplayHTMLWithImages

        mock_bleach = types.ModuleType("bleach")

        def mock_clean(html, tags=None, strip=False, attributes=None):
            return html

        mock_bleach.clean = mock_clean
        mocker.patch.dict("sys.modules", {"bleach": mock_bleach})

        html_input = "<b>bold</b> <i>italic</i> <u>underline</u> <strong>strong</strong> <em>emphasis</em>"
        result = DisplayHTMLWithImages._sanitize_html(html_input)
        assert "<b>" in result
        assert "<i>" in result
        assert "<u>" in result
        assert "<strong>" in result
        assert "<em>" in result

    def test_calls_bleach_with_allowed_tags(self, mocker):
        """
        Given
        - An HTML body
        When
        - _sanitize_html is called with bleach available
        Then
        - bleach.clean is called with the ALLOWED_EMAIL_TAGS set and strip=True
        """
        import types
        import DisplayHTMLWithImages
        from unittest.mock import MagicMock

        mock_bleach = types.ModuleType("bleach")
        mock_clean = MagicMock(return_value="<p>safe</p>")
        mock_bleach.clean = mock_clean
        mocker.patch.dict("sys.modules", {"bleach": mock_bleach})

        DisplayHTMLWithImages._sanitize_html("<p>test</p>")
        mock_clean.assert_called_once()
        call_kwargs = mock_clean.call_args
        assert call_kwargs[1].get("strip") is True or call_kwargs[1].get("strip")
        assert "p" in call_kwargs[1].get("tags", set())
        assert "div" in call_kwargs[1].get("tags", set())
        assert "table" in call_kwargs[1].get("tags", set())

    def test_fallback_strips_dangerous_tags_when_bleach_unavailable(self, mocker):
        """
        Given
        - An HTML body with dangerous tags and bleach is not installed
        When
        - _sanitize_html is called
        Then
        - Dangerous tags (script, iframe, etc.) are stripped via regex fallback
        """
        import sys
        import DisplayHTMLWithImages

        # Force bleach to be unavailable by setting it to None in sys.modules
        # This makes 'import bleach' raise ImportError deterministically
        mocker.patch.dict(sys.modules, {"bleach": None})

        html_input = '<p>Hello</p><script>alert("test")</script><p>World</p>'
        result = DisplayHTMLWithImages._sanitize_html(html_input)
        # Without bleach, the fallback regex strips script tags
        assert "<script>" not in result
        assert "alert" not in result
        assert "Hello" in result
        assert "World" in result


class TestCreateHtmlWithImagesInputSanitization:
    """Tests for safe regex handling in create_html_with_images."""

    def test_attachment_name_with_regex_special_chars(self, mocker):
        """
        Given
        - An attachment name containing regex special characters like (, ), .
        When
        - create_html_with_images is called
        Then
        - No regex error occurs and the function completes successfully
        """
        from DisplayHTMLWithImages import create_html_with_images

        mocker.patch("DisplayHTMLWithImages.get_tenant_account_name", return_value="")
        mocker.patch("DisplayHTMLWithImages.is_xsiam_or_xsoar_saas", return_value=False)

        email_html = '<img src="cid:content_id_123">'
        entry_id_list = [("file (1).png", "content_id_123", "42@100")]
        # Should not raise a regex error
        result = create_html_with_images(email_html, entry_id_list)
        assert isinstance(result, str)

    def test_content_id_with_regex_special_chars(self, mocker):
        """
        Given
        - A content ID containing regex special characters like +, .
        When
        - create_html_with_images is called
        Then
        - No regex error occurs and replacement works correctly
        """
        from DisplayHTMLWithImages import create_html_with_images

        mocker.patch("DisplayHTMLWithImages.get_tenant_account_name", return_value="")
        mocker.patch("DisplayHTMLWithImages.is_xsiam_or_xsoar_saas", return_value=False)

        email_html = '<img src="cid:id+special.chars(1)">'
        entry_id_list = [("image.png", "id+special.chars(1)", "50@200")]
        # Should not raise a regex error
        result = create_html_with_images(email_html, entry_id_list)
        assert isinstance(result, str)

    def test_empty_entry_id_list_returns_original(self, mocker):
        """
        Given
        - An empty entry_id_list
        When
        - create_html_with_images is called
        Then
        - The original email_html is returned unchanged
        """
        from DisplayHTMLWithImages import create_html_with_images

        email_html = "<p>No images here</p>"
        result = create_html_with_images(email_html, [])
        assert result == email_html
