# ruff: noqa: RUF001

def test_text_from_html_success_english():
    """
    Given
    - html string:
        <!DOCTYPE html>
        <html>
        <body>
        <h1>This is heading 1</h1>
        </body>
        </html>

    When
    - extracting text from the html

    Then
    - ensure we return "This is heading 1"
    """
    import TextFromHTML

    html = """
<!DOCTYPE html>
<html>
<body>
<h1>This is heading 1</h1>
</body>
</html>
"""

    body = TextFromHTML.get_body(html, html_tag='body')
    res = TextFromHTML.get_plain_text(body, replace_line_breaks=False, trim_result=False)

    assert res == '\nThis is heading 1\n'


def test_text_from_html_success_hebrew():
    """
    Given
    - html string:
        <!DOCTYPE html>
        <html>
        <body>
        <h1>משפט בעברית לבדיקה</h1>
        </body>
        </html>

    When
    - extracting text from the html

    Then
    - ensure we return "משפט בעברית לבדיקה"
    """
    import TextFromHTML

    html = """
<!DOCTYPE html>
<html>
<body>
<h1>משפט בעברית לבדיקה</h1>
</body>
</html>
"""

    body = TextFromHTML.get_body(html, html_tag='body')
    res = TextFromHTML.get_plain_text(body, replace_line_breaks=False, trim_result=False)

    assert res == '\nמשפט בעברית לבדיקה\n'


def test_text_from_html_success_spanish():
    """
    Given
    - html string:
        <!DOCTYPE html>
        <html>
        <body>
        <h1>Frase en español para revisión</h1>
        </body>
        </html>

    When
    - extracting text from the html

    Then
    - ensure we return "Frase en español para revisión"
    """
    import TextFromHTML

    html = """
<!DOCTYPE html>
<html>
<body>
<h1>Frase en español para revisión</h1>
</body>
</html>
"""

    body = TextFromHTML.get_body(html, html_tag='body')
    res = TextFromHTML.get_plain_text(body, replace_line_breaks=False, trim_result=False)

    assert res == '\nFrase en español para revisión\n'


def test_extract_text_from_complex_html():
    """
    Given
    - html string:
        <!DOCTYPE html>
        <html>
        <body>

        <h2>HTML Links</h2>
        <p>HTML links are defined with the a tag:</p>

        <a href="https://www.w3schools.com">This is a link</a>

        </body>
        </html>

    When
    - extracting text from the html

    Then
    - ensure we return "This is heading 1"
    """
    import TextFromHTML

    html = """
<!DOCTYPE html>
<html>
<body>

<h2>HTML Links</h2>
<p>HTML links are defined with the a tag:</p>

<a href="https://www.w3schools.com">This is a link</a>

</body>
</html>
"""

    body = TextFromHTML.get_body(html, html_tag='body')
    res = TextFromHTML.get_plain_text(body, replace_line_breaks=False, trim_result=False)

    assert res == '\n\nHTML Links\nHTML links are defined with the a tag:\n\nThis is a link\n\n'


def test_extract_text_from_html_with_breaks():
    """
    Given
    - html string:
        <!DOCTYPE html>
        <html>
        <body>
        <h2>HTML Breaks</h2>
        <p>HTML can contain break tags</p>
        <br>
        <p>Which should lead to a proper linebreak</p>
        </body>
        </html>

    When
    - extracting text from the html

    Then
    - ensure we return "\nHTML Breaks\nHTML can contain break tags\n\n\nWhich should lead to a proper linebreak"
    """
    import TextFromHTML

    html = """
<!DOCTYPE html>
<html>
<body>
<h2>HTML Breaks</h2>
<p>HTML can contain break tags</p>
<br>
<p>Which should lead to a proper linebreak</p>
</body>
</html>
"""

    body = TextFromHTML.get_body(html, html_tag='body')
    res = TextFromHTML.get_plain_text(body, replace_line_breaks=True, trim_result=False)
    assert res == '\nHTML Breaks\nHTML can contain break tags\n\n\nWhich should lead to a proper linebreak\n'


def test_extract_text_from_html_with_breaks_trimed():
    """
    Given
    - html string:
        <!DOCTYPE html>
        <html>
        <body>
        <h2>HTML Breaks</h2>
        <p>HTML can contain break tags</p>
        <br>
        <p>Which should lead to a proper linebreak</p>
        </body>
        </html>

    When
    - extracting text from the html with replace_line_breaks and trim_result enabled

    Then
    - ensure we return "HTML Breaks\nHTML can contain break tags\n\nWhich should lead to a proper linebreak"
    """
    import TextFromHTML

    html = """
<!DOCTYPE html>
<html>
<body>
<h2>HTML Breaks</h2>
<p>HTML can contain break tags</p>
<br>
<p>Which should lead to a proper linebreak</p>
</body>
</html>
"""
    body = TextFromHTML.get_body(html, html_tag='body')
    res = TextFromHTML.get_plain_text(body, replace_line_breaks=True, trim_result=True)
    assert res == 'HTML Breaks\nHTML can contain break tags\n\nWhich should lead to a proper linebreak'


def test_extract_text_from_specific_tag():
    """
    Given
    - html string:
        <p>HTML links are defined with the a tag:</p>
    When
    - extracting text from the html
    Then
    - ensure we return "HTML links are defined with the a tag:"
    """
    import TextFromHTML

    html = """<p>HTML links are defined with the a tag:</p>"""

    body = TextFromHTML.get_body(html, html_tag='p')
    res = TextFromHTML.get_plain_text(body, replace_line_breaks=False, trim_result=False)

    assert res == 'HTML links are defined with the a tag:'


def test_extract_with_fallback():
    """
    Given
    - html string:
        <div>Some HTML does not have a body Tag</div>
    When
    - extracting text from the html with fallback enabled
    Then
    - ensure we return "Some HTML does not have a body Tag"
    """
    import TextFromHTML

    html = """<div>Some HTML does not have a body Tag</div>"""

    body = TextFromHTML.get_body(html, html_tag='body', allow_fallback=True)
    res = TextFromHTML.get_plain_text(body, replace_line_breaks=False, trim_result=False)

    assert res == 'Some HTML does not have a body Tag'


def test_extract_without_fallback():
    """
    Given
    - html string:
        <div>Some HTML does not have a body Tag</div>
    When
    - extracting text from the html
    Then
    - ensure we return ""
    """
    import TextFromHTML

    html = """<div>Some HTML does not have a body Tag</div>"""

    body = TextFromHTML.get_body(html, html_tag='body', allow_fallback=False)
    res = TextFromHTML.get_plain_text(body, replace_line_breaks=False, trim_result=False)

    assert res == ''


def test_get_body():
    """
    Given
    - html string:
        <!DOCTYPE html>
<html>
<body>
<h1>This is heading 1</h1>
</body>
</html>
    When
    - extracting body from html
    Then
    - ensure we return "<body>\n<h1>This is heading 1</h1>\n</body>"
    """
    import TextFromHTML
    html = """
<!DOCTYPE html>
<html>
<body>
<h1>This is heading 1</h1>
</body>
</html>
"""
    body = TextFromHTML.get_body(html, html_tag='body', allow_fallback=False)

    assert body == '<body>\n<h1>This is heading 1</h1>\n</body>'


def test_get_body_without_fallback():
    """
    Given
    - html string:
        <div>Some HTML does not have a body Tag</div>
    When
    - extracting body from html
    Then
    - ensure we return ""
    """
    import TextFromHTML

    html = """<div>Some HTML does not have a body Tag</div>"""
    body = TextFromHTML.get_body(html, html_tag='body', allow_fallback=False)

    assert body == ''


def test_get_body_with_fallback():
    """
    Given
    - html string:
        <div>Some HTML does not have a body Tag</div>
    When
    - extracting body from html
    Then
    - ensure we return ""
    """
    import TextFromHTML

    html = """<div>Some HTML does not have a body Tag</div>"""
    body = TextFromHTML.get_body(html, html_tag='body', allow_fallback=True)

    assert body == '<div>Some HTML does not have a body Tag</div>'
