# -*- coding: utf-8 -*- 


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

    args = {
        'html': html
    }
    res = TextFromHTML.text_from_html(args)

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

    html = u"""
<!DOCTYPE html>
<html>
<body>
<h1>משפט בעברית לבדיקה</h1>
</body>
</html>
"""

    args = {
        'html': html
    }
    res = TextFromHTML.text_from_html(args)

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

    html = u"""
<!DOCTYPE html>
<html>
<body>
<h1>Frase en español para revisión</h1>
</body>
</html>
"""

    args = {
        'html': html
    }
    res = TextFromHTML.text_from_html(args)

    assert res == '\nFrase en español para revisión\n'
