import pytest
from diplayMappedFields import escape_for_html_table, format_data_to_rows, convert_to_html


class TestEscapeForHtmlTable:
    """Tests for output encoding in escape_for_html_table."""

    def test_html_special_characters_are_escaped(self):
        """
        Given
        - A string containing HTML special characters
        When
        - escape_for_html_table is called
        Then
        - All HTML special characters are properly encoded
        """
        assert escape_for_html_table('<img src=x>') == '&lt;img src=x&gt;'

    def test_ampersand_is_escaped(self):
        """
        Given
        - A string containing an ampersand
        When
        - escape_for_html_table is called
        Then
        - The ampersand is encoded as &amp;
        """
        assert escape_for_html_table('a & b') == 'a &amp; b'

    def test_quotes_are_escaped(self):
        """
        Given
        - A string containing quote characters
        When
        - escape_for_html_table is called
        Then
        - Quotes are properly encoded
        """
        result = escape_for_html_table('"hello"')
        assert '&quot;' in result or '&#x27;' in result or '"' not in result or result == '&quot;hello&quot;'

    def test_pipe_characters_are_escaped(self):
        """
        Given
        - A string containing pipe characters
        When
        - escape_for_html_table is called
        Then
        - Pipe characters are replaced with &#124;
        """
        assert escape_for_html_table('a|b') == 'a&#124;b'

    def test_normal_text_passes_through_unchanged(self):
        """
        Given
        - A plain text string with no special characters
        When
        - escape_for_html_table is called
        Then
        - The string is returned unchanged
        """
        assert escape_for_html_table('hello world') == 'hello world'

    def test_empty_string(self):
        """
        Given
        - An empty string
        When
        - escape_for_html_table is called
        Then
        - An empty string is returned
        """
        assert escape_for_html_table('') == ''

    def test_combined_special_characters(self):
        """
        Given
        - A string with both HTML special chars and pipe characters
        When
        - escape_for_html_table is called
        Then
        - Both types of special characters are properly encoded
        """
        result = escape_for_html_table('<b>test</b>|value')
        assert '&lt;' in result
        assert '&gt;' in result
        assert '&#124;' in result
        assert '<' not in result
        assert '|' not in result


class TestFormatDataToRows:
    """Tests for format_data_to_rows with input sanitization."""

    def test_html_in_keys_and_values_is_escaped(self):
        """
        Given
        - Items with HTML markup in both keys and values
        When
        - format_data_to_rows is called
        Then
        - The output rows contain escaped HTML, not raw markup
        """
        items = [('<script>alert(1)</script>', '<img src=x>')]
        rows = format_data_to_rows(items)
        assert len(rows) == 1
        assert '<script>' not in rows[0]
        assert '<img' not in rows[0]
        assert '&lt;script&gt;' in rows[0]
        assert '&lt;img src=x&gt;' in rows[0]

    def test_list_values_are_escaped(self):
        """
        Given
        - Items where the value is a list containing HTML
        When
        - format_data_to_rows is called
        Then
        - List items are joined and the result is escaped
        """
        items = [('key', ['<b>bold</b>', 'normal'])]
        rows = format_data_to_rows(items)
        assert len(rows) == 1
        assert '<b>' not in rows[0]

    def test_normal_data_formatted_correctly(self):
        """
        Given
        - Items with normal text keys and values
        When
        - format_data_to_rows is called
        Then
        - Rows are formatted as key|value
        """
        items = [('name', 'John'), ('age', '30')]
        rows = format_data_to_rows(items)
        assert len(rows) == 2
        assert rows[0] == 'name|John'
        assert rows[1] == 'age|30'


class TestConvertToHtml:
    """Tests for convert_to_html output encoding."""

    def test_output_does_not_contain_raw_html_from_input(self):
        """
        Given
        - Rows generated from data containing HTML special characters (already escaped)
        When
        - convert_to_html is called on those rows
        Then
        - The final HTML output does not contain unescaped user-supplied HTML
        """
        items = [('<img src=x onerror=alert(1)>', 'value')]
        rows = format_data_to_rows(items)
        html_output = convert_to_html(rows)
        assert '<img src=x' not in html_output
        assert '&lt;img' in html_output

    def test_table_structure_is_valid(self):
        """
        Given
        - Normal rows
        When
        - convert_to_html is called
        Then
        - The output contains proper table HTML structure
        """
        rows = ['key|value']
        html_output = convert_to_html(rows)
        assert '<table' in html_output
        assert '<tr>' in html_output
        assert '<td' in html_output
        assert '</table>' in html_output
