from ExtractHTMLTables import extract_html_table


def test_extract_html_table():
    """
    Given:
        An html table.

    When:
        Execute command extract_html_table

    Then:
        Validate the right output returns.
    """
    html_table = """
        <table>
          <tr>
            <th>Company</th>
            <th>Contact</th>
            <th>Country</th>
          </tr>
          <tr>
            <td>Alfreds Futterkiste</td>
            <td>Maria Anders</td>
            <td>Germany</td>
          </tr>
          <tr>
            <td>Centro comercial Moctezuma</td>
            <td>Francisco Chang</td>
            <td>Mexico</td>
          </tr>
        </table>
        """
    res = extract_html_table(html_table, [])
    assert "Found 1 tables in HTML." in res['Contents']
