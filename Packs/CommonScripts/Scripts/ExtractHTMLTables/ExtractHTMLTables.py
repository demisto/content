import demistomock as demisto  # noqa: F401
from bs4 import BeautifulSoup
from CommonServerPython import *  # noqa: F401


def extract_html_table(html, indexes):
    soup = BeautifulSoup(html, 'html.parser')
    tables = []
    for index, tab in enumerate(soup.find_all('table')):
        if len(indexes) > 0 and index not in indexes and str(index) not in indexes:
            continue
        table = []
        headers = []
        # Check if there are headers and use them
        for th in tab.find_all('th'):
            headers.append(th.text)
        for tr in tab.find_all('tr'):
            tds = tr.find_all('td')
            # This is a data row and not header row
            if len(tds) > 0:
                # Single value in a table - just create an array of strings ignoring header
                if len(tds) == 1:
                    table.append(tds[0].text)
                # If there are 2 columns and no headers, treat as key-value (might override values if same key in first column)
                elif len(tds) == 2 and len(headers) == 0:
                    if type(table) is list:
                        table = {}  # type: ignore
                    table[tds[0].text] = tds[1].text
                else:
                    row = {}
                    if len(headers) > 0:
                        for i, td in enumerate(tds):
                            row[headers[i]] = td.text
                    else:
                        for i, td in enumerate(tds):
                            row['cell' + str(i)] = td.text
                    table.append(row)
        if len(table) > 0:
            tables.append(table)
    if len(tables) > 0:
        return ({
            'Type': entryTypes['note'],
            'Contents': 'Found {} tables in HTML.'.format(len(tables)),
            'ContentsFormat': formats['text'],
            'EntryContext': {'HTMLTables': tables if len(tables) > 1 else tables[0]}
        })
    else:
        return 'Did not find tables in HTML.'


def main():
    html = demisto.getArg('html')
    indexes = argToList(demisto.getArg('indexes'))
    demisto.results(extract_html_table(html, indexes))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
