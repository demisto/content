import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import copy
from typing import Any, Dict, Generator, List, Optional, Tuple, Union
from bs4 import BeautifulSoup, NavigableString, Tag


TITLE_THRESHOLD = 4


class Table:
    def __init__(self, title: str):
        self.__title = title
        self.__headers: List[str] = []
        self.__rows: List[Tuple[List[str], List[str]]] = []
        self.__rowspan_labels: List[Tuple[int, str]] = []

    def __set_rowspan_labels(self, columns: Optional[List[Tag]]):
        if not columns or not any(col.attrs.get('rowspan') for col in columns):
            return

        rowspan_labels: List[Tuple[int, str]] = []
        for col in columns:
            try:
                rowspan = int(col.attrs.get('rowspan') or 1)
            except Exception:
                rowspan = 1
            rowspan = max(1, rowspan)

            try:
                colspan = int(col.attrs.get('colspan') or 1)
            except Exception:
                colspan = 1
            colspan = max(1, colspan)

            rowspan_labels += [(rowspan, col.text.strip())] * colspan

        self.__rowspan_labels = rowspan_labels

    def get_title(self) -> str:
        return self.__title

    def set_header_labels(self, headers: List[Tag]):
        self.__headers = [header.text.strip() for header in headers]

    def get_header_labels(self) -> List[str]:
        return self.__headers

    def add_row(self, columns: List[Tag], labels: Optional[List[Tag]] = None):
        """
        Add a row with cells and labels.

        :param columns: List of data cells of the row.
        :param labels: List of header cells of the row.
        """
        rowspan_labels = self.__rowspan_labels

        # Normalize labels
        if labels and any(label.attrs.get('rowspan') for label in labels):
            self.__set_rowspan_labels(labels)

        normalized_labels = []
        if labels:
            for i, (count, label) in enumerate(rowspan_labels):
                if count >= 2:
                    normalized_labels.append(label)

            for label in labels:
                try:
                    colspan = int(label.attrs.get('colspan') or 1)
                except Exception:
                    colspan = 1
                normalized_labels += [label.text.strip()] * max(1, colspan)

        # Normalize columns
        if any(col.attrs.get('rowspan') for col in columns):
            self.__set_rowspan_labels(columns)

        normalized_columns = []
        for i, (count, label) in enumerate(rowspan_labels):
            if count >= 2:
                normalized_columns.append(label)
                rowspan_labels[i] = count - 1, label

        for col in columns:
            try:
                colspan = int(col.attrs.get('colspan') or 1)
            except Exception:
                colspan = 1
            normalized_columns += [col.text.strip()] * max(1, colspan)

        self.__rows.append((normalized_labels, normalized_columns))

    def get_rows(self) -> List[Tuple[List[str], List[str]]]:
        return self.__rows

    def make_pretty_table_rows(self, default_header_line: Optional[str] = None) -> Any:
        """
        Format a table

        :param default_header_line: Which table line handles as header by default, 'first_column' or 'first_row'
        :return: The table formatted in JSON structure.
        """
        rows: List[Union[str, Dict[str, Any]]] = []
        temp_row: Dict[str, Any] = {}

        tbl_rows = self.__rows
        headers = self.__headers

        if default_header_line and default_header_line != 'none':
            if not headers and not any(labels for labels, cols in tbl_rows):
                if default_header_line in ('first_column', 'first_row'):
                    # The first column or row is considered as header
                    if default_header_line == 'first_column':
                        # transpose
                        tbl_rows = [([], list(cols)) for cols in zip(*[cols for labels, cols in tbl_rows])]

                    labels, headers = tbl_rows[0]
                    tbl_rows = tbl_rows[1:]
                else:
                    raise ValueError(f'Unknown default header line: {default_header_line}')

        for labels, cols in tbl_rows:
            labels = labels[-1:]
            headers = labels + headers[len(labels):len(headers) - len(labels)]

            if not cols:
                continue

            elif len(cols) == 1:
                if len(headers) >= 1:
                    # If there 1 header and 1 column, treat as key-value
                    key = headers[0]
                    vals = temp_row.get(key)
                    if vals is None:
                        temp_row[key] = cols[0]
                    elif type(vals) is list:
                        temp_row[key] = vals + [cols[0]]
                    else:
                        temp_row[key] = [vals, cols[0]]
                else:
                    if temp_row:
                        rows.append(temp_row)
                        temp_row = {}

                    # Single value in a table - just create an array of strings
                    rows.append(cols[0])

            elif len(cols) == 2 and len(headers) == 0:
                # If there are 2 columns and no headers, treat as key-value
                key = cols[0]
                vals = temp_row.get(key)
                if vals is None:
                    temp_row[key] = cols[1]
                elif type(vals) is list:
                    temp_row[key] = vals + [cols[1]]
                else:
                    temp_row[key] = [vals, cols[1]]
            else:
                if temp_row:
                    rows.append(temp_row)
                    temp_row = {}

                rows.append({headers[i] if i < len(headers) else 'cell' + str(i): col for i, col in enumerate(cols)})

        if temp_row:
            rows.append(temp_row)

        if len(rows) == 1 and type(rows[0]) is dict:
            return rows[0]
        return rows


def find_table_title(base: Optional[Union[BeautifulSoup, Tag, NavigableString]],
                     node: Union[BeautifulSoup, Tag, NavigableString]) -> Optional[str]:
    """
    Search for a table title from a node.

    :param base: The top node of the tree.
    :param node: The node from which searching starts.
    :return: A title found.
    """
    title = ''
    orig = node
    prev = node.previous_element
    while prev and node is not base:
        node = prev
        if isinstance(node, Tag) and node.name in ('h1', 'h2', 'h3', 'h4', 'h5', 'h6'):
            title = ' '.join(node.text.strip().split())
            break

        prev = node.previous_element

    if not title or title.count(' ') >= TITLE_THRESHOLD:
        message = ''
        node = orig
        prev = node.previous_element
        while prev and node is not base:
            node = prev
            if isinstance(node, NavigableString):
                message = (str(node) if message else str(node).rstrip()) + message
                if message.lstrip() and any(c in message for c in ('\n', '\r')):
                    break

            prev = node.previous_element

        message = ' '.join(message.strip().split())
        title = title if title and message.count(' ') >= title.count(' ') else message

    return title


def list_columns(node: Union[BeautifulSoup, Tag, NavigableString], name: str) -> List[Tag]:
    """
    List columns of the row.

    :param node: The node which contains columns of the row.
    :param name: The name of the tag of columns.
    :return: The list of columns.
    """
    vals = []
    ancestor = node
    name_list = ['table', 'td', 'th', name]
    node = node.find(name_list)
    while node and is_descendant(ancestor, node):
        if node.name in name_list:
            if node.name == name:
                tnode = copy.copy(node)
                for t in tnode.find_all('table'):
                    t.decompose()
                vals.append(tnode)
            node = node.find_next_sibling(True)
        else:
            node = node.find_next(name_list)
    return vals


def is_descendant(ancestor: Optional[Union[BeautifulSoup, Tag, NavigableString]],
                  node: Optional[Union[BeautifulSoup, Tag, NavigableString]]) -> bool:
    """
    Check if a node is descendant in the tree.

    :param ancestor: The ancestor node.
    :param node: The node to be checked.
    :return: True - node is descendant, False - node is not descendant.
    """
    return ancestor is not None and node is not None and any([ancestor is p for p in node.parents])


def parse_table(base: Optional[Union[BeautifulSoup, Tag, NavigableString]],
                table_node: Union[BeautifulSoup, Tag, NavigableString]) -> Generator[Table, None, None]:
    """
    Parse a HTML table and enumerate tables found in the table.

    :param base: The top node of the HTML tree.
    :param table_node: The table node to parse.
    :return: Tables found.
    """
    table = Table(title=find_table_title(base, table_node) or 'No Title')
    has_nested_tables = False

    node = table_node.find(['table', 'tr'])
    while node and is_descendant(table_node, node):
        if node.name == 'tr':
            ths = list_columns(node, 'th')
            tds = list_columns(node, 'td')
            if tds:
                table.add_row(columns=tds, labels=ths)
            if ths and not table.get_header_labels():
                table.set_header_labels(ths)

            node = node.find_next(['table', 'tr'])

        elif node.name == 'table':
            has_nested_tables = True
            yield from parse_table(base, node)

            base = node.previous_element
            node = node.find_next_sibling(True)
        else:
            node = node.find_next(['table', 'tr'])

    # Not to make a table if tr only has tables
    has_table = True
    if has_nested_tables:
        rows = table.get_rows()
        if len(rows) == 1:
            labels, cols = rows[0]
            if len(cols) == 1 and not cols[0]:
                has_table = False

    if has_table:
        yield table


def parse_tables(node: Union[BeautifulSoup, Tag, NavigableString]) -> Generator[Table, None, None]:
    """
    Parse HTML tables and enumerate them.

    :param node: The node from which searching starts.
    :return: Tables found.
    """
    base = None
    node = node.find('table')
    while node:
        yield from parse_table(base, node)
        base = node.next_sibling

        while node:
            next = node.find_next_sibling(True)
            if next:
                if next.name == 'table':
                    break

                next = next.find_next('table')
                if next:
                    break
            node = node.parent
        node = next


def main():
    args = demisto.args()
    html = args.get('value') or ''
    overwriting_title = args.get('title')
    filter_indexes = argToList(args.get('filter_indexes'))
    filter_titles = argToList(args.get('filter_titles'))
    default_header_line = args.get('default_header_line') or 'none'

    tables = []
    try:
        soup = BeautifulSoup(html, 'html.parser')
        index = -1
        for table in parse_tables(soup):
            rows = table.make_pretty_table_rows(default_header_line)
            if not rows:
                continue

            index = index + 1
            if filter_indexes and\
               index not in filter_indexes and\
               str(index) not in filter_indexes:
                continue

            original_title = table.get_title()
            if filter_titles and original_title not in filter_titles:
                continue

            tables.append({overwriting_title or original_title: rows})

    except Exception as err:
        # Don't return an error by return_error() as this is transformer.
        raise DemistoException(str(err))

    return_results(tables)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
