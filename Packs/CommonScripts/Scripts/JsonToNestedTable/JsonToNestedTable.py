from CommonServerPython import *
import demistomock as demisto

"""Extract nested values from a JSON tree."""




def json_extract(obj):
    """Recursively fetch values from nested JSON."""
    arr = []

    def extract(obj):
        """Recursively search for values of key in JSON tree."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                arr.append(f"{k}:")
                if isinstance(v, (dict, list)):
                    extract(v)
                else:
                    arr.append(v)
        elif isinstance(obj, list):
            for item in obj:
                extract(item)
        return arr

    values = extract(obj)
    return ''.join(values)


def release_notes_to_str(changelog):

    release_notes = changelog.get('releaseNotes')
    release_notes = re.sub('[#\n]', "", release_notes)
    return f"{changelog.get('displayName')}, Release Notes: {release_notes}"


def flattenCell(data, is_pretty=True):
    """
       Flattens a markdown table cell content into a single string

       :type data: ``str`` or ``list``
       :param data: The cell content (required)

       :type is_pretty: ``bool``
       :param is_pretty: Should cell content be pretified (default is True)

       :return: A sting representation of the cell content
       :rtype: ``str``
    """
    indent = 4 if is_pretty else None
    if isinstance(data, STRING_TYPES):
        return data
    elif isinstance(data, list):
        string_list = []
        for d in data:
            try:
                if IS_PY3 and isinstance(d, bytes):
                    string_list.append(d.decode('utf-8'))
                else:
                    string_list.append(str(d))
            except UnicodeEncodeError:
                string_list.append(d.encode('utf-8'))

        return ',\n'.join(string_list)
    else:
        return json.dumps(data, indent=indent, ensure_ascii=False)


def formatCell(data, is_pretty=True):
    """
       Convert a given object to md while decending multiple levels

       :type data: ``str`` or ``list``
       :param data: The cell content (required)

       :type is_pretty: ``bool``
       :param is_pretty: Should cell content be prettified (default is True)

       :return: The formatted cell content as a string
       :rtype: ``str``
    """
    if isinstance(data, STRING_TYPES):
        return data
    elif isinstance(data, dict):
        return '\n'.join([u'{}: {}'.format(k, flattenCell(v, is_pretty)) for k, v in data.items()])
    else:
        return flattenCell(data, is_pretty)


def table_to_md(name, t, headers=None, headerTransform=None, removeNull=False, metadata=None, url_keys=None,
                date_fields=None):
    """
       Converts a demisto table in JSON form to a Markdown table

       :type name: ``str``
       :param name: The name of the table (required)

       :type t: ``dict`` or ``list``
       :param t: The JSON table - List of dictionaries with the same keys or a single dictionary (required)

       :type headers: ``list`` or ``string``
       :param headers: A list of headers to be presented in the output table (by order). If string will be passed
            then table will have single header. Default will include all available headers.

       :type headerTransform: ``function``
       :param headerTransform: A function that formats the original data headers (optional)

       :type removeNull: ``bool``
       :param removeNull: Remove empty columns from the table. Default is False

       :type metadata: ``str``
       :param metadata: Metadata about the table contents

       :type url_keys: ``list``
       :param url_keys: a list of keys in the given JSON table that should be turned in to clickable

       :type date_fields: ``list``
       :param date_fields: A list of date fields to format the value to human-readable output.

       :return: A string representation of the markdown table
       :rtype: ``str``
    """
    # Turning the urls in the table to clickable
    if url_keys:
        t = url_to_clickable_markdown(t, url_keys)

    mdResult = ''
    if name:
        mdResult = '### ' + name + '\n'

    if metadata:
        mdResult += metadata + '\n'

    if not t or len(t) == 0:
        mdResult += '**No entries.**\n'
        return mdResult

    if not headers and isinstance(t, dict) and len(t.keys()) == 1:
        # in case of a single key, create a column table where each element is in a different row.
        headers = list(t.keys())
        t = list(t.values())[0]

    if not isinstance(t, list):
        t = [t]

    if headers and isinstance(headers, STRING_TYPES):
        headers = [headers]

    if not isinstance(t[0], dict):
        # the table contains only simple objects (strings, numbers)
        # should be only one header
        if headers and len(headers) > 0:
            header = headers[0]
            t = [{header: item} for item in t]
        else:
            raise Exception("Missing headers param for tableToMarkdown. Example: headers=['Some Header']")

    # in case of headers was not provided (backward compatibility)
    if not headers:
        headers = list(t[0].keys())
        headers.sort()

    if removeNull:
        headers_aux = headers[:]
        for header in headers:
            if all(obj.get(header) in ('', None, [], {}) for obj in t):
                headers_aux.remove(header)
        headers = headers_aux

    if t and len(headers) > 0:
        newHeaders = []
        if headerTransform is None:  # noqa
            def headerTransform(s): return stringEscapeMD(s, True, True)  # noqa
        for header in headers:
            newHeaders.append(headerTransform(header))
        mdResult += '|'
        if len(newHeaders) == 1:
            mdResult += newHeaders[0]
        else:
            mdResult += '|'.join(newHeaders)
        mdResult += '|\n'
        sep = '---'
        mdResult += '|' + '|'.join([sep] * len(headers)) + '|\n'
        for entry in t:
            entry_copy = entry.copy()
            if date_fields:
                for field in date_fields:
                    try:
                        entry_copy[field] = datetime.fromtimestamp(int(entry_copy[field]) / 1000).strftime(
                            '%Y-%m-%d %H:%M:%S')
                    except Exception:
                        pass

            vals = [stringEscapeMD((formatCell(entry_copy.get(h, ''), False) if entry_copy.get(h) is not None else ''),
                                   True, True) for h in headers]

            # this pipe is optional
            mdResult += '| '
            try:
                mdResult += ' | '.join(vals)
            except UnicodeDecodeError:
                vals = [str(v) for v in vals]
                mdResult += ' | '.join(vals)
            mdResult += ' |\n'

    else:
        mdResult += '**No entries.**\n'

    return mdResult


def main():
    args = demisto.args()
    value = args.get('value')
    title = args.get('title')
    headers = argToList(args.get('headers'))
    markdown = table_to_md(title, value, headers=headers)

    return_results(markdown)


if __name__ in ['__builtin__', 'builtins']:
    main()
