import csv

from CommonServerPython import *

reload(sys)  # type: ignore
sys.setdefaultencoding('utf8')  # pylint: disable=E1101
codec_type = demisto.args().get('codec', 'utf-8')


def remove_non_printable_chars(s):
    """
    removes
    'ZERO WIDTH SPACE' (U+200B)
    'ZERO WIDTH NO-BREAK SPACE' (U+FEFF)
    """
    return s.replace(u'\ufeff', '').replace(u'\u200f', '')


def unicode_dict_reader(csv_data, **kwargs):
    """
    reads from csv file each row and converts to array of dictionaries.
    in case there are extra fields in a row and they have no column, then we will create NO_NAME_COLUMN_{NUMBER}

    CSV Example:
    aaa,bbb
    1,2
    3,4,5

    ===>

    [
        {
            "aaa": 1,
            "bbb": 2,
            "NO_NAME_COLUMN_3": ""
        },
        {
            "aaa": 3,
            "bbb": 4,
            "NO_NAME_COLUMN_3": 5       <-- extra field/column
        }
    ]
    """
    csv_reader = csv.DictReader((line.replace('\0', '') for line in csv_data), **kwargs)
    arr = []
    no_name_columns_counter = 0
    for row in csv_reader:
        row_dict = {}

        for key, value in row.iteritems():
            if key is None:
                # if the key is None it means there are fields in the row which has no column name
                # so we create NO_NAME_COLUMN_{} column
                if not isinstance(value, list):
                    value = [value]

                counter = 0
                for val in value:
                    col_name = 'NO_NAME_COLUMN_{}'.format(counter)
                    row_dict[col_name] = unicode(val, codec_type)
                    counter += 1

                if no_name_columns_counter < counter:
                    no_name_columns_counter = counter

            elif value is not None:
                col_name = remove_non_printable_chars(unicode(key, codec_type))
                row_dict[col_name] = unicode(value, codec_type)
            else:
                col_name = remove_non_printable_chars(unicode(key, codec_type))
                row_dict[col_name] = None

        arr.append(row_dict)

    if no_name_columns_counter > 0:
        """
        adding NO_NAME_COLUMN_{} to the first dict in the array
        so that later in tableToMarkdown it will print all the columns
        """
        first_row = arr[0]
        for counter in range(no_name_columns_counter):
            first_row['NO_NAME_COLUMN_{}'.format(counter)] = ""

    return arr


def get_entry_by_file_name(file_name):
    entries = demisto.executeCommand('getEntries', {})
    for entry in reversed(entries):
        fn = demisto.get(entry, 'File')

        if type(fn) not in [unicode, str]:
            continue

        if file_name.lower() == fn.lower():
            return entry
    raise ValueError('Was unable to find "{}" in the war room. Please ensure the file was uploaded.'.format(file_name))


csv_entry = None
ip_count = 0
domain_count = 0
hash_count = 0


def is_one_dimension_list(all_csv):
    """ Checks if given list is one dimensional

    Args:
        all_csv (list): list of csv entries

    Returns:
        bool: True if all strings (one dimension list) or False if not
    """
    return all(isinstance(entry, STRING_TYPES) for entry in all_csv) or not all_csv


def main():
    ip_list = []
    domain_list = []
    hash_list = []
    d_args = demisto.args()

    entry_id = d_args['entryID'] if 'entryID' in d_args else None
    file_name = d_args['file'] if 'file' in d_args else None  # file arg deprecated
    parse_ip = int(d_args['ips']) if 'ips' in d_args else -1
    parse_domain = int(d_args['domains']) if 'domains' in d_args else -1
    parse_hash = int(d_args['hashes']) if 'hashes' in d_args else -1
    parse_all = True if d_args['parseAll'] == 'yes' else False

    if parse_ip == -1 and parse_domain == -1 and parse_hash == -1 and not parse_all:
        return_error('Select a field to extract or set parseAll=yes to parse the whole CSV file')

    if file_name is None and entry_id is None:
        return_error('Please provide entryID.')

    if entry_id is None:
        # search entry by file name
        try:
            entry = get_entry_by_file_name(file_name)
            entry_id = entry['ID']
        except ValueError as e:
            return_error(e.message)

    res = demisto.getFilePath(entry_id)
    if not res:
        return_error("Entry {} not found".format(entry_id))

    file_path = res['path']
    file_name = res['name']
    if not file_name.lower().endswith('.csv'):
        return_error(
            '"{}" is not in csv format. Please ensure the file is in correct format and has a ".csv" extension'.format(
                file_name))

    if parse_all:
        all_csv = []
        with open(file_path) as f:
            records = unicode_dict_reader(f)
            # `records` is a list contains CSV rows (without headers)
            # so if it doesn't exists - it can be empty or one-lined CSV
            if records:
                for row in records:
                    all_csv.append(row)
            else:  # Can be one-line csv
                f.seek(0)
                line = f.read()
                all_csv = line.split(',')

        output = {
            'ParseCSV.ParsedCSV': all_csv
        }
        if is_one_dimension_list(all_csv):
            human_readable = tableToMarkdown(file_name, all_csv, headers=["CSV list"])
        else:
            human_readable = tableToMarkdown(file_name, all_csv)
        demisto.results({
            "Type": entryTypes["note"],
            "ContentsFormat": formats["json"],
            "ReadableContentsFormat": formats["markdown"],
            "Contents": all_csv,
            "EntryContext": output,
            "HumanReadable": human_readable
        })

    elif not (parse_ip == -1 and parse_domain == -1 and parse_hash == -1):
        # if need to parse ips/domains/hashes, keep the script running
        if sum(1 for line in open(file_path)) <= 1:  # checks if there are less than one line
            return_error('No data to parse. CSV file might be empty or one-lined. try the `ParseAll=yes` argument.')

        with open(file_path, 'rU') as f:
            has_header = csv.Sniffer().has_header(f.read(1024))
            f.seek(0)
            csv_data = csv.reader(f)

            if has_header:
                next(csv_data)

            md = '### Parsed Data Table\n' + ('IPs |' if 'ips' in d_args else '') + (
                'Domains |' if 'domains' in d_args else '') + ('Hashes |' if 'hashes' in d_args else '') + '\n'
            md += ('- |' if 'ips' in d_args else '') + ('- |' if 'domains' in d_args else '') + (
                '- |' if 'hashes' in d_args else '') + '\n'
            content = ''

            for row in csv_data:
                content += ','.join(row) + '\n'
                if parse_ip != -1:
                    md += (row[parse_ip] + '|' if row[parse_ip] else ' |')
                    is_ip = re.search(r'([0-9]{1,3}\.){3}[0-9]{1,3}', row[parse_ip])
                    is_valid = is_ip_valid(row[parse_ip])
                    if is_ip and is_valid:
                        ip_list.append(row[parse_ip])

                if parse_domain != -1:
                    md += (row[parse_domain] + '|' if row[parse_domain] else ' |')
                    has_dot = '.' in row[parse_domain]
                    no_spaces = ' ' not in row[parse_domain]
                    if has_dot and no_spaces:
                        domain_list.append(row[parse_domain])

                if parse_hash != -1:
                    md += (row[parse_hash] + '|' if row[parse_hash] else ' |')
                    is_hash = re.search(r'[0-9A-Fa-f]{32,128}', row[parse_hash])
                    if is_hash:
                        hash_list.append(row[parse_hash])
                md += '\n'

        context = {}  # type: dict
        if ip_list:
            old_ip_list = list(demisto.get(demisto.context(), 'ips')) if demisto.get(demisto.context(), 'ips') else []
            ip_list = list(set(ip_list) - set(old_ip_list))
            if len(ip_list) > 0:
                context["IP"] = []
                for ip in ip_list:
                    context["IP"].append({"Address": ip})

        if domain_list:
            old_domain_list = list(demisto.get(demisto.context(), 'domains')) if demisto.get(demisto.context(),
                                                                                             'domains') else []
            domain_list = list(set(domain_list) - set(old_domain_list))
            if len(domain_list) > 0:
                context["Domain"] = []
                for domain in domain_list:
                    context["Domain"].append({"Name": domain})

        if hash_list:
            old_hash_list = list(demisto.get(demisto.context(), 'hashes')) if demisto.get(demisto.context(),
                                                                                          'hashes') else []
            hash_list = list(set(hash_list) - set(old_hash_list))
            if len(hash_list) > 0:
                context["File"] = []
                for hash_string in hash_list:
                    if len(hash_string) == 32:
                        context["File"].append({"MD5": hash_string})
                    if len(hash_string) == 64:
                        context["File"].append({"SHA256": hash_string})
                    if len(hash_string) == 40:
                        context["File"].append({"SHA1": hash_string})

        demisto.results({
            "Type": entryTypes["note"],
            "ContentsFormat": formats["text"],
            "Contents": content,
            "HumanReadable": md,
            "EntryContext": context
        })


if __name__ in ('__builtin__', 'builtins'):
    main()
