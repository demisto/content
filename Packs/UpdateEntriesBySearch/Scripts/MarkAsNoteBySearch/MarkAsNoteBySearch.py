import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import fnmatch
import re
from typing import Any
from collections.abc import Iterator


def to_string(value: Any) -> Optional[str]:
    if isinstance(value, (list, dict)) or value is None:
        return None
    try:
        return str(value)
    except ValueError:
        return None


def to_entry_type_code(name: str) -> int:
    etype = {
        'NOTE': EntryType.NOTE,
        'ERROR': EntryType.ERROR
    }.get(name)

    if etype is None:
        raise ValueError(f'Invalid entry type: {name}')
    return etype


def build_pattern(pattern_algorithm: str, pattern: str, case_insensitive: bool) -> re.Pattern[str]:
    """
    Build a matching object from the pattern given.

    :param pattern_algorithm: A pattern matching algorithm.
    :param pattern: A pattern text.
    :param case_insensitive: True if the matching is performed in case-insensitive, False otherwise.
    :return A matching object built.
    """
    if pattern_algorithm == 'basic':
        pattern = re.escape(pattern)
    elif pattern_algorithm == 'wildcard':
        pattern = fnmatch.translate(pattern)
    elif pattern_algorithm == 'regex':
        pass
    else:
        raise ValueError(f'Invalid pattern algorithm: {pattern_algorithm}')

    return re.compile(pattern, re.IGNORECASE if case_insensitive else 0)


class EntryFilter:
    def __init__(self, include_pattern: re.Pattern[str], exclude_pattern: Optional[re.Pattern[str]],
                 node_paths: list[str], filter_entry_formats: list[str], filter_entry_types: list[str]):
        """
        Initialize the filter with the matching conditions.

        :param include_pattern: A pattern to perform matching.
        :param exclude_pattern: A pattern to exclude.
        :param node_paths: The list of node path of entries to which the pattern matching is performed.
        :param filter_entry_formats: The list of entry format to filter entries.
        :param filter_entry_types: The list of entry type to filter entries.
        """
        self.__include_pattern = include_pattern
        self.__exclude_pattern = exclude_pattern
        self.__node_paths = node_paths
        self.__filter_entry_formats = filter_entry_formats
        self.__filter_entry_types = [to_entry_type_code(f) for f in filter_entry_types]

        # Check content format name
        for f in filter_entry_formats:
            if not EntryFormat.is_valid_type(f):
                raise ValueError(f'Invalid entry format: {f}')

    def match(self, entry: dict[str, Any]) -> Optional[tuple[re.Match, str]]:
        """
        Search the entry for the pattern.

        :param entry: The entry data.
        :return: re.Match and the target string if the pattern matched with the entry, None otherwise.
        """
        def iterate_value(value: Any) -> Iterator[Any]:
            if isinstance(value, list):
                for v in value:
                    yield from iterate_value(v)

            elif isinstance(value, dict):
                for k, v in value.items():
                    yield from iterate_value(v)
            else:
                yield value

        if self.__filter_entry_types and entry.get('Type') not in self.__filter_entry_types:
            return None

        if self.__filter_entry_formats and \
                entry.get('ContentsFormat') not in self.__filter_entry_formats:
            return None

        matched = None
        for node_path in self.__node_paths:
            for val in iterate_value(demisto.get(entry, node_path)):
                s = to_string(val)
                if s is not None:
                    if self.__exclude_pattern and self.__exclude_pattern.search(s):
                        return None

                    if not matched:
                        m = self.__include_pattern.search(s)
                        if m:
                            matched = (m, s)
        return matched


class Entry:
    def __init__(self, entry: dict[str, Any], match: Optional[re.Match], value_matched: Optional[str]):
        self.entry = entry
        self.match = match
        self.value_matched = value_matched


def iterate_entries(incident_id: Optional[str], query_filter: dict[str, Any],
                    entry_filter: Optional[EntryFilter] = None) -> Iterator[Entry]:
    """
    Iterate war room entries

    :param incident_id: The incident ID to search entries from.
    :param query_filter: Filters to search entries.
    :param entry_filter: Filters to filter entries.
    :return: An iterator to retrieve entries.
    """
    query_filter = dict(**query_filter)
    first_id = 1
    while True:
        query_filter['firstId'] = str(first_id)

        ents = demisto.executeCommand('getEntries', assign_params(
            id=incident_id,
            filter=query_filter
        ))
        if not ents:
            break

        if is_error(ents[0]):
            if first_id == 1:
                return_error('Unable to retrieve entries')
            break

        for ent in ents:
            if not entry_filter:
                yield Entry(ent, None, None)
            else:
                match = entry_filter.match(ent)
                if match:
                    yield Entry(ent, match[0], match[1])

        # Set the next ID
        last_id = ent['ID']
        m = re.match('([0-9]+)', last_id)
        if not m:
            raise ValueError(f'Invalid entry ID: {last_id}')
        next_id = int(m[1]) + 1
        if next_id <= first_id:
            break
        first_id = next_id


def main():
    args = demisto.args()

    build_pattern_args = assign_params(
        pattern_algorithm=args.get('algorithm', 'basic'),
        case_insensitive=argToBoolean(args.get('case_insensitive', False))
    )
    build_pattern_args['pattern'] = args['pattern']
    include_pattern = build_pattern(**build_pattern_args)
    exclude_pattern = None
    if args.get('exclude_pattern'):
        build_pattern_args['pattern'] = args['exclude_pattern']
        exclude_pattern = build_pattern(**build_pattern_args)

    filter_options = argToList(args.get('filter_options', []))
    output_option = args.get('summary', 'basic')

    exclude_ids = []
    if 'exclude_this_entry' in filter_options:
        exclude_ids.append(demisto.parentEntry()['id'])

    ents = []
    for entry in iterate_entries(
        incident_id=args.get('incident_id'),
        query_filter=assign_params(
            categories=argToList(args.get('filter_categories')),
            tags=argToList(args.get('filter_tags'))
        ),
        entry_filter=EntryFilter(
            include_pattern=include_pattern,
            exclude_pattern=exclude_pattern,
            node_paths=argToList(args.get('node_paths', 'Contents')),
            filter_entry_formats=argToList(args.get('filter_entry_formats', [])),
            filter_entry_types=argToList(args.get('filter_entry_types', []))
        )
    ):
        if entry.entry['ID'] not in exclude_ids:
            rent = {
                'ID': entry.entry['ID']
            }
            if output_option == 'verbose' and entry.match:
                rent['Where'] = entry.match[0][:128]
                rent['Text'] = entry.value_matched
            ents.append(rent)

    if 'first_entry' in filter_options:
        if 'last_entry' in filter_options:
            del ents[1:-1]
        else:
            ents = ents[:1]
    elif 'last_entry' in filter_options:
        ents = ents[-1:]

    if not ents:
        return_outputs('No entries matched')
    else:
        if not argToBoolean(args.get('dry_run', False)):
            mark = argToBoolean(args.get('mark', True))
            res = demisto.executeCommand('markAsNote', {
                'entryIDs': [ent['ID'] for ent in ents],
                'isNote': mark
            })
            if not res or is_error(res[0]):
                return_error('Failed to mark entries as note')

        md = f'**Matched entries:** {len(ents)}'
        if output_option != 'quiet':
            header = assign_params(
                ID='Entry ID',
                Where='Where' if output_option == 'verbose' else None,
                Text='Text' if output_option == 'verbose' else None
            )
            md += '\n' + tblToMd('', ents, headers=header.keys(), headerTransform=lambda h: header.get(h, ''))
        return_outputs(md)


if __name__ in ('__builtin__', 'builtins'):
    main()
