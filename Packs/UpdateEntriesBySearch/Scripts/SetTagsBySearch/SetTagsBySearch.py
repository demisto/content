import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import fnmatch
import re
from typing import Any, Dict, Iterator, List, Tuple


def to_string(value: Any) -> Optional[str]:
    if isinstance(value, (List, Dict)) or value is None:
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
                 node_paths: List[str], filter_entry_formats: List[str], filter_entry_types: List[str],
                 filter_user_type: List[str]):
        """
        Initialize the filter with the matching conditions.

        :param include_pattern: A pattern to perform matching.
        :param exclude_pattern: A pattern to exclude.
        :param node_paths: The list of node path of entries to which the pattern matching is performed.
        :param filter_entry_formats: The list of entry format to filter entries.
        :param filter_entry_types: The list of entry type to filter entries.
        :param filter_user_type: The list of user type to filter entries.
        """
        self.__include_pattern = include_pattern
        self.__exclude_pattern = exclude_pattern
        self.__node_paths = node_paths
        self.__filter_entry_formats = filter_entry_formats
        self.__filter_entry_types = [to_entry_type_code(f) for f in filter_entry_types]
        self.__filter_user_type = filter_user_type

        # Check content format name
        for f in filter_entry_formats:
            if not EntryFormat.is_valid_type(f):
                raise ValueError(f'Invalid entry format: {f}')

    def match(self, entry: Dict[str, Any]) -> Optional[Tuple[re.Match, str]]:
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

        if self.__filter_user_type:
            user = demisto.get(entry, 'Metadata.user') or ''
            if (user and ('user' not in self.__filter_user_type)) or \
               ((not user) and ('dbot' not in self.__filter_user_type)):
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
    def __init__(self, entry: Dict[str, Any], match: Optional[re.Match], value_matched: Optional[str]):
        self.entry = entry
        self.match = match
        self.value_matched = value_matched


def iterate_entries(incident_id: Optional[str], query_filter: Dict[str, Any],
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
            filter_entry_types=argToList(args.get('filter_entry_types', [])),
            filter_user_type=argToList(args.get('filter_user_type', []))
        )
    ):
        if entry.entry['ID'] not in exclude_ids:
            rent = {
                'ID': entry.entry['ID'],
                'Tags': entry.entry['Tags'] or [],
            }
            if 'verbose' == output_option and entry.match:
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
        action = args.get('action', 'add')
        dry_run = argToBoolean(args.get('dry_run', False))

        if action == 'add':
            tags = argToList(args.get('tags', []))
            for ent in ents:
                ent['Modified'] = True if set(tags) - set(ent['Tags']) else False
                ent['Tags'] = ','.join(list(set(tags + ent['Tags'])))

            if not dry_run:
                for ent in ents:
                    if ent['Modified']:
                        entry_id = ent['ID']
                        res = demisto.executeCommand('setEntriesTags', {
                            'entryIDs': entry_id,
                            'entryTags': ent['Tags']
                        })
                        if not res or is_error(res[0]):
                            return_error(f'Failed to set tags: entryID={entry_id}')

        elif action == 'replace':
            tags = list(set(argToList(args.get('tags', []))))
            for ent in ents:
                ent['Modified'] = set(tags) != set(ent['Tags'])
                ent['Tags'] = ','.join(tags)

            if not dry_run:
                ent_ids = [ent['ID'] for ent in ents if ent['Modified']]
                if ent_ids:
                    res = demisto.executeCommand('setEntriesTags', {
                        'entryIDs': ent_ids,
                        'entryTags': ','.join(tags)
                    })
                    if not res or is_error(res[0]):
                        return_error('Failed to set tags')

        else:
            raise ValueError(f'Invalid action name: {action}')

        md = f'**Matched entries:** {len(ents)}'
        if output_option != 'quiet':
            header = assign_params(
                ID='Entry ID',
                Tags='Tags',
                Modified='Modified',
                Where='Where' if 'verbose' == output_option else None,
                Text='Text' if 'verbose' == output_option else None
            )
            md += '\n' + tblToMd('', ents, headers=header.keys(), headerTransform=lambda h: header.get(h, ''))
        return_outputs(md)


if __name__ in ('__builtin__', 'builtins'):
    main()
