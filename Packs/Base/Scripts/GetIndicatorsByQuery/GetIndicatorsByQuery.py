from CommonServerPython import *

import hashlib

PAGE_SIZE = 500

RANDOM_UUID = str(demisto.args().get('addRandomSalt', '').encode('utf8'))
# Memo for key matching
CACHE = {}  # type: ignore


def hash_value(simple_value):
    if not isinstance(simple_value, str):
        simple_value = str(simple_value)
    if simple_value.lower() in ["none", "null"]:
        return None
    return hashlib.md5(simple_value.encode('utf8') + RANDOM_UUID.encode('utf8')).hexdigest()    # nosec


def pattern_match(pattern, s):
    regex = re.compile(pattern.replace("*", ".*"))
    return re.match(regex, s) is not None


def is_key_match_fields_to_hash(key, fields_to_hash):
    if key is None:
        return False

    if key in CACHE:
        return CACHE[key]
    for field in fields_to_hash:
        if pattern_match(field, key):
            CACHE[key] = True
            return True
    return False


def hash_multiple(value, fields_to_hash, to_hash=False):
    if isinstance(value, list):
        return [hash_multiple(x, fields_to_hash, to_hash) for x in value]
    if isinstance(value, dict):
        for k, v in value.items():
            _hash = to_hash or is_key_match_fields_to_hash(k, fields_to_hash)
            value[k] = hash_multiple(v, fields_to_hash, _hash)
        return value
    else:
        try:
            if isinstance(value, int | float | bool):
                to_hash = False
            if not isinstance(value, str):
                value = str(value)
        except Exception:
            value = ""
        if to_hash and value:
            return hash_value(value)
        else:
            return value


def parse_ioc(ioc):
    global fields_to_hash, unpopulate_fields, populate_fields
    # flat
    cf = ioc.pop('CustomFields', {}) or {}
    ioc.update(cf)
    new_ioc = {}
    for k, v in ioc.items():
        if v in ["0001-01-01T00:00:00Z"]:
            continue
        if populate_fields:
            if k in populate_fields:
                new_ioc[k] = v
        else:
            if unpopulate_fields:
                if k not in unpopulate_fields:
                    new_ioc[k] = v
            else:
                new_ioc[k] = v

    ioc = new_ioc
    if fields_to_hash and is_key_match_fields_to_hash(k, fields_to_hash):
        ioc = hash_multiple(ioc, fields_to_hash)

    return ioc


def find_indicators_with_limit_loop(indicator_query: str, limit: int):
    """
    Finds indicators using while loop with demisto.searchIndicators, and returns result and last page
    """
    iocs: List[dict] = []
    demisto.debug(f"Searching indicators with {indicator_query=} and {populate_fields=}.")
    search_indicators = IndicatorsSearcher(
        query=indicator_query,
        limit=limit,
        size=PAGE_SIZE,
        filter_fields=",".join(populate_fields) if populate_fields else None,
    )

    for ioc_res in search_indicators:
        fetched_iocs = ioc_res.get('iocs') or []
        iocs.extend(fetched_iocs)
    demisto.debug(f"Received {len(iocs)} results from server. Parsing.")

    return [parse_ioc(x) for x in iocs]


def get_parsed_populated_fields(fields_to_parse: list[str]) -> frozenset | None:
    """ Gets a list of fields to populate for an indicator and parse it according to specific requirements."""
    # Due to using the always populated field and no ability to provide None value in the UI, we allow an explicit override.

    if "ALL" in fields_to_parse:
        demisto.debug("All fields are requested. populated_field argument is set to None.")

        return None

    new_fields = [field for field in fields_to_parse if field]

    # Due to a server bug where API request an result non-matching names, we allow this "non existing" field.
    if "RelatedIncCount" in new_fields:
        new_fields.append("investigationsCount")

    demisto.debug(f"User's fields to populate: {new_fields}.")
    return frozenset(new_fields)


fields_to_hash, unpopulate_fields, populate_fields = [], [], []  # type: ignore


def main():
    global fields_to_hash, unpopulate_fields, populate_fields
    args = demisto.args()
    fields_to_hash = frozenset([x for x in argToList(args.get('fieldsToHash', '')) if x])  # type: ignore
    unpopulate_fields = frozenset([x for x in argToList(args.get('dontPopulateFields', '')) if x])  # type: ignore
    populate_fields = get_parsed_populated_fields(argToList(args.get('populateFields', '')))  # type: ignore

    limit = int(args.get('limit', PAGE_SIZE))
    query = args.get('query', '')
    offset = int(args.get('offset', 0))
    indicators = find_indicators_with_limit_loop(query, limit + offset)[offset:offset + limit]

    entry = fileResult("indicators.json", json.dumps(indicators).encode('utf8'))
    entry['Contents'] = indicators
    entry['ContentsFormat'] = formats['json']
    entry['HumanReadable'] = f'Fetched {len(indicators)} indicators successfully by the query: {query}'

    return entry


if __name__ in ['__main__', '__builtin__', 'builtins']:
    demisto.results(main())
