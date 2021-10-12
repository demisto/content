from CommonServerPython import *

import hashlib
from dateutil import parser

PAGE_SIZE = 500

RANDOM_UUID = str(demisto.args().get('addRandomSalt', '').encode('utf8'))
# Memo for key matching
CACHE = {}  # type: ignore


def hash_value(simple_value):
    if not isinstance(simple_value, str):
        simple_value = str(simple_value)
    if simple_value.lower() in ["none", "null"]:
        return None
    return hashlib.md5(simple_value.encode('utf8') + RANDOM_UUID.encode('utf8')).hexdigest()


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
        return list(map(lambda x: hash_multiple(x, fields_to_hash, to_hash), value))
    if isinstance(value, dict):
        for k, v in value.items():
            _hash = to_hash or is_key_match_fields_to_hash(k, fields_to_hash)
            value[k] = hash_multiple(v, fields_to_hash, _hash)
        return value
    else:
        try:
            if isinstance(value, (int, float, bool)):
                to_hash = False
            if not isinstance(value, str):
                value = str(value)
        except Exception:
            value = ""
        if to_hash and value:
            return hash_value(value)
        else:
            return value


def find_indicators_with_limit(indicator_query: str, limit: int, offset: int, from_date: str) -> list:
    """
    Finds indicators using demisto.searchIndicators
    """
    # calculate the starting page (each page holds 200 entries)
    if offset:
        next_page = int(offset / PAGE_SIZE)

        # set the offset from the starting page
        offset_in_page = offset - (PAGE_SIZE * next_page)

    else:
        next_page = 0
        offset_in_page = 0

    iocs, _ = find_indicators_with_limit_loop(indicator_query, limit, next_page=next_page, from_date=from_date)

    # if offset in page is bigger than the amount of results returned return empty list
    if len(iocs) <= offset_in_page:
        return []

    return iocs[offset_in_page:limit + offset_in_page]


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


def find_indicators_with_limit_loop(indicator_query: str, limit: int, from_date:str, total_fetched: int = 0,
                                    next_page: int = 0, last_found_len: int = PAGE_SIZE):
    """
    Finds indicators using while loop with demisto.searchIndicators, and returns result and last page
    """
    iocs: List[dict] = []
    search_indicators = IndicatorsSearcher(page=next_page)
    if not last_found_len:
        last_found_len = total_fetched
    while last_found_len == PAGE_SIZE and limit and total_fetched < limit:
        fetched_iocs = search_indicators.search_indicators_by_version(query=indicator_query, size=PAGE_SIZE,
                                                                      from_date=from_date).get('iocs')
        iocs.extend(fetched_iocs)
        last_found_len = len(fetched_iocs)
        total_fetched += last_found_len
    return list(map(lambda x: parse_ioc(x), iocs)), next_page


def parse_relative_time(datetime_str):
    if datetime_str:
        datetime_str = datetime_str.lower()
        try:
            res = re.search("([0-9]+) (minute|minutes|hour|hours|day|days|week|weeks|month|months|year|years) ago",
                            datetime_str)
            if res:
                number = int(res.group(1))
                unit = res.group(2)
                if unit in ['minute', 'hour', 'day', 'week', 'month', 'year']:
                    unit += "s"
                if unit == 'years':
                    unit = 'days'
                    number *= 365
                elif unit == 'months':
                    number *= 43800
                    unit = 'minutes'

                kargs = {}
                kargs[unit] = int(number)
                result = datetime.now() - timedelta(**kargs)
                return result
        except Exception:
            return None


def get_demisto_datetme_format(date_string):
    if date_string:
        date_object = None
        # try to parse date string
        try:
            date_object = parser.parse(date_string)
        except Exception:
            pass
        # try to parse relative time
        if date_object is None and date_string.strip().endswith("ago"):
            date_object = parse_relative_time(date_string)

        if date_object:
            return date_object.astimezone().isoformat('T')
        else:
            return None


fields_to_hash, unpopulate_fields, populate_fields = [], [], []  # type: ignore


def main():
    global fields_to_hash, unpopulate_fields, populate_fields
    args = demisto.args()
    fields_to_hash = frozenset([x for x in argToList(args.get('fieldsToHash', '')) if x])  # type: ignore
    unpopulate_fields = frozenset([x for x in argToList(args.get('dontPopulateFields', ''))])  # type: ignore
    populate_fields = frozenset([x for x in argToList(args.get('populateFields', ''))])  # type: ignore
    limit = int(args.get('limit', PAGE_SIZE))
    query = args.get('query', '')
    offset = int(args.get('offset', 0))
    from_date = args.get('fromDate')
    from_date = get_demisto_datetme_format(from_date)
    indicators = find_indicators_with_limit(query, limit, offset, from_date)

    entry = fileResult("indicators.json", json.dumps(indicators).encode('utf8'))
    entry['Contents'] = indicators
    entry['ContentsFormat'] = formats['json']
    entry['HumanReadable'] = f'Fetched {len(indicators)} indicators successfully by the query: {query}'

    return entry


if __name__ in ['__main__', '__builtin__', 'builtins']:
    demisto.results(main())
