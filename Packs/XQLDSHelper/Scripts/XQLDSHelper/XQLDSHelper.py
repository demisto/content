import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re
import enum
import pytz
import gzip
import math
import base64
import hashlib
import dateparser
import itertools
import colorsys
import traceback
import urllib.parse
from collections import defaultdict
from collections.abc import Iterable, Hashable


DEFAULT_POLLING_INTERVAL = 10  # in seconds
DEFAULT_RETRY_INTERVAL = 10  # in seconds
DEFAULT_RETRY_MAX = 10
DEFAULT_QUERY_TIMEOUT_DURATION = 60  # in seconds


def to_float(
    val: Any
) -> float | int:
    """ Ensure the value is of type number (float or int).

    :param val: The value.
    :return: A float or int converted from `val`.
    """
    if val is None:
        return 0
    try:
        val = float(val)
        return int(val) if val.is_integer() else val
    except (ValueError, TypeError):
        return 0


def to_str(
    val: Any
) -> str:
    """ Ensure the value is of type string.

    :param val: The value.
    :return: A str converted from `val`.
    """
    return val if isinstance(val, str) else json.dumps(val)


class CacheType(enum.StrEnum):
    NONE = 'none'
    RECORDSET = 'recordset'
    ENTRY = 'entry'


class DefaultEntryScope(enum.StrEnum):
    NO_RECORDSET = 'no_recordset'
    QUERY_SKIPPED = 'query_skipped'


class ContextData:
    def __init__(
        self,
        context: dict[str, Any] | None = None,
        incident: dict[str, Any] | None = None,
        alert: dict[str, Any] | None = None,
        value: dict[str, Any] | None = None,
    ) -> None:
        self.__context: dict[str, Any] = context or {}
        self.__value: dict[str, Any] = value or {}
        self.__specials: dict[str, Any] = {
            'alert': alert or {},
            'incident': incident or {},
            'lists': None,
        }

    def get(
        self,
        key: str | None = None
    ) -> Any:
        """ Get the context value

        :param key: The dt expressions (string within ${}).
        :return: The value.
        """
        if not key:
            return None

        if key != '.' and not key.startswith('.=') and key.startswith('.'):
            dx = self.__value
            key = key[1:]
        else:
            for prefix in self.__specials:
                k = key[len(prefix):]
                if key.startswith(prefix) and k[:1] in ('', '.', '(', '='):
                    if prefix == 'lists':
                        if list_name := re.split('[.(=]', k[1:], maxsplit=1)[0]:
                            dx = {
                                prefix: {
                                    list_name: execute_command(
                                        'getList', {
                                            'listName': list_name
                                        }
                                    )
                                }
                            }
                            break
                    else:
                        dx = self.__specials
                        break
            else:
                dx = self.__context

        return demisto.dt(dx, key)

    def inherit(
        self,
        value: dict[str, Any] | None = None,
    ) -> "ContextData":
        """ Create a ContextData with the new value

        :param value: The new value.
        :return: ContextData created.
        """
        return ContextData(
            context=self.__context,
            incident=self.__specials.get('incident'),
            alert=self.__specials.get('alert'),
            value=value,
        )


class Formatter:
    def __init__(
        self,
        variable_substitution: tuple[str, str],
        keep_symbol_to_null: bool
    ) -> None:
        self.__keep_symbol_to_null = keep_symbol_to_null
        self.__var_opening, self.__var_closing = variable_substitution
        if not self.__var_opening:
            raise DemistoException('opening marker is required.')

    @staticmethod
    def __is_closure(
        source: str,
        ci: int,
        closure_marker: str
    ) -> bool:
        if closure_marker:
            return source[ci:ci + len(closure_marker)] == closure_marker
        else:
            c = source[ci]
            if c.isspace():
                return True
            elif c.isascii():
                return c != '_' and not c.isalnum()
            else:
                return False

    @staticmethod
    def __extract_dt(
        dtstr: str,
        dx: ContextData | None,
    ) -> Any:
        """ Extract dt expression

        :param dtstr: The dt expressions (string within ${}).
        :param dx: The context instance.
        :return: The value extracted.
        """
        try:
            return dx.get(dtstr) if dx else dtstr
        except Exception:
            return None

    def __extract(
        self,
        source: str,
        dx: ContextData | None,
        si: int,
        markers: tuple[str, str] | None,
    ) -> tuple[Any, int | None]:
        """ Extract a template text, or an enclosed value within starting and ending marks

        :param source: The template text, or the enclosed value starts with the next charactor of a start marker
        :param dx: The context data
        :param si: The index of `source` to start extracting
        :param markers: The opening and closing markers to find an end position for parsing an enclosed value.
                        It must be None when the template text is given to `source`.
        :return: The extracted value and index of `source` when parsing ended.
                 The index is the next after the end marker when extracting the enclosed value.
        """
        out = None
        ci = si
        while ci < len(source):
            if markers is not None and Formatter.__is_closure(source, ci, markers[1]):
                key = source[si:ci] if out is None else str(out) + source[si:ci]
                if markers == (self.__var_opening, self.__var_closing):
                    xval = self.__extract_dt(key, dx)
                    if xval is None and self.__keep_symbol_to_null:
                        xval = markers[0] + key + markers[1]
                    else:
                        xval = self.build(xval, dx)
                else:
                    xval = markers[0] + key + markers[1]
                return xval, ci + len(markers[1])
            elif source[ci:ci + len(self.__var_opening)] == self.__var_opening:
                xval, ei = self.__extract(
                    source=source,
                    dx=dx,
                    si=ci + len(self.__var_opening),
                    markers=(self.__var_opening, self.__var_closing),
                )
                if si != ci:
                    out = source[si:ci] if out is None else str(out) + source[si:ci]

                if ei is None:
                    xval = self.__var_opening
                    ei = ci + len(self.__var_opening)

                if out is None:
                    out = xval
                elif xval is not None:
                    out = str(out) + str(xval)
                si = ci = ei
            elif markers is None:
                ci += 1
            elif endc := {'(': ')', '{': '}', '[': ']', '"': '"', "'": "'", "`": "`"}.get(source[ci]):
                xval, ei = self.__extract(
                    source=source,
                    dx=dx,
                    si=ci + 1,
                    markers=(source[ci], endc),
                )
                if si != ci:
                    out = source[si:ci] if out is None else str(out) + source[si:ci]

                if ei is None:
                    xval = source[ci]
                    ei = ci + len(source[ci])

                if out is None:
                    out = xval
                elif xval is not None:
                    out = str(out) + str(xval)

                si = ci = ei
            elif source[ci] == '\\':
                ci += 2
            else:
                ci += 1

        if markers is not None:
            # unbalanced braces, brackets, quotes, etc.
            return None, None
        elif si >= len(source):
            return out, ci
        elif out is None:
            return source[si:], ci
        else:
            return str(out) + source[si:], ci

    def build(
        self,
        template: Any,
        context: ContextData | None
    ) -> Any:
        """ Format a text from a template including DT expressions

        :param template: The template.
        :param context: The context instance.
        :return: The text built from the template.
        """
        if isinstance(template, dict):
            return {
                self.build(k, context): self.build(v, context)
                for k, v in template.items()
            }
        elif isinstance(template, list):
            return [self.build(v, context) for v in template]
        elif isinstance(template, str):
            return self.__extract(
                source=template,
                dx=context,
                si=0,
                markers=None
            )[0] if template else ''
        else:
            return template


class SortableValue:
    """
    The custom value object class, which enables you to sort for any types of data even in different types.
    """

    def __init__(
        self,
        value: Any,
    ) -> None:
        self.__value = value

    def __lt__(
        self,
        other: Any
    ) -> bool:
        def __lt(
            obj1: Any,
            obj2: Any
        ) -> bool:
            if any(
                f(obj1) and f(obj2) for f in [
                    lambda x:isinstance(x, int | float),
                    lambda x:isinstance(x, bool),
                    lambda x:isinstance(x, str),
                ]
            ):
                return obj1 < obj2  # type: ignore[operator]
            elif obj1 is None or obj2 is None:
                return (obj2 is None) < (obj1 is None)
            else:
                def __get_order(
                    v: Any,
                ) -> int:
                    if isinstance(v, bool):
                        return 1
                    elif isinstance(v, int | float):
                        return 2
                    elif isinstance(v, str):
                        return 3
                    else:
                        return 4

                order1 = __get_order(obj1)
                order2 = __get_order(obj2)
                if n := (order1 > order2) - (order1 < order2):
                    return n < 0
                else:
                    return json.dumps(obj1) < json.dumps(obj2)

        if not isinstance(other, SortableValue):
            return False
        return __lt(self.__value, other.__value)


class QueryParams:
    def __init__(
        self,
        query_name: str,
        query_string: str,
        earliest_time: datetime,
        latest_time: datetime,
    ) -> None:
        if not query_string:
            raise DemistoException('Query string is required.')

        if earliest_time.tzinfo is None or latest_time.tzinfo is None:
            raise DemistoException('earliest_time and latest_time must be timezone aware.')

        if earliest_time > latest_time:
            raise DemistoException(
                f'latest_time ({latest_time}) must be equal to or later than'
                f' earliest_time ({earliest_time}).'
            )

        self.__query_name = query_name
        self.__query_string = '\n'.join(x.strip() for x in query_string.splitlines()).strip()
        self.__earliest_time = earliest_time
        self.__latest_time = latest_time

    @property
    def query_name(
        self,
    ) -> str:
        return self.__query_name

    @property
    def query_string(
        self,
    ) -> str:
        return self.__query_string

    def get_earliest_time_iso(
        self,
    ) -> str:
        return self.__earliest_time.isoformat(timespec='milliseconds')

    def get_latest_time_iso(
        self,
    ) -> str:
        return self.__latest_time.isoformat(timespec='milliseconds')

    def query_hash(
        self,
    ) -> str:
        # The input value doesn't include `query_name` for the hash.
        return hashlib.sha256(
            json.dumps({
                'query_string': self.query_string,
                'earliest_time': self.get_earliest_time_iso(),
                'latest_time': self.get_latest_time_iso(),
            }).encode()
        ).hexdigest()


class Cache:
    @staticmethod
    def __compress(
        val: str
    ) -> dict[Hashable, str]:
        return {
            'type': 'gz+b85',
            'data': base64.b85encode(gzip.compress(val.encode())).decode()
        }

    @staticmethod
    def build_query_params(
        query_params: QueryParams,
    ) -> dict[Hashable, Any]:
        return {
            'query_name': query_params.query_name,
            'query_string': Cache.__compress(query_params.query_string),
            'earliest_time': query_params.get_earliest_time_iso(),
            'latest_time': query_params.get_latest_time_iso(),
        }

    def __load_data(
        self,
        query_hash: str,
        cache_node: str,
    ) -> Any:
        cache = self.__context.get(self.__key)
        if not isinstance(cache, dict):
            return None

        if cache.get('QueryHash') != query_hash:
            return None

        _data = demisto.get(cache, f'{cache_node}.data')
        _type = demisto.get(cache, f'{cache_node}.type')
        if _type == 'gz+b85':
            try:
                return json.loads(
                    gzip.decompress(
                        base64.b85decode(_data.encode())
                    ).decode()
                )
            except Exception as e:
                demisto.debug(f'Failed to load cache data [{cache_node}] - {e}')
                return None
        else:
            return None

    def __save_data(
        self,
        query_params: QueryParams,
        cache_node: str,
        data: Any,
    ) -> None:
        cache = {
            'QueryParams': self.build_query_params(query_params),
            'QueryHash': query_params.query_hash(),
            cache_node: self.__compress(json.dumps(data)),
        }
        if incident_id := demisto.incident().get('id'):
            target = 'alerts' if is_xsiam() else 'incidents'
            demisto.executeCommand('executeCommandAt', {
                'command': 'Set',
                target: incident_id,
                'arguments': {
                    'key': self.__key,
                    'value': cache,
                    'append': 'false',
                }
            })

    def __init__(
        self,
        name: str,
        context: ContextData,
    ) -> None:
        name = urllib.parse.quote(name).replace('.', '%2E')
        self.__key = f'XQLDSHelperCache.{name}'
        self.__context = context

    def save_recordset(
        self,
        query_params: QueryParams,
        recordset: list[dict[Hashable, Any]],
    ) -> None:
        self.__save_data(
            query_params=query_params,
            cache_node='CacheDataset',
            data=recordset,
        )

    def save_entry(
        self,
        query_params: QueryParams,
        entry: dict[Hashable, Any],
    ) -> None:
        self.__save_data(
            query_params=query_params,
            cache_node='CacheEntry',
            data=entry,
        )

    def load_recordset(
        self,
        query_hash: str,
    ) -> list[dict[Hashable, Any]] | None:
        recordset = self.__load_data(
            query_hash=query_hash,
            cache_node='CacheDataset',
        )
        return recordset if isinstance(recordset, list) else None

    def load_entry(
        self,
        query_hash: str,
    ) -> dict[Hashable, Any] | None:
        entry = self.__load_data(
            query_hash=query_hash,
            cache_node='CacheEntry',
        )
        return entry if isinstance(entry, dict) else None


class XQLQuery:
    """
    This class executes XQL queries.
    """
    @staticmethod
    def __peek_response(
        res: list[dict[str, Any]],
    ) -> dict[Hashable, Any] | None:
        for ent in res:
            ec = ent.get('EntryContext') or {}
            for k, v in ec.items():
                k, _, _ = k.partition('(')
                if k == 'PaloAltoNetworksXQL.GenericQuery' and isinstance(v, dict):
                    return v
        return None

    @staticmethod
    def __get_response(
        res: list[dict[str, Any]],
    ) -> dict[Hashable, Any]:
        resp = XQLQuery.__peek_response(res)
        if resp is None:
            raise DemistoException(f'Unable to get query results - {res}')
        else:
            return resp

    @staticmethod
    def __get_error_message(
        res: list[dict[str, Any]],
    ) -> str | None:
        if XQLQuery.__peek_response(res) is not None:
            return None
        elif is_error(res):
            if message := get_error(res):
                return message
        else:
            for ent in res:
                if message := ent.get('HumanReadable'):
                    return message
        return f'Unable to get query results - {res}'

    def __init__(
        self,
        xql_query_instance: str | None = None,
        polling_interval: int = DEFAULT_POLLING_INTERVAL,
        retry_interval: int = DEFAULT_RETRY_INTERVAL,
        retry_max: int = DEFAULT_RETRY_MAX,
        query_timeout_duration: int = DEFAULT_QUERY_TIMEOUT_DURATION,
    ) -> None:
        self.__xql_query_instance = xql_query_instance
        self.__polling_interval = polling_interval
        self.__retry_interval = retry_interval
        self.__retry_max = max(retry_max, 0)
        self.__query_timeout_duration = max(query_timeout_duration, 0)

    def query(
        self,
        query_params: QueryParams,
    ) -> list[dict[Hashable, Any]]:
        """ Execute an XQL query and get results

        :param query_params: The query parameters.
        :return: List of fields retrieved.
        """
        # Start the query
        time_frame = f'between {query_params.get_earliest_time_iso()} and {query_params.get_latest_time_iso()}'
        demisto.debug(f'Run XQL: {query_params.query_name} {time_frame}: {query_params.query_string}')

        for retry_count in range(self.__retry_max + 1):
            res = demisto.executeCommand(
                'xdr-xql-generic-query',
                assign_params(
                    query_name=query_params.query_name,
                    query=query_params.query_string,
                    time_frame=time_frame,
                    parse_result_file_to_context='true',
                    using=self.__xql_query_instance,
                ),
            )
            error_message = self.__get_error_message(res)
            if error_message is None:
                break

            if (
                retry_count >= self.__retry_max
                or all(
                    x not in error_message for x in
                    [
                        'reached max allowed amount of parallel running queries',
                        'maximum allowed number of parallel running queries has been reached'
                    ]
                )
            ):
                raise DemistoException(
                    'Failed to execute xdr-xql-generic-query.'
                    f' Error details:\n{error_message}'
                )

            time.sleep(self.__retry_interval)

        # Poll and retrieve the record set
        response = self.__get_response(res)

        execution_id = response.get('execution_id')
        if not execution_id:
            raise DemistoException('No execution_id in the response.')

        timeout_time = None

        while True:
            status = response.get('status', '')
            if status == 'SUCCESS':
                return response.get('results') or []
            elif status == 'PENDING':
                current_time = time.time()
                if timeout_time is None:
                    timeout_time = current_time + self.__query_timeout_duration

                remaining_time = timeout_time - current_time
                if remaining_time <= 0:
                    raise DemistoException(
                        f'Unable to get query results within {self.__query_timeout_duration} seconds.'
                    )

                time.sleep(min(remaining_time, self.__polling_interval))

                res = demisto.executeCommand(
                    'xdr-xql-get-query-results',
                    assign_params(
                        query_id=execution_id,
                        parse_result_file_to_context='true',
                        using=self.__xql_query_instance,
                    ),
                )
                if is_error(res):
                    error_message = get_error(res)
                    raise DemistoException(
                        'Failed to execute xdr-xql-get-query-results.'
                        f' Error details:\n{error_message}'
                    )

                response = self.__get_response(res)
            else:
                raise DemistoException(f'Failed to get query results - {response}')


class Query:
    """
    This class allows you to get the query results.
    """

    def __init__(
        self,
        query_params: QueryParams,
        xql_query: XQLQuery | None,
        cache: Cache | None,
    ) -> None:
        self.__query_params = query_params
        self.__xql_query = xql_query
        self.__cache = cache

    def available(
        self,
    ) -> bool:
        return self.__xql_query is not None

    def query(
        self,
    ) -> list[dict[Hashable, Any]]:
        """ Get the record set by running the query. It will return an empty list if the query is not available,

        :return: List of fields retrieved by the query.
        """
        if self.__cache:
            recordset = self.__cache.load_recordset(self.__query_params.query_hash())
        else:
            recordset = None

        if recordset is None and self.__xql_query:
            recordset = self.__xql_query.query(self.__query_params)
            if self.__cache:
                self.__cache.save_recordset(self.__query_params, recordset)

        return recordset or []


class EntryBuilder:
    """
    This class helps to query XQL and build an entry data.
    """
    @staticmethod
    def __enum_fields_by_group(
        recordset: Iterable[dict[Hashable, Any]],
        sort_by: str,
        group_by: str,
        asc: bool,
    ) -> Iterable[
        tuple[
            Hashable,
            Iterable[dict[Hashable, Any]]
        ]
    ]:
        """ Enumerate fields with a group value by group

        :param recordset: The list of fields.
        :param sort_by: The field name to sort the recordset before grouping.
        :param group_by: The name of the field to make groups.
        :param asc: Set to True to sort the recordset in ascent order, Set to False for descent order.
        :return: Each group value with fields.
        """
        return itertools.groupby(
            sorted(
                recordset,
                key=lambda v: SortableValue(v.get(sort_by)),
                reverse=not asc,
            ),
            key=lambda v: v.get(group_by)
        )

    @staticmethod
    def __sum_by(
        recordset: list[dict[Hashable, Any]],
        sum_field: str,
        group_by: str,
        order_asc: bool,
    ) -> dict[Hashable, float]:
        """ Sum field values by a field

        :param recordset: The list of fields.
        :param sum_field: The field name of the value to be summed.
        :param group_by: The field name to group the fields.
        :param order_asc: Set to True for ascending order, and False for descending order.
        :return: Mapping of field name with the sum value in order by the sum.
        """
        d: dict[Hashable, float] = defaultdict(float)
        for fields in recordset:
            d[fields.get(group_by)] += to_float(fields.get(sum_field))
        return dict(sorted(d.items(), key=lambda x: x[1], reverse=not order_asc))

    @staticmethod
    def __make_color_palette(
        names: list[str],
        colors: dict[Hashable, str] | list[str] | str,
    ) -> dict[Hashable, str]:
        """ Build a color table

        :param names: The list of names to be mapped to colors
        :param colors: The base color mapping, or colors for 'names' in order
        :return: The color mapping. (name and color)
        """
        color_order: list[str] = []
        if isinstance(colors, str):
            color_order = [colors] * len(names)
        elif isinstance(colors, list):
            color_order = colors

        color_map: dict[Hashable, str] = dict(zip(
            names,
            color_order + EntryBuilder.list_colors(len(names))
        ))
        if isinstance(colors, dict):
            color_map.update(colors)
        return color_map

    @staticmethod
    def __build_singley_chart(
        chart_type: str,
        params: dict[Hashable, Any],
        recordset: list[dict[Hashable, Any]],
    ) -> dict[Hashable, Any]:
        """ Build a single-Y chart entry

        :param chart_type: The chart type. (bar or pie)
        :param params: The template parameters for a single-Y chart.
        :param recordset: The list of fields used to create the single-Y chart.
        :return: A single-Y chart entry.
        """
        class Template:
            class Records:
                class Sort:
                    def __init__(
                        self,
                        sort: dict[Hashable, Any],
                        default_by: str,
                    ) -> None:
                        by = sort.get('by') or default_by
                        assert isinstance(by, str) or by is None, (
                            f'sort.by must be of type str or null - {type(by)}'
                        )
                        self.__by = by or default_by
                        self.__asc = EntryBuilder.to_sort_order(sort.get('order') or 'asc')

                    @property
                    def by(
                        self,
                    ) -> str:
                        return self.__by

                    @property
                    def asc(
                        self,
                    ) -> bool:
                        return self.__asc

                def __init__(
                    self,
                    records: dict[Hashable, Any],
                ) -> None:
                    name_field = records.get('name-field')
                    assert isinstance(name_field, str), (
                        f'name-field must be of type str - {type(name_field)}'
                    )
                    self.__name_field = name_field

                    data_field = records.get('data-field')
                    assert isinstance(data_field, str), (
                        f'data-field must be of type str - {type(data_field)}'
                    )
                    self.__data_field = data_field

                    colors = records.get('colors')
                    if isinstance(colors, list):
                        for color in colors:
                            assert isinstance(color, str), (
                                f'color must be of type str - {type(color)}'
                            )
                    elif isinstance(colors, dict):
                        for color in colors.values():
                            assert isinstance(color, str), (
                                f'color must be of type str - {type(color)}'
                            )
                    elif colors is None:
                        colors = []
                    elif not isinstance(colors, str):
                        raise DemistoException(
                            f'colors must be of type dict, list or null - {type(colors)}'
                        )
                    self.__colors = colors

                    sort = records.get('sort') or {}
                    assert isinstance(sort, dict), (
                        f'sort must be of type dict or null - {type(sort)}'
                    )
                    self.__sort = self.Sort(sort, default_by=self.data_field)

                @property
                def name_field(
                    self,
                ) -> str:
                    return self.__name_field

                @property
                def data_field(
                    self,
                ) -> str:
                    return self.__data_field

                @property
                def colors(
                    self,
                ) -> dict[Hashable, str] | list[str] | str:
                    return self.__colors

                @property
                def sort(
                    self,
                ) -> Sort:
                    return self.__sort

            class Field:
                def __init__(
                    self,
                    field: dict[Hashable, Any],
                    default_color: str,
                ) -> None:
                    assert isinstance(field, dict), (
                        f'field in .fields must be of type dict - {type(field)}'
                    )
                    color = field.get('color')
                    assert isinstance(color, str) or color is None, (
                        f'field.color must be of type str or null - {type(color)}'
                    )
                    self.__color = color or default_color

                    self.__label = field.get('label')
                    assert isinstance(self.__label, str) or self.__label is None, (
                        f'field.label must be of type str or null - {type(self.__label)}'
                    )

                @property
                def color(
                    self,
                ) -> str:
                    return self.__color

                @property
                def label(
                    self,
                ) -> str | None:
                    return self.__label

            def __init__(
                self,
                template: dict[Hashable, Any],
            ) -> None:
                self.__records: Records | None = None  # pylint: disable=undefined-variable
                self.__fields: dict[Hashable, Field] | None = None  # pylint: disable=undefined-variable

                group = template.get('group')
                if group == 'records':
                    records = template.get(group)
                    assert isinstance(records, dict), (
                        f'records is required and must be of type dict - {type(records)}'
                    )
                    self.__records = self.Records(records)
                elif group == 'fields':
                    fields = template.get(group)
                    assert isinstance(fields, dict), (
                        f'fields is required and must be of type dict - {type(fields)}'
                    )
                    self.__fields = {
                        name: self.Field(field, default_color=color)
                        for (name, field), color in zip(
                            fields.items(),
                            EntryBuilder.list_colors(len(fields))
                        )
                    }
                else:
                    raise DemistoException(f"group must be 'records' or 'fields' - {group}")

            @property
            def records(
                self,
            ) -> Records | None:
                return self.__records

            @property
            def fields(
                self,
            ) -> dict[Hashable, Field] | None:
                return self.__fields

        template = Template(params)
        if records := template.records:
            sort: Template.Records.Sort = records.sort

            names = EntryBuilder.__sum_by(
                recordset=recordset,
                sum_field=records.data_field,
                group_by=records.name_field,
                order_asc=sort.asc,
            )
            # Create color mapping
            colors = EntryBuilder.__make_color_palette(
                names=[x for x in names if isinstance(x, str)],
                colors=records.colors,
            )
            # Build stats
            stats = [
                assign_params(
                    name=to_str(name),
                    data=[to_float(value)],
                    color=colors.get(name),
                ) for fields in sorted(
                    recordset,
                    key=lambda v: to_float(v.get(sort.by)),
                    reverse=not sort.asc,
                ) for name, value in [
                    (fields.get(records.name_field, ''), fields.get(records.data_field))
                ]
            ]
        elif fields := template.fields:
            # Build stats
            stats = [
                {
                    'name': to_str(group.label or field or ''),
                    'data': [sum(to_float(x.get(field)) for x in recordset)],
                    'color': group.color,
                } for field, group in fields.items()
            ]
        else:
            stats = []

        return {
            'Type': EntryType.WIDGET,
            'ContentsFormat': chart_type,
            'Contents': dict(
                assign_params(
                    params=params.get('params')
                ),
                stats=stats,
            ),
        }

    @staticmethod
    def __build_multiy_chart(
        chart_type: str,
        params: dict[Hashable, Any],
        recordset: list[dict[Hashable, Any]],
    ) -> dict[Hashable, Any]:
        """ Build a multi-Y chart entry

        :param chart_type: The chart type. (bar or line)
        :param params: The template parameters for a multi-Y chart.
        :param recordset: The list of fields used to create the multi-Y chart.
        :return: A multi-Y chart entry.
        """
        class Template:
            class X:
                def __init__(
                    self,
                    x: dict[Hashable, Any],
                ) -> None:
                    by = x.get('by')
                    assert isinstance(by, str), f'x.by must be of type str - {type(by)}'
                    self.__by = by

                    self.__asc = EntryBuilder.to_sort_order(x.get('order') or 'asc')
                    self.__field = x.get('field')
                    assert isinstance(self.__field, str) or self.__field is None, (
                        f'x.field must be of type str or null - {type(self.__field)}'
                    )

                @property
                def by(
                    self,
                ) -> str:
                    return self.__by

                @property
                def asc(
                    self,
                ) -> bool:
                    return self.__asc

                @property
                def field(
                    self,
                ) -> str | None:
                    return self.__field

            class Y:
                class Records:
                    def __init__(
                        self,
                        records: dict[Hashable, Any],
                    ) -> None:
                        name_field = records.get('name-field')
                        assert isinstance(name_field, str), (
                            f'name-field must be of type str - {type(name_field)}'
                        )
                        self.__name_field = name_field

                        data_field = records.get('data-field')
                        assert isinstance(data_field, str), (
                            f'data-field must be of type str - {type(data_field)}'
                        )
                        self.__data_field = data_field

                        colors = records.get('colors')
                        if isinstance(colors, list):
                            for color in colors:
                                assert isinstance(color, str), (
                                    f'color must be of type str - {type(color)}'
                                )
                        elif isinstance(colors, dict):
                            for color in colors.values():
                                assert isinstance(color, str), (
                                    f'color must be of type str - {type(color)}'
                                )
                        elif colors is None:
                            colors = []
                        elif not isinstance(colors, str):
                            raise DemistoException(
                                f'colors must be of type dict, list or null - {type(colors)}'
                            )
                        self.__colors = colors

                    @property
                    def name_field(
                        self,
                    ) -> str:
                        return self.__name_field

                    @property
                    def data_field(
                        self,
                    ) -> str:
                        return self.__data_field

                    @property
                    def colors(
                        self,
                    ) -> dict[Hashable, str] | list[str] | str:
                        return self.__colors

                class Field:
                    def __init__(
                        self,
                        field: dict[Hashable, Any],
                        default_color: str,
                    ) -> None:
                        assert isinstance(field, dict), (
                            f'field in y.fields must be of type dict - {type(field)}'
                        )
                        color = field.get('color')
                        assert isinstance(color, str) or color is None, (
                            f'field.color must be of type str or null - {type(color)}'
                        )
                        self.__color = color or default_color

                        self.__label = field.get('label')
                        assert isinstance(self.__label, str) or self.__label is None, (
                            f'field.label must be of type str or null - {type(self.__label)}'
                        )

                    @property
                    def color(
                        self,
                    ) -> str:
                        return self.__color

                    @property
                    def label(
                        self,
                    ) -> str | None:
                        return self.__label

                def __init__(
                    self,
                    y: dict[Hashable, Any],
                ) -> None:
                    self.__records: Records | None = None  # pylint: disable=undefined-variable
                    self.__fields: dict[Hashable, Field] | None = None  # pylint: disable=undefined-variable

                    group = y.get('group')
                    if group == 'records':
                        records = y.get(group)
                        assert isinstance(records, dict), (
                            f'y.records is required and must be of type dict - {type(records)}'
                        )
                        self.__records = self.Records(records)
                    elif group == 'fields':
                        fields = y.get(group)
                        assert isinstance(fields, dict), (
                            f'y.fields is required and must be of type dict - {type(fields)}'
                        )
                        self.__fields = {
                            name: self.Field(field, default_color=color)
                            for (name, field), color in zip(
                                fields.items(),
                                EntryBuilder.list_colors(len(fields))
                            )
                        }
                    else:
                        raise DemistoException(f"y.group must be 'records' or 'fields' - {group}")

                @property
                def records(
                    self,
                ) -> Records | None:
                    return self.__records

                @property
                def fields(
                    self,
                ) -> dict[Hashable, Field] | None:
                    return self.__fields

            def __init__(
                self,
                template: dict[Hashable, Any],
            ) -> None:
                x = template.get('x')
                assert isinstance(x, dict), f'x must be of type dict - {type(x)}'
                self.__x = self.X(x)

                y = template.get('y')
                assert isinstance(y, dict), f'y must be of type dict - {type(y)}'
                self.__y = self.Y(y)

            @property
            def x(
                self,
            ) -> X:
                return self.__x

            @property
            def y(
                self,
            ) -> Y:
                return self.__y

        template = Template(params)
        if records := template.y.records:
            ynames = EntryBuilder.__sum_by(
                recordset=recordset,
                sum_field=records.data_field,
                group_by=records.name_field,
                order_asc=False,
            )
            # Create color mapping
            ycolors = EntryBuilder.__make_color_palette(
                names=[x for x in ynames if isinstance(x, str)],
                colors=records.colors,
            )
            # Build stats
            stats = []
            for x_val, x_records in EntryBuilder.__enum_fields_by_group(
                recordset=recordset,
                sort_by=template.x.by,
                group_by=template.x.by,
                asc=template.x.asc
            ):
                groups = {k: None for k in ynames}
                xlabel = ''
                for y_fields in x_records:
                    data = y_fields.get(records.data_field)
                    name = y_fields.get(records.name_field)
                    name_str = to_str(name)
                    groups[name_str] = assign_params(
                        name=name_str,
                        data=[to_float(data)],
                        color=ycolors.get(name),
                    )
                    xlabel = xlabel or to_str(
                        y_fields.get(template.x.field) if template.x.field else x_val
                    )

                stats.append({
                    'name': xlabel,
                    'groups': [
                        assign_params(
                            name=k,
                            data=[0],
                            color=ycolors.get(k),
                        ) if v is None else v
                        for k, v in groups.items()
                    ],
                })
        elif fields := template.y.fields:
            # Build stats
            stats = [
                {
                    'name': to_str(y_fields.get(template.x.field) if template.x.field else x_val),
                    'groups': [
                        {
                            'name': to_str(y_group.label or field or ''),
                            'data': [to_float(y_fields.get(field))],
                            'color': y_group.color,
                        } for field, y_group in fields.items()
                    ]
                } for x_val, x_records in EntryBuilder.__enum_fields_by_group(
                    recordset=recordset,
                    sort_by=template.x.by,
                    group_by=template.x.by,
                    asc=template.x.asc,
                ) for y_fields in x_records
            ]
        else:
            stats = []

        return {
            'Type': EntryType.WIDGET,
            'ContentsFormat': chart_type,
            'Contents': dict(
                assign_params(
                    params=params.get('params')
                ),
                stats=stats,
            ),
        }

    @staticmethod
    def __build_single_bar(
        params: dict[Hashable, Any],
        recordset: list[dict[Hashable, Any]],
    ) -> dict[Hashable, Any]:
        """ Build a single bar entry

        :param params: The template parameters for 'single-bar'.
        :param recordset: The list of fields used to create the single-bar chart.
        :return: An single bar entry.
        """
        return EntryBuilder.__build_singley_chart(
            chart_type='bar',
            params=params,
            recordset=recordset,
        )

    @staticmethod
    def __build_stacked_bar(
        params: dict[Hashable, Any],
        recordset: list[dict[Hashable, Any]],
    ) -> dict[Hashable, Any]:
        """ Build a stacked bar entry

        :param params: The template parameters for 'stacked-bar'.
        :param recordset: The list of fields used to create the stacked-bar chart.
        :return: An stacked bar entry.
        """
        return EntryBuilder.__build_multiy_chart(
            chart_type='bar',
            params=params,
            recordset=recordset,
        )

    @staticmethod
    def __build_line(
        params: dict[Hashable, Any],
        recordset: list[dict[Hashable, Any]],
    ) -> dict[Hashable, Any]:
        """ Build a line entry

        :param params: The template parameters for 'line'.
        :param recordset: The list of fields used to create the line chart.
        :return: A line entry.
        """
        return EntryBuilder.__build_multiy_chart(
            chart_type='line',
            params=params,
            recordset=recordset,
        )

    @staticmethod
    def __build_pie(
        params: dict[Hashable, Any],
        recordset: list[dict[Hashable, Any]],
    ) -> dict[Hashable, Any]:
        """ Build a pie entry

        :param params: The template parameters for 'pie'.
        :param recordset: The list of fields used to create the pie chart.
        :return: A pie chart entry.
        """
        return EntryBuilder.__build_singley_chart(
            chart_type='pie',
            params=params,
            recordset=recordset,
        )

    @staticmethod
    def __build_markdown_table(
        params: dict[Hashable, Any],
        recordset: list[dict[Hashable, Any]],
    ) -> dict[Hashable, Any]:
        """ Build a markdown table

        :param params: The template parameters for 'markdown-table'.
        :param recordset: The list of fields used to create the markdown table.
        :return: A markdown table.
        """
        class Template:
            class Sort:
                def __init__(
                    self,
                    sort: dict[Hashable, Any],
                ) -> None:
                    self.__by = sort.get('by')
                    assert isinstance(self.__by, str) or self.__by is None, (
                        f'sort.by must be of type str or null - {type(self.__by)}'
                    )
                    self.__asc = EntryBuilder.to_sort_order(sort.get('order') or 'asc')

                @property
                def by(
                    self,
                ) -> str | None:
                    return self.__by

                @property
                def asc(
                    self,
                ) -> bool:
                    return self.__asc

            class Column:
                def __init__(
                    self,
                    column: dict[Hashable, Any],
                ) -> None:
                    assert isinstance(column, dict), (
                        f'column in columns must be of type dict - {type(column)}'
                    )
                    self.field = column.get('field')
                    self.label = column.get('label') or self.field or ''

            def __init__(
                self,
                template: dict[Hashable, Any],
            ) -> None:
                self.__title = template.get('title') or ''
                assert isinstance(self.__title, str), (
                    f'title must be of type str or null - {type(self.__title)}'
                )
                self.__columns: list[Column] | None = None  # pylint: disable=undefined-variable
                if columns := template.get('columns'):
                    assert isinstance(columns, list), (
                        f'columns must be list or null - {type(columns)}'
                    )
                    self.__columns = [self.Column(c) for c in columns]

                sort = template.get('sort') or {}
                assert isinstance(sort, dict), (
                    f'sort must be of type dict or null - {type(sort)}'
                )
                self.__sort = self.Sort(sort)

            @property
            def title(
                self,
            ) -> str:
                return self.__title

            @property
            def columns(
                self,
            ) -> list[Column] | None:
                return self.__columns

            @property
            def sort(
                self,
            ) -> Sort:
                return self.__sort

        template = Template(params)

        if not recordset:
            md = ''
        else:
            if template.sort.by:
                recordset = sorted(
                    recordset,
                    key=lambda v: SortableValue(v.get(template.sort.by)),
                    reverse=not template.sort.asc,
                )

            # Build markdown
            md = tableToMarkdown(
                template.title,
                recordset,
                headers=[c.field for c in template.columns] if template.columns else None,
                headerTransform=lambda field: next(
                    (c.label for c in template.columns or [] if c.field == field),
                    pascalToSpace(field.replace('_', ' '))
                ),
                sort_headers=False,
            )

        return {
            'Type': EntryType.NOTE,
            'ContentsFormat': EntryFormat.MARKDOWN,
            'HumanReadable': md,
            'Contents': None,
        }

    @staticmethod
    def __build_duration(
        params: dict[Hashable, Any],
        recordset: list[dict[Hashable, Any]],
    ) -> dict[Hashable, Any]:
        """ Build a duration entry

        :param params: The template parameters for 'duration'.
        :param recordset: The list of fields used to create the duration entry.
        :return: A duration entry.
        """
        field = params.get('field')
        if not field or not isinstance(field, str):
            raise DemistoException(f'field must be of type str - {type(field)}')

        if len(recordset) > 1:
            raise DemistoException('The duration entry allows at most one record.')

        return {
            'Type': EntryType.WIDGET,
            'ContentsFormat': 'duration',
            'Contents': dict(
                assign_params(
                    params=params.get('params')
                ),
                stats=int(to_float((recordset or [{}])[0].get(field))),
            ),
        }

    @staticmethod
    def __build_number(
        params: dict[Hashable, Any],
        recordset: list[dict[Hashable, Any]],
    ) -> dict[Hashable, Any]:
        """ Build a number entry

        :param params: The template parameters for 'number'.
        :param recordset: The list of fields used to create the number entry.
        :return: A number entry.
        """
        field = params.get('field')
        if not field or not isinstance(field, str):
            raise DemistoException(f'field must be of type str - {type(field)}')

        if len(recordset) > 1:
            raise DemistoException('The number entry allows at most one record.')

        return {
            'Type': EntryType.WIDGET,
            'ContentsFormat': 'number',
            'Contents': dict(
                assign_params(
                    params=params.get('params')
                ),
                stats=to_float((recordset or [{}])[0].get(field)),
            ),
        }

    @staticmethod
    def __build_number_trend(
        params: dict[Hashable, Any],
        recordset: list[dict[Hashable, Any]],
    ) -> dict[Hashable, Any]:
        """ Build a number trend entry

        :param params: The template parameters for 'number-trend'.
        :param recordset: The list of fields used to create the number trend entry.
        :return: A number trend entry.
        """
        prev_field = params.get('prev-field')
        if not prev_field or not isinstance(prev_field, str):
            raise DemistoException(f'prev-field must be of type str - {type(prev_field)}')

        curr_field = params.get('curr-field')
        if not curr_field or not isinstance(curr_field, str):
            raise DemistoException(f'curr-field must be of type str - {type(curr_field)}')

        if len(recordset) > 1:
            raise DemistoException('The number-trend entry allows at most one record.')

        fields = (recordset or [{}])[0]

        return {
            'Type': EntryType.WIDGET,
            'ContentsFormat': 'number',
            'Contents': dict(
                assign_params(
                    params=params.get('params')
                ),
                stats={
                    'prevSum': to_float(fields.get(prev_field)),
                    'currSum': to_float(fields.get(curr_field)),
                },
            ),
        }

    @staticmethod
    def __build_markdown(
        params: dict[Hashable, Any],
        **kwargs,
    ) -> dict[Hashable, Any]:
        """ Build a markdown entry

        :param params: The template parameters for 'markdown'.
        :return: A markdown entry.
        """
        return {
            'Type': EntryType.NOTE,
            'ContentsFormat': EntryFormat.MARKDOWN,
            'HumanReadable': str(params.get('text') or ''),
            'Contents': None,
        }

    @staticmethod
    def to_sort_order(
        order: str,
    ) -> bool:
        if order == 'asc':
            return True
        elif order == 'desc':
            return False
        else:
            raise DemistoException(f'Invalid sort order - {order}')

    @staticmethod
    def list_colors(
        n: int,
    ) -> list[str]:
        colors = [
            f'rgb({int(r * 256)}, {int(g * 256)}, {int(b * 256)})'
            for r, g, b in [
                colorsys.hsv_to_rgb(i / n, 1, 0.9)
                for i in range(max(0, n))
            ]
        ]
        return list(reversed(colors[1::2])) + colors[::2]

    def __get_default_entry(
        self,
        scope: DefaultEntryScope,
        entry_params: dict[Hashable, Any],
    ) -> dict[Hashable, Any] | None:
        default = entry_params.get('default')
        assert default is None or isinstance(default, dict), (
            f'entry.default must be of type dict or null - {type(default)}'
        )
        if not default:
            return None

        scopes = default.get('scope')
        assert scopes is None or isinstance(scopes, str | list), (
            f'default.scope must be of type null, str, or list - {type(scopes)}'
        )
        scopes = [str(x) for x in list(DefaultEntryScope)] if scopes is None else scopes
        scopes = scopes if isinstance(scopes, list) else [scopes]
        if scope not in scopes:
            return None

        entry_key = str(scope) if str(scope) in default else 'entry'
        entry = default.get(entry_key)
        if isinstance(entry, dict):
            return entry
        elif isinstance(entry, str):
            return {
                'Type': EntryType.NOTE,
                'ContentsFormat': EntryFormat.MARKDOWN,
                'HumanReadable': entry,
                'Contents': None,
            }
        else:
            raise DemistoException(
                f'default.{entry_key} must be of type stror dict - {type(entry)}'
            )

    def __init__(
        self,
        formatter: Formatter,
        context: ContextData,
    ) -> None:
        self.__formatter = formatter
        self.__context = context

    def build(
        self,
        query: Query,
        entry_params: dict[Hashable, Any],
    ) -> dict[Hashable, Any]:
        if (
            not query.available()
            and (
                entry := self.__get_default_entry(
                    scope=DefaultEntryScope.QUERY_SKIPPED,
                    entry_params=self.__formatter.build(
                        template=entry_params,
                        context=self.__context,
                    )
                )
            )
        ):
            return entry

        entry_type = entry_params.get('type')
        if not entry_type:
            raise DemistoException('type is required.')

        params = entry_params.get(entry_type, {})
        if not isinstance(params, dict):
            raise DemistoException(f'{entry_type} must be of type dict - {type(params)}.')

        build_entry = {
            'single-bar': lambda params, recordset: self.__build_single_bar(
                params=params,
                recordset=recordset,
            ),
            'stacked-bar': lambda params, recordset: self.__build_stacked_bar(
                params=params,
                recordset=recordset,
            ),
            'line': lambda params, recordset: self.__build_line(
                params=params,
                recordset=recordset,
            ),
            'pie': lambda params, recordset: self.__build_pie(
                params=params,
                recordset=recordset,
            ),
            'markdown-table': lambda params, recordset: self.__build_markdown_table(
                params=params,
                recordset=recordset,
            ),
            'duration': lambda params, recordset: self.__build_duration(
                params=params,
                recordset=recordset,
            ),
            'number': lambda params, recordset: self.__build_number(
                params=params,
                recordset=recordset,
            ),
            'number-trend': lambda params, recordset: self.__build_number_trend(
                params=params,
                recordset=recordset,
            ),
            'markdown': lambda params, recordset: self.__build_markdown(
                params=params,
                recordset=recordset,
            ),
        }.get(entry_type)

        if not build_entry:
            raise DemistoException(f'Invalid type - {entry_type}')

        recordset = query.query()
        if (
            not recordset
            and (
                entry := self.__get_default_entry(
                    scope=DefaultEntryScope.NO_RECORDSET,
                    entry_params=self.__formatter.build(
                        template=entry_params,
                        context=self.__context.inherit({
                            'recordset': []
                        })
                    )
                )
            )
        ):
            return entry
        else:
            return build_entry(
                self.__formatter.build(
                    template=params,
                    context=self.__context.inherit({
                        'recordset': recordset
                    })
                ),
                recordset
            )


''' MAIN FUNCTION '''


class Main:
    @staticmethod
    def __get_template(
        args: dict[Hashable, Any],
    ) -> tuple[str, dict[Hashable, Any]]:
        """ Get the templates with its name

        :param args: The argument parameters.
        :return: The template name and template.
        """
        templates_type = args.get('templates_type') or 'raw'
        if templates_type == 'raw':
            templates = args.get('templates')
        elif templates_type == 'list':
            templates = execute_command('getList', {
                'listName': args.get('templates')
            })
        else:
            raise DemistoException(f'Invalid template type - {templates_type}')

        if isinstance(templates, str):
            if argToBoolean(args.get('triple_quotes_to_string', 'true')):
                templates = re.sub(
                    r"""(\"{3}|'{3}|`{3})(.*?)\1""",
                    lambda m: json.dumps(m.group(2)),
                    templates,
                    flags=re.DOTALL
                )

            templates = json.loads(templates)
        if not isinstance(templates, dict):
            raise DemistoException(f'Invalid templates - {templates}')

        template_name = args.get('template_name') or ''
        if template := templates.get(template_name):
            if not isinstance(template, dict):
                raise DemistoException(f'Invalid template - {template}')
        else:
            raise DemistoException(f'No templates were found - {template_name}')

        return template_name, template

    @staticmethod
    def __parse_date_time(
        value: Any,
        base_time: datetime | None,
    ) -> datetime:
        """ Parse a date time value

        :param value: The date or time to parse
        :param base_time: The base time for the relative time.
        :return: aware datetime object
        """
        if value in (None, ''):
            return datetime.now(pytz.UTC)

        if isinstance(value, int):
            # Parse as time stamp
            try:
                # Considered the value as seconds > milliseconds > microseconds when it's too large (> uint max).
                # (Currently later than 2106-02-07 06:28:15)
                while value > 4294967295:
                    value /= 1000

                return datetime.fromtimestamp(value).astimezone(pytz.UTC)
            except Exception as e:
                raise DemistoException(f'Error with input date / time - {e}')

        if isinstance(value, str):
            value = value.strip()
            try:
                # Parse as time stamp
                return Main.__parse_date_time(int(value), base_time)
            except (TypeError, ValueError):
                pass

        try:
            date_time = dateparser.parse(
                value,
                settings=assign_params(
                    RELATIVE_BASE=base_time
                )
            )
            assert date_time is not None, f'could not parse {value}'

            if date_time.tzinfo is not None:
                return date_time

            date_time = dateparser.parse(
                value,
                settings=assign_params(
                    TIMEZONE='UTC',
                    RETURN_AS_TIMEZONE_AWARE=True,
                    RELATIVE_BASE=base_time,
                )
            )
            assert date_time is not None, f'could not parse {value}'
            return date_time
        except Exception as e:
            raise DemistoException(f'Error with input date / time - {e}')

    @staticmethod
    def __get_variable_substitution(
        args: dict[Hashable, Any],
        template: dict[Hashable, Any],
    ) -> tuple[str, str]:
        vs = args.get('variable_substitution') or '${,}'
        if isinstance(vs, str):
            vs = vs.split(',', maxsplit=1)
        elif not isinstance(vs, list):
            raise DemistoException(f'Invalid variable substitution - {vs}')

        if not vs or not vs[0]:
            raise DemistoException('variable_substitution must have a opening marker.')
        elif len(vs) == 1:
            assert isinstance(vs[0], str), f'opening marker must be of type str - {vs[0]}'
            vs = [vs[0], '']
        elif len(vs) == 2:
            assert isinstance(vs[0], str), f'opening marker must be of type str - {vs[0]}'
            assert isinstance(vs[1], str), f'closing marker must be of type str - {vs[1]}'
        else:
            raise DemistoException(f'too many values for variable_substitution - {vs}')

        var_opening = demisto.get(template, 'config.variable_substitution.opening')
        if var_opening is not None:
            assert isinstance(var_opening, str), (
                f'config.variable_substitution.opening must be of type str - {var_opening}'
            )
            assert var_opening, (
                'config.variable_substitution.opening cannot be empty when provided'
            )
        else:
            var_opening = vs[0]

        var_closing = demisto.get(template, 'config.variable_substitution.closing')
        if var_closing is not None:
            assert isinstance(var_closing, str), (
                f'config.variable_substitution.closing must be of type str - {var_opening}'
            )
        else:
            var_closing = vs[1]

        return str(var_opening), str(var_closing)

    @staticmethod
    def __get_base_time(
        args: dict[Hashable, Any],
        query_node: dict[Hashable, Any],
        context: ContextData,
    ) -> tuple[datetime, datetime]:
        """ Get the base time of earliest_time and latest_time

        :param args: The argument parameters.
        :param query_node: The `.query` node of the template.
        :param context: The context data.
        :return: The base time of earliest_time and latest_time.
        """
        round_time = demisto.get(query_node, 'time_range.round_time')
        if round_time is None:
            round_time = argToList(args.get('round_time'))
            if len(round_time) == 0:
                round_time_latest = round_time_earliest = 0
            elif len(round_time) == 1:
                round_time_latest = round_time_earliest = arg_to_number(round_time[0]) or 0
            elif len(round_time) == 2:
                round_time[0] = arg_to_number(round_time[0])
                assert isinstance(round_time[0], int), (
                    f'list of round_time must be number - {round_time}'
                )
                round_time_earliest = round_time[0]

                round_time[1] = arg_to_number(round_time[1])
                assert isinstance(round_time[1], int), (
                    f'list of round_time must be number - {round_time}'
                )
                round_time_latest = round_time[1]
            else:
                raise DemistoException(f'Too many round_time - {round_time}')

        elif isinstance(round_time, dict):
            round_time_earliest = arg_to_number(round_time.get('earliest_time')) or 0
            round_time_latest = arg_to_number(round_time.get('latest_time')) or 0
        elif isinstance(round_time, str | int):
            round_time_latest = round_time_earliest = arg_to_number(round_time) or 0
        else:
            raise DemistoException(f'query.time_range.round_time must be of type str or dict - {round_time}')

        base_time = args.get('base_time')
        if not base_time:
            # Set default base time
            for k in ['alert.occurred', 'incident.occurred', 'alert.created', 'incident.created']:
                base_time = context.get(k)
                if base_time and base_time != '0001-01-01T00:00:00Z':
                    break
            else:
                base_time = 'now'

        base_time = Main.__parse_date_time(base_time, None)

        return (
            base_time if not round_time_earliest else datetime.fromtimestamp(
                math.floor(base_time.timestamp() / round_time_earliest) * round_time_earliest,
                base_time.tzinfo
            ),
            base_time if not round_time_latest else datetime.fromtimestamp(
                math.floor(base_time.timestamp() / round_time_latest) * round_time_latest,
                base_time.tzinfo
            )
        )

    @staticmethod
    def __build_query_params(
        args: dict[Hashable, Any],
        query_name: str,
        template: dict[Hashable, Any],
        formatter: Formatter,
        context: ContextData,
    ) -> QueryParams:
        """ Build query parameters

        :param args: The argument parameters.
        :param query_name: The name of the query.
        :param template: The template.
        :param formatter: The formatter to process variable substitution.
        :param context: The context data.
        :return: Query parameters.
        """
        query_node = formatter.build(
            template=demisto.get(template, 'query'),
            context=context,
        )

        earliest_time_base, latest_time_base = Main.__get_base_time(
            args=args,
            query_node=query_node,
            context=context,
        )

        return QueryParams(
            query_name=query_name,
            query_string=query_node.get('xql'),
            earliest_time=Main.__parse_date_time(
                demisto.get(
                    query_node,
                    'time_range.earliest_time',
                    args.get('earliest_time', '24 hours ago')
                ),
                earliest_time_base
            ),
            latest_time=Main.__parse_date_time(
                demisto.get(
                    query_node,
                    'time_range.latest_time',
                    args.get('latest_time', 'now')
                ),
                latest_time_base
            )
        )

    def __arg_to_int(
        self,
        name: str,
        default_value: int,
    ) -> int:
        arg = self.__args.get(name)
        if arg is None or arg == '':
            return default_value
        elif isinstance(arg, str | int | float):
            try:
                return int(arg)
            except Exception:
                raise DemistoException(f'Invalid {name} - {arg}')
        else:
            raise DemistoException(f'Invalid {name} - {arg}')

    def __is_query_executable(
        self,
    ) -> bool:
        class Evaluation:
            def __init__(
                self,
                formatter: Formatter,
                context: ContextData,
            ) -> None:
                self.__formatter = formatter
                self.__context = context

            def evaluate(
                self,
                conds: Any,
            ) -> bool:
                if isinstance(conds, str):
                    conds = self.__formatter.build(
                        template=conds,
                        context=self.__context,
                    )

                if isinstance(conds, dict):
                    return any(
                        self.evaluate(k) and self.evaluate(v)
                        for k, v in conds.items()
                    )
                elif isinstance(conds, list):
                    return any(self.evaluate(v) for v in conds)
                elif conds is None:
                    return False
                elif isinstance(conds, bool):
                    return conds
                elif isinstance(conds, int | float):
                    return conds != 0.0
                elif isinstance(conds, str):
                    return conds.lower() not in ('', 'false')
                else:
                    return bool(conds)

        query = self.__template.get('query') or {}
        if 'conditions' not in query:
            # Queries are executable when 'query.conditions' is not specified
            return True
        else:
            conditions = query.get('conditions')

            return Evaluation(
                formatter=Formatter(
                    variable_substitution=self.__variable_substitution,
                    keep_symbol_to_null=False,
                ),
                context=self.__context,
            ).evaluate(conditions)

    def __init__(
        self,
        args: dict[Hashable, Any],
    ) -> None:
        self.__args = args

        fields = demisto.incident()
        fields = dict(fields, **(fields.get('CustomFields') or {}))
        fields.pop('CustomFields', None)

        context = args.get('context_data') or demisto.context()
        if isinstance(context, str):
            context = json.loads(context)

        assert context is None or isinstance(context, dict), (
            f'Context data must be of type str, dict, or null - {type(context)}'
        )
        self.__context: ContextData = ContextData(
            context=context,
            alert=fields if is_xsiam() else None,
            incident=None if is_xsiam() else fields,
        )
        self.__template_name, self.__template = self.__get_template(args)
        self.__variable_substitution = self.__get_variable_substitution(
            args, self.__template
        )
        self.__cache_type: str = args.get('cache_type') or CacheType.RECORDSET
        if self.__cache_type not in [str(x) for x in list(CacheType)]:
            raise DemistoException(f'Invalid cache_type - {self.__cache_type}')

        self.__max_retries: int = self.__arg_to_int(
            'max_retries', DEFAULT_RETRY_MAX
        )  # max_retries accepts 0

        self.__retry_interval: int = self.__arg_to_int(
            'retry_interval', DEFAULT_RETRY_INTERVAL
        ) or DEFAULT_RETRY_INTERVAL

        self.__polling_interval: int = self.__arg_to_int(
            'polling_interval', DEFAULT_POLLING_INTERVAL
        ) or DEFAULT_POLLING_INTERVAL

        self.__query_timeout_duration: int = self.__arg_to_int(
            'query_timeout_duration', DEFAULT_QUERY_TIMEOUT_DURATION
        ) or DEFAULT_QUERY_TIMEOUT_DURATION

        self.__xql_query_instance: str | None = (
            demisto.get(self.__template, 'query.command.using')
            or args.get('xql_query_instance')
        )

    def create(
        self,
    ) -> CommandResults:
        """ Create a graph entry

        :return: The command results.
        """
        formatter = Formatter(
            variable_substitution=self.__variable_substitution,
            keep_symbol_to_null=True,
        )
        query_params = self.__build_query_params(
            args=self.__args,
            query_name=self.__template_name,
            template=self.__template,
            formatter=formatter,
            context=self.__context,
        )
        cache = Cache(
            name=self.__template_name,
            context=self.__context
        )
        entry = cache.load_entry(
            query_params.query_hash()
        ) if self.__cache_type == CacheType.ENTRY else None

        need_query = not entry and self.__is_query_executable()

        entry = entry or EntryBuilder(
            formatter=formatter,
            context=self.__context,
        ).build(
            query=Query(
                query_params=query_params,
                xql_query=XQLQuery(
                    xql_query_instance=self.__xql_query_instance,
                    polling_interval=self.__polling_interval,
                    retry_interval=self.__retry_interval,
                    retry_max=self.__max_retries,
                    query_timeout_duration=self.__query_timeout_duration,
                ) if need_query else None,
                cache=cache if self.__cache_type != CacheType.NONE else None,
            ),
            entry_params=self.__template.get('entry') or {},
        )

        res = {
            'QueryParams': {
                'query_name': query_params.query_name,
                'query_string': query_params.query_string,
                'earliest_time': query_params.get_earliest_time_iso(),
                'latest_time': query_params.get_latest_time_iso(),
            },
            'QueryHash': query_params.query_hash(),
            'Entry': entry
        }
        if need_query and self.__cache_type == CacheType.ENTRY:
            cache.save_entry(query_params, entry)

        return CommandResults(
            readable_output='Done.',
            outputs={
                'XQLDSHelper': res
            },
            raw_response=res,
        )


def main():
    try:
        return_results(Main(demisto.args()).create())
    except Exception as e:
        return_error(f'{e}\n\n{traceback.format_exc()}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
