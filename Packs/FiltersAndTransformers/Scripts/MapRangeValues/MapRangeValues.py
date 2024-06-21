import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Union


VALUE_TYPE = Union[str, float]


class Replace:

    def __init__(self, value: str, replacement: str):
        self._value = self.get_typed_value(value)
        self.replacement = self.get_typed_value(replacement)

    def should_replace(self, value: VALUE_TYPE) -> bool:
        return self._value == value

    @staticmethod
    def get_typed_value(value: str) -> VALUE_TYPE:
        try:
            demisto.debug(f'MapRangeValues, get_typed_value, the initial {value=}')
            f_value = float(value)
            if f_value % 1 == 0:
                demisto.debug(f'MapRangeValues, get_typed_value, casting {f_value=} to int')
                return int(f_value)
            demisto.debug(f'MapRangeValues, get_typed_value, return float {f_value=}')
            return f_value
        except ValueError:
            demisto.debug(f'MapRangeValues, get_typed_value, in ValueError {value=}')
            return str(value)


class RangeReplace(Replace):
    def __init__(self, start_value: str, end_value: str, replacement: str):
        self._start_value = self.get_typed_value(start_value)
        self._end_value = self.get_typed_value(end_value)
        self.replacement = self.get_typed_value(replacement)

    def should_replace(self, value) -> bool:    # pylint: disable=W9014
        demisto.debug(f'MapRangeValues, RangeReplace class, should_replace {self._start_value=} {value=} {self._end_value=}')
        try:
            return self._start_value <= value <= self._end_value
        except TypeError:
            return False


def get_replace_list(map_from: list[str], map_to: list[str], sep: str = '-') -> list[Replace]:
    replace_list: list[Replace] = []
    for _from, _to in zip(map_from, map_to):
        try:
            start, end = _from.split(sep)
            replace_list.append(RangeReplace(start, end, _to))
        except ValueError:
            replace_list.append(Replace(_from, _to))

    return replace_list


def replace_values(values: list[str], replace_list: list[Replace]) -> list[VALUE_TYPE]:
    replaced_list = []
    for value in map(Replace.get_typed_value, values):
        for replace_obj in replace_list:
            if replace_obj.should_replace(value):
                value = replace_obj.replacement
                break
        replaced_list.append(value)
    return replaced_list


def main():  # pragma: no cover
    try:
        args = demisto.args()
        map_from = argToList(args['map_from'])
        map_to = argToList(args['map_to'])
        assert len(map_from) == \
            len(map_to), "the length of 'map_from' list does not match the length of 'map_to' list."
        replace_list = get_replace_list(map_from, map_to, args.get('sep', '-'))
        return_results(replace_values(argToList(args['value']), replace_list))
    except Exception as error:
        return_error(str(error), error)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
