import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any, Callable, Dict, Optional, Tuple


class ContextData:
    def __init__(self, context: Optional[Dict[str, Any]] = None):
        self.__context = context or demisto.context()

    def __get_inputs_value(self, key: str) -> Any:
        inputs = demisto.callingContext.get('context.PlaybookInputs') or {}
        return demisto.dt(inputs, key)

    def __get_incident_value(self, key: str) -> Any:
        incident = demisto.incident()
        val = demisto.dt(incident, key)
        if val is None:
            val = demisto.dt(incident.get('CustomFields') or {}, key)
        return val

    def __get_lists_value(self, key: str) -> Any:
        if key.startswith('.'):
            key = key[1:]

        name = key
        ok, val = execute_command('getList', {'listName': name}, fail_on_error=False)
        if not ok:
            for sep in ['=', '(', '.']:
                name = key.split(sep, maxsplit=1)[0]
                ok, val = execute_command('getList', {'listName': name}, fail_on_error=False)
                if ok:
                    break
            else:
                return None

        val = demisto.dt(val, '.' + key[len(name):])
        if isinstance(val, str):
            try:
                val = json.loads(val)
            except json.JSONDecodeError:
                pass
        return val

    def get(self, key: Optional[str] = None) -> Any:
        """ Get the context value

        :param key: The dt expressions (string within ${}).
        :return: The value.
        """
        if not key:
            return None

        for prefix, handler in {
            'inputs': ContextData.__get_inputs_value,
            'incident': ContextData.__get_incident_value,
            'lists': ContextData.__get_lists_value
        }.items():
            if prefix == key or (key.startswith(prefix)
                                 and key[len(prefix):len(prefix) + 1] in ('.', '(', '=')):
                return handler(self, key[len(prefix):])
        return demisto.dt(self.__context, key)


class Formatter:
    def __init__(self, start_marker: str, end_marker: str, keep_symbol_to_null: bool):
        if not start_marker:
            raise ValueError('start-marker is required.')

        self.__start_marker = start_marker
        self.__end_marker = end_marker
        self.__keep_symbol_to_null = keep_symbol_to_null

    @staticmethod
    def __is_end_mark(source: str, ci: int, end_marker: str) -> bool:
        if end_marker:
            return source[ci:ci + len(end_marker)] == end_marker
        else:
            c = source[ci]
            if c.isspace():
                return True
            elif c.isascii():
                return c != '_' and not c.isalnum()
            else:
                return False

    def __extract(self,
                  source: str,
                  extractor: Optional[Callable[[str,
                                                Optional[ContextData]],
                                               Any]],
                  dx: Optional[ContextData],
                  si: int,
                  markers: Optional[Tuple[str, str]]) -> Tuple[Any, Optional[int]]:
        """ Extract a template text, or an enclosed value within starting and ending marks

        :param source: The template text, or the enclosed value starts with the next charactor of a start marker
        :param extractor: The function to extract an enclosed value as DT
        :param dx: The context data
        :param si: The index of `source` to start extracting
        :param markers: The start and end marker to find an end position for parsing an enclosed value.
                        It must be None when the template text is given to `source`.
        :return: The extracted value and index of `source` when parsing ended.
                 The index is the next after the end marker when extracting the enclosed value.
        """
        out = None
        ci = si
        while ci < len(source):
            if markers is not None and Formatter.__is_end_mark(source, ci, markers[1]):
                key = source[si:ci] if out is None else str(out) + source[si:ci]
                if extractor:
                    if (xval := extractor(key, dx)) is None and self.__keep_symbol_to_null:
                        xval = markers[0] + key + markers[1]
                else:
                    xval = key
                return xval, ci + len(markers[1])
            elif extractor and source[ci:ci + len(self.__start_marker)] == self.__start_marker:
                xval, ei = self.__extract(source, extractor, dx,
                                          ci + len(self.__start_marker),
                                          (self.__start_marker, self.__end_marker))
                if si != ci:
                    out = source[si:ci] if out is None else str(out) + source[si:ci]

                if ei is None:
                    xval = self.__start_marker
                    ei = ci + len(self.__start_marker)

                if out is None:
                    out = xval
                elif xval is not None:
                    out = str(out) + str(xval)
                si = ci = ei
            elif markers is None:
                ci += 1
            elif endc := {'(': ')', '{': '}', '[': ']', '"': '"', "'": "'"}.get(source[ci]):
                _, ei = self.__extract(source, None, dx, ci + 1, (source[ci], endc))
                ci = ci + 1 if ei is None else ei
            elif source[ci] == '\\':
                ci += 2
            else:
                ci += 1

        if markers is not None:
            # unbalanced braces, brackets, quotes, etc.
            return None, None
        elif not extractor:
            return None, ci
        elif si >= len(source):
            return out, ci
        elif out is None:
            return source[si:], ci
        else:
            return str(out) + source[si:], ci

    def build(self,
              template: Any,
              extractor: Optional[Callable[[str,
                                            Optional[ContextData]],
                                           Any]],
              dx: Optional[ContextData]) -> Any:
        """ Format a text from a template including DT expressions

        :param template: The template.
        :param extractor: The extractor to get real value within ${dt}.
        :param dx: The context instance.
        :return: The text built from the template.
        """
        if isinstance(template, dict):
            return {
                self.build(k, extractor, dx): self.build(v, extractor, dx)
                for k, v in template.items()}
        elif isinstance(template, list):
            return [self.build(v, extractor, dx) for v in template]
        elif isinstance(template, str):
            return self.__extract(template, extractor, dx, 0, None)[0] if template else ''
        else:
            return template


def extract_dt(dtstr: str, dx: Optional[ContextData]) -> Any:
    """ Extract dt expression

    :param dtstr: The dt expressions (string within ${}).
    :param dx: The context instance.
    :return: The value extracted.
    """
    try:
        return dx.get(dtstr) if dx else dtstr
    except Exception as err:
        demisto.debug(f'failed to extract dt from "{dtstr=}". Error: {err}')
        return None


def normalize_value(value: Any, stringify: str) -> Any:
    if stringify == 'noop':
        return value
    elif stringify == 'all':
        if isinstance(value, dict):
            # key should be str for the context
            value = {
                k if isinstance(k, str) else json.dumps(k): normalize_value(v, stringify)
                for k, v in value.items()}
        elif isinstance(value, list):
            value = [normalize_value(v, stringify) for v in value]
        elif not isinstance(value, str):
            value = json.dumps(value)
    elif stringify == 'false':
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                pass
    elif stringify == 'true':
        if not isinstance(value, str):
            value = json.dumps(value)
    else:
        raise DemistoException(f'Invalid stringify value: {stringify}')

    return value


def main():
    try:
        args = assign_params(**demisto.args())
        key = args.get('key')
        template = args.get('template')
        template_type = args.get('template_type', 'raw')
        append = argToBoolean(args.get('append', False))
        stringify = args.get('stringify', 'noop')
        force = argToBoolean(args.get('force', False))
        keep_symbol_to_null = argToBoolean(args.get('keep_symbol_to_null', False))
        variable_markers = argToList(args.get('variable_markers', '${,}'))

        if not variable_markers or not variable_markers[0]:
            raise ValueError('variable_markers must have a start marker.')
        elif len(variable_markers) >= 3:
            raise ValueError('too many values for variable_markers.')
        elif len(variable_markers) == 1:
            variable_markers = variable_markers + ['']

        value = ''
        if template:
            if template_type == 'json':
                template = json.loads(template)
            elif template_type != 'raw':
                raise DemistoException(f'Invalid template type: {template_type}')

            context = args.get('context')
            if context:
                context = json.loads(context) if isinstance(context, str) else context
            else:
                context = demisto.context()

            formatter = Formatter(variable_markers[0], variable_markers[1], keep_symbol_to_null)
            value = formatter.build(template, extract_dt, ContextData(context))

        value = normalize_value(value, stringify)

        if value or force:
            readable_output = f'Key {key} set'
            outputs = {key: value}
        else:
            readable_output = 'value is None'
            outputs = {}

        if not append and outputs:
            demisto.executeCommand('DeleteContext', {'key': key, 'subplaybook': 'auto'})

        return_results(CommandResults(readable_output=readable_output, outputs=outputs))

    except Exception as err:
        return_error(str(err))


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
